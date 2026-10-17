"""The human side: adding, approving, testing and removing targets, approving commands.

Anything that grants trust (going live, pinning a host key, approving a command) needs an
interactive terminal. An agent calling `conn targets add` from its shell has no TTY, so its target is saved
as pending and does nothing until a human runs `conn approve <name>`.
"""

import contextlib
import fnmatch
import getpass
import re
import sys
from dataclasses import replace
from pathlib import Path
from typing import Protocol

from conning import audit, paths, secrets, ssh
from conning.core import PENDING, Core
from conning.policy import SAFE, WRAPPERS, policy_argv, program, remembered_rule
from conning.secrets import SecretError, store_in_keychain
from conning.state import Approval, Job, rename_target, set_problem
from conning.targets import (
    AUTHS,
    MODES,
    NAME_RE,
    Target,
    TargetFileError,
    jump_chain,
    load_targets,
    save_targets,
    select,
)

APPROVE_WAIT = 10  # seconds `conn approve a:<id>` waits for the command before handing back its job id


class IO(Protocol):
    tty: bool

    def ask(self, prompt: str) -> str: ...

    def secret(self, prompt: str) -> str: ...

    def say(self, text: str) -> None: ...


class ConsoleIO:
    def __init__(self):
        self.tty = sys.stdin.isatty() and sys.stdout.isatty()

    def ask(self, prompt: str) -> str:  # pragma: no cover - interactive
        return input(prompt)

    def secret(self, prompt: str) -> str:  # pragma: no cover - interactive
        return getpass.getpass(prompt)

    def say(self, text: str) -> None:
        print(text)


def _save(t: Target) -> None:
    path = paths.targets_file()
    targets = load_targets(path)
    targets[t.name] = t
    save_targets(path, targets)


def _confirm(io: IO, question: str) -> bool:
    return io.ask(f"{question} [y/N] ").strip().lower() in ("y", "yes")


def _need_tty(io: IO, what: str) -> int | None:
    if io.tty:
        return None
    io.say(f"error: {what} needs a human at an interactive terminal")
    return 1


def add(
    core: Core,
    io: IO,
    name: str,
    *,
    host: str | None = None,
    user: str | None = None,
    port: int | None = None,
    auth: str | None = None,
    secret: str | None = None,
    key: str | None = None,
    os_name: str | None = None,
    mode: str = "ask",
    tags: list[str] | None = None,
    like: str | None = None,
    jump: str | None = None,
) -> int:
    try:
        targets = load_targets(paths.targets_file())
    except TargetFileError as e:
        io.say(f"error: {e}")
        return 1
    if like is not None:  # the same machine as another target, usually as another user
        base = targets.get(like)
        if base is None:
            io.say(f"error: no target {like} to copy")
            return 1
        host, port, os_name = host or base.host, port or base.port, os_name or base.os
        jump = jump or base.jump  # the same machine is reached the same way
        user = user or base.user
        tags = tags or list(base.tags)
        auth = auth or base.auth
        if user == base.user:  # same login: same credentials
            secret, key = secret or base.secret, key or base.key
    if not NAME_RE.match(name):
        io.say("error: target names use letters, digits, '.', '_' and '-'")
        return 1
    if mode not in MODES:
        io.say(f"error: mode must be one of {', '.join(MODES)}")
        return 1
    if jump is not None and (jump == name or jump not in targets):
        io.say(f"error: jump host {jump} is not a target; add it first")
        return 1
    if name in targets:
        io.say(f"error: {name} already exists (probe it again with conn approve {name}, or conn targets rm {name})")
        return 1
    if not io.tty and not (host and user):
        io.say("error: --host and --user are required when adding without a terminal")
        return 1
    host = host or io.ask("host: ").strip()
    user = user or io.ask("user: ").strip()
    auth = auth or ("password" if secret else "key" if key else None)
    if auth is None:
        auth = (io.ask("auth [ssh-agent/key/password] (ssh-agent): ").strip() or "ssh-agent") if io.tty else "ssh-agent"
    if auth not in AUTHS:
        io.say(f"error: auth must be one of {', '.join(AUTHS)}")
        return 1
    if auth == "password" and not secret and not io.tty:
        io.say("error: a password is typed by a human at a terminal, or give --secret <reference>")
        return 1
    if auth == "key" and not key:
        key = io.ask("private key file: ").strip() if io.tty else None
        if not key:
            io.say("error: auth=key needs --key")
            return 1
    t = Target(
        name=name,
        host=host,
        user=user,
        port=port or 22,
        auth=auth,
        secret=secret,
        key=key,
        os=os_name or "linux",
        shell="pwsh" if os_name == "windows" else "bash",
        mode=mode,
        tags=tuple(tags or ()),
        status="pending",
        jump=jump,
    )
    if not io.tty:
        _save(t)
        audit.record("target", target=name, change="proposed")
        io.say(f"{name} saved as pending. It does nothing until a human runs: conn approve {name}")
        return 0
    if auth == "password" and not secret:
        t = replace(t, secret=store_in_keychain(name, io.secret(f"password for {user}@{host}: ")))
    _save(t)
    return _enroll(core, io, t)


def _stays_pending(io: IO, t: Target, message: str, reason: str) -> int:
    """Tell the human, and record a host-free reason that `targets` shows next to the pending target."""
    io.say(message)
    set_problem(t.name, re.sub(rf"(?<![\w.-]){re.escape(t.host)}(?![\w.-])", "<host>", reason))
    return 1


def _enroll(core: Core, io: IO, t: Target) -> int:
    """Pin the host key the human confirms, probe OS and shell, and make the target live."""
    try:
        keys = ssh.scan_host_keys_via(t, ssh.hops(t)) if t.jump else ssh.scan_host_keys(t.host, t.port)
    except (ssh.SSHError, SecretError) as e:
        return _stays_pending(io, t, f"error: {e}", str(e))
    if not keys:
        if not ssh.port_open(t.host, t.port):
            return _stays_pending(io, t, ssh.no_ssh_hint(t), "no SSH server answered")
        return _stays_pending(io, t, f"{t.name}: no host keys offered", "no host keys offered")
    via = f"  via {t.jump}" if t.jump else ""
    secret = f"  secret={t.secret}" if t.secret else ""
    io.say(f"{t.name}: {t.user}@{t.host}:{t.port}{via}  auth={t.auth}{secret}  mode={t.mode}")
    for key_type, fp, _ in keys:
        io.say(f"  host key {key_type:<20} {fp}")
    auto = " in mode=auto, where the agent runs anything without asking" if t.mode == "auto" else ""
    if not _confirm(io, f"pin these host keys and make the target live{auto}?"):
        return _stays_pending(io, t, "not pinned; the target stays pending", "host key not confirmed")
    ssh.pin_host_keys(t.name, keys)
    t = replace(t, hostkey=keys[0][1], status="active")
    os_name, shell, problem = probe(core, t)
    if problem:
        _save(replace(t, status="pending"))
        return _stays_pending(io, t, f"error: {problem}", f"login check failed: {problem}")
    t = replace(t, os=os_name, shell=shell)
    _save(t)
    set_problem(t.name, None)
    audit.record("target", target=t.name, change="live")
    io.say(f"{t.name} is live: {os_name} {shell} mode={t.mode}")
    return 0


def probe(core: Core, t: Target) -> tuple[str, str, str | None]:
    """Return (os, shell, problem). POSIX if `uname` works, else PowerShell on Windows."""
    try:
        rc, out = core.transport.exec(t, "uname -s", timeout=30)
    except (ssh.SSHError, SecretError) as e:
        return t.os, t.shell, str(e)
    if rc == 255:
        return t.os, t.shell, core.transport.explain(t, rc, out)
    if rc == 0 and out.strip():
        return out.decode(errors="replace").strip().splitlines()[0].lower(), "bash", None
    for shell in ("pwsh", "powershell"):
        rc, out = core.transport.exec(t, f"{shell} -NoProfile -Command $PSVersionTable.PSVersion.Major", timeout=30)
        if rc == 0:
            return "windows", shell, None
    return t.os, t.shell, "could not detect the remote shell (neither uname nor PowerShell answered)"


def approve(core: Core, io: IO, what: str, *, always: bool = False) -> int:
    if (code := _need_tty(io, "approving")) is not None:
        return code
    if what.startswith("a:"):
        code = approve_command(io, what[2:], always=always)
        approved = Approval.load(what[2:])
        if code == 0 and approved is not None and approved.status == "approved":
            io.say(core.read(what, wait=APPROVE_WAIT))  # start it and show the result here too
            for job_id in (Approval.load(what[2:]) or approved).jobs.values():
                job = Job.load(job_id)
                if job is not None:  # what the human saw still counts as unread for the agent
                    job.seen = 0
                    job.save()
        return code
    return approve_target(core, io, what)


def approve_target(core: Core, io: IO, name: str) -> int:
    if (code := _need_tty(io, "approving a target")) is not None:
        return code
    targets = load_targets(paths.targets_file())
    t = targets.get(name)
    if t is None:
        io.say(f"error: no target {name}")
        return 1
    return _enroll(core, io, t)


def run_here(core: Core, io: IO, result: str, *, wait: int, max_bytes: int, grep: str | None) -> int:
    """`conn run` at a terminal: a command that needs approval is asked about right here, and its
    result printed, instead of handing back an id to copy into `conn approve`."""
    match = PENDING.search(result)
    if match is None or not io.tty:
        io.say(result)
        return 1 if result.startswith("error:") else 0
    others = PENDING.sub("", result).strip()
    if others:
        io.say(others)
    approval_id = match.group(1)
    approve_command(io, approval_id, inline=True)
    a = Approval.load(approval_id)
    if a is None or a.status != "approved":
        return 1
    out = core.read(f"a:{approval_id}", wait=wait, grep=grep, max_bytes=max_bytes)
    first, _, rest = out.partition("\n")
    io.say(rest if first.startswith(f"approved a:{approval_id}") and rest else out)
    return 1 if out.startswith("error:") else 0


def approve_command(io: IO, approval_id: str, *, always: bool = False, inline: bool = False) -> int:
    a = Approval.load(approval_id)
    if a is None:
        io.say(f"error: no approval a:{approval_id}")
        return 1
    if a.status != "pending":
        io.say(f"a:{a.id} is already {a.status}")
        return 0
    where = ", ".join(a.targets) + (f" (cwd {a.cwd})" if a.cwd else "")
    io.say(f"needs approval on {where}: {a.display}" if inline else f"a:{a.id} on {where}\n  {a.display}")
    rule = remembered_rule(policy_argv(a.command, a.argv))
    choices = "[a]llow once, [e] always allow '" + " ".join(rule) + "', [d]eny" if rule else "[a]llow once, [d]eny"
    answer = "e" if always and rule else io.ask(f"{choices}: ").strip().lower()[:1]
    choice = {"a": "once", "e": "always"}.get(answer) if answer in (("a", "e") if rule else ("a",)) else None
    said = decide(a, choice or "deny", by="terminal")
    if inline:  # the result follows right here, so the note about the agent's `read` is noise
        said = "\n".join(line for line in said.splitlines() if not line.startswith("approved a:"))
    if said:
        io.say(said)
    return 0


def decide(a: Approval, answer: str, *, by: str) -> str:
    """Record the human's answer to a pending command: once, always or deny. Returns one line.

    Shared by `conn approve`, `conn watch` and the prompt in the agent client, so all three
    remember the same rule and leave the same audit entry.
    """
    if a.status != "pending":
        return f"a:{a.id} is already {a.status}"
    if answer == "deny":
        a.status = "denied"
        a.save()
        audit.record("denied", id=a.id, by=by)
        return f"denied a:{a.id}"
    rule = remembered_rule(policy_argv(a.command, a.argv))
    lines = []
    if answer == "always" and rule:
        _add_rule(a.targets, rule)
        lines.append(f"always allowing '{' '.join(rule)}' on {', '.join(a.targets)}")
    a.status = "approved"
    a.save()
    audit.record("approved", id=a.id, by=by, always=bool(answer == "always" and rule) or None)
    lines.append(f"approved a:{a.id}; the agent sees the result with read a:{a.id}")
    return "\n".join(lines)


def _add_rule(names: list[str], rule: tuple[str, ...]) -> list[str]:
    """Add an allow rule to these targets; returns the names that did not have it yet."""
    path = paths.targets_file()
    targets = load_targets(path)
    changed = []
    for name in names:
        if name in targets and rule not in targets[name].allow:
            targets[name] = replace(targets[name], allow=(*targets[name].allow, rule))
            changed.append(name)
            audit.record("rule", target=name, change="allow", rule=" ".join(rule))
    save_targets(path, targets)
    return changed


def rule_words(words: list[str]) -> tuple[str, ...] | str:
    """Validate a rule typed by a human: a program and up to a few plain words. Returns the rule or an error."""
    if not words:
        return "error: give the command words to allow, e.g. conn allow lab systemctl status"
    if any(w.startswith("-") for w in words):
        return "error: rules match words, not flags (flags are ignored when matching)"
    if program(words[0]) in WRAPPERS:
        return f"error: '{words[0]}' can run anything, so it always asks"
    return (program(words[0]), *words[1:])


def allow(io: IO, selector: str, words: list[str]) -> int:
    """Human only: list a target's rules, or add one so the command runs without asking."""
    targets = load_targets(paths.targets_file())
    chosen = select(targets, selector)
    if not chosen:
        io.say(f"error: no target matches {selector!r}")
        return 1
    if not words:
        for t in chosen:
            rules = ", ".join("'" + " ".join(r) + "'" for r in t.allow) or "(none)"
            safe = "the built-in read-only list" if t.safe else "no built-in list (safe = false)"
            io.say(f"{t.name}: {safe}; rules: {rules}")
        return 0
    if (code := _need_tty(io, "changing the allowlist")) is not None:
        return code
    rule = rule_words(words)
    if isinstance(rule, str):
        io.say(rule)
        return 1
    names = [t.name for t in chosen]
    shown = " ".join(rule)
    if not _confirm(io, f"let the agent run '{shown} ...' on {', '.join(names)} without asking?"):
        io.say("no change")
        return 1
    changed = _add_rule(names, rule)
    io.say(f"allowing '{shown}' on {', '.join(changed)}" if changed else f"'{shown}' was already allowed")
    return 0


def deny(io: IO, selector: str, words: list[str]) -> int:
    """Remove an allow rule. Taking trust away needs no terminal."""
    rule = rule_words(words)
    if isinstance(rule, str):
        io.say(rule)
        return 1
    path = paths.targets_file()
    targets = load_targets(path)
    chosen = select(targets, selector)
    if not chosen:
        io.say(f"error: no target matches {selector!r}")
        return 1
    changed = []
    for t in chosen:
        if rule in t.allow:
            targets[t.name] = replace(t, allow=tuple(r for r in t.allow if r != rule))
            changed.append(t.name)
            audit.record("rule", target=t.name, change="deny", rule=" ".join(rule))
    save_targets(path, targets)
    shown = " ".join(rule)
    if changed:
        io.say(f"'{shown}' now asks again on {', '.join(changed)}")
    elif rule[0] in SAFE:
        io.say(f"'{rule[0]}' is on the built-in read-only list; to make it ask, set safe = false for the target")
    else:
        io.say(f"no target had the rule '{shown}'")
    return 0


def set_mode(io: IO, selector: str, mode: str | None) -> int:
    """Show targets' modes, or set one. Turning auto on needs a human; going back to ask needs no terminal."""
    path = paths.targets_file()
    targets = load_targets(path)
    chosen = select(targets, selector)
    if not chosen:
        io.say(f"error: no target matches {selector!r}")
        return 1
    if mode is None:
        for t in chosen:
            io.say(f"{t.name}: mode={t.mode}")
        return 0
    names = [t.name for t in chosen if t.mode != mode]
    if not names:
        io.say(f"already mode={mode}")
        return 0
    if mode == "auto":
        if (code := _need_tty(io, "turning on mode=auto")) is not None:
            return code
        if not _confirm(io, f"let the agent run anything on {', '.join(names)} without asking?"):
            io.say("no change")
            return 1
    for name in names:
        targets[name] = replace(targets[name], mode=mode)
        audit.record("target", target=name, change="mode", mode=mode)
    save_targets(path, targets)
    io.say(f"mode={mode} on {', '.join(names)}")
    return 0


def remove(io: IO, name: str) -> int:
    path = paths.targets_file()
    targets = load_targets(path)
    if name not in targets:
        io.say(f"error: no target {name}")
        return 1
    through = [t.name for t in targets.values() if t.jump == name]
    if through:
        io.say(f"error: {', '.join(through)} jump through {name}; remove them or change their jump first")
        return 1
    del targets[name]
    save_targets(path, targets)
    ssh.pin_host_keys(name, [])
    audit.record("target", target=name, change="removed")
    io.say(f"removed {name}")
    return 0


def rename(io: IO, old: str, new: str) -> int:
    """Human only: give a target a new name, and carry everything kept under the old one along: its
    pinned host keys, the password Conning stored for it, pending approvals and running jobs."""
    if (code := _need_tty(io, "renaming a target")) is not None:
        return code
    path = paths.targets_file()
    targets = load_targets(path)
    if old not in targets:
        io.say(f"error: no target {old}")
        return 1
    if not NAME_RE.match(new):
        io.say("error: target names use letters, digits, '.', '_' and '-'")
        return 1
    if new in targets:
        io.say(f"error: {new} already exists")
        return 1
    t = replace(targets[old], name=new)
    stored = t.secret == f"keychain:{secrets.KEYCHAIN_SERVICE}/{old}"  # the password `conn targets add` saved
    if stored:  # moved, so a later `conn targets add <old>` can't overwrite the password this target uses
        try:
            t = replace(t, secret=secrets.move_in_keychain(t.secret, new))
        except Exception as e:  # noqa: BLE001 - every keyring backend fails differently
            io.say(f"error: can't move {old}'s password in the OS keychain ({e}); nothing changed")
            return 1
    renamed = {name: replace(o, jump=new) if o.jump == old else o for name, o in targets.items()}
    save_targets(path, {(new if name == old else name): (t if name == old else o) for name, o in renamed.items()})
    if stored:
        with contextlib.suppress(Exception):  # a leftover copy is harmless: nothing points at it
            secrets.forget(targets[old].secret)
    ssh.rename_host_keys(old, new)
    rename_target(old, new)
    (paths.state_dir() / "ssh" / f"{old}.conf").unlink(missing_ok=True)
    audit.record("target", target=new, change="renamed", was=old)
    io.say(f"renamed {old} to {new}")
    return 0


def test(core: Core, io: IO, name: str) -> int:
    t = load_targets(paths.targets_file()).get(name)
    if t is None:
        io.say(f"error: no target {name}")
        return 1
    if t.status == "pending":
        io.say(f"{name} is pending; a human runs: conn approve {name}")
        return 1
    os_name, shell, problem = probe(core, t)
    if problem:
        io.say(f"{name}: {problem}")
        return 1
    io.say(f"{name}: ok, {os_name} {shell}, host key pinned")
    return 0


UNSAFE_SSH_OPTIONS = ("forwardagent", "localforward", "remoteforward", "dynamicforward", "proxycommand", "forwardx11")


def import_ssh_config(io: IO, match: str = "*", config: Path | None = None) -> int:
    """Turn Host blocks of an ssh config into pending targets. Unsafe options are never copied; a
    ProxyJump to another host that is (or becomes) a target is kept as its jump."""
    config = config or Path.home() / ".ssh" / "config"
    if not config.exists():
        io.say(f"error: {config} not found")
        return 1
    hosts: list[tuple[str, dict[str, str]]] = []
    current: list[tuple[str, dict[str, str]]] = []
    for raw in config.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.replace("=", " ", 1).partition(" ")
        key, value = key.lower(), value.strip().strip('"')
        if key == "host":
            current = [(alias, {}) for alias in value.split() if not any(c in alias for c in "*?!")]
            hosts += current
        elif key == "match":
            current = []
        else:
            for _, opts in current:
                opts.setdefault(key, value)
    path = paths.targets_file()
    targets = load_targets(path)
    chosen = [(a, o) for a, o in hosts if fnmatch.fnmatch(a, match) and a not in targets and NAME_RE.match(a)]
    names = set(targets) | {alias for alias, _ in chosen}
    added = []
    for alias, opts in chosen:
        for option in UNSAFE_SSH_OPTIONS:
            if option in opts and opts[option].lower() not in ("no", "none"):
                io.say(f"  ! {alias}: {option} in your ssh config; Conning drops it")
        jump = opts.get("proxyjump")
        if jump and jump.lower() != "none" and (jump not in names or jump == alias):  # user@host, a list...
            io.say(f'  ! {alias}: ProxyJump {jump} is not a target here; add it, then set jump = "<name>"')
        jump = jump if jump in names and jump != alias else None
        key = opts.get("identityfile")
        targets[alias] = Target(
            name=alias,
            host=opts.get("hostname", alias),
            user=opts.get("user", getpass.getuser()),
            port=int(opts.get("port", 22)),
            auth="key" if key else "ssh-agent",
            key=key,
            jump=jump,
            status="pending",
        )
        added.append(alias)
    for alias in added:  # two imported hosts jumping through each other would break the target file
        try:
            jump_chain(targets, targets[alias])
        except TargetFileError as e:
            io.say(f"  ! {e}; {alias} is imported without it")
            targets[alias] = replace(targets[alias], jump=None)
    save_targets(path, targets)
    io.say(f"imported {len(added)} target(s) as pending: {', '.join(added) or '-'}")
    if added:
        io.say("approve each with: conn approve <name>")
    return 0
