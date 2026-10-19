"""`conn mcp install <client>`: add Conning to an agent client and deny the agent the ways around it.

Each client gets the MCP server entry plus permission rules that refuse raw `ssh`, `scp` and `sftp`,
the human-only `conn` commands, and reads of Conning's config dir (D44, D45); pi has no rules to write.
Each also gets the Conning skill (D57), from the copy shipped in this package, in its skills folder.
Files are merged, never replaced: what is already there stays, a backup of each changed file is kept
next to it, and a second run changes nothing. Rules in an agent's settings are a guardrail, not a
sandbox: they match the command the agent writes (`/usr/bin/ssh` or `sh -c 'ssh ...'` slip past), so
the real wall stays Conning's own toolset.
"""

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from conning import paths

DENIED_PROGRAMS = ("ssh", "scp", "sftp")
HUMAN_ONLY = ("approve", "allow", "targets rename", "targets mode", "ssh")  # grant or move trust, or skip policy


@dataclass
class Plan:
    """What an install would change. `notes` are told to the human; nothing else is printed."""

    writes: dict[Path, str] = field(default_factory=dict)
    commands: list[list[str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def server_command() -> list[str]:
    """The installed `conn` by absolute path, so a client with a bare PATH still finds it."""
    conn = shutil.which("conn")
    return [conn, "mcp"] if conn else ["uvx", "conning", "mcp"]


def _add_skill(plan: Plan, skills: Path) -> None:
    """Write the shipped skill to `<skills>/conning/SKILL.md`, and again whenever this version's copy differs."""
    path = skills / "conning" / "SKILL.md"
    text = resources.files("conning").joinpath("skill", "SKILL.md").read_text(encoding="utf-8")
    if not path.exists() or path.read_text(encoding="utf-8") != text:
        plan.writes[path] = text


def _home_relative(path: Path, prefix: str) -> str:
    """`~/x` for a path under the home folder, else `<prefix>/abs` (Claude Code's `//` anchor)."""
    try:
        return "~/" + path.resolve().relative_to(Path.home().resolve()).as_posix()
    except ValueError:
        return prefix + path.resolve().as_posix().lstrip("/")


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8") or "{}")
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    return data


def _dump_json(data: dict) -> str:
    return json.dumps(data, indent=2) + "\n"


def _merge_deny(data: dict, rules: list[str]) -> list[str]:
    """Add `rules` to data.permissions.deny; return the ones that were new."""
    permissions = data.setdefault("permissions", {})
    deny = permissions.setdefault("deny", [])
    new = [r for r in rules if r not in deny]
    deny.extend(new)
    return new


def _claude_dir() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")


def plan_claude(command: list[str]) -> Plan:
    plan = Plan()
    config = _home_relative(paths.config_dir(), "//")
    rules = [f"Bash({p} *)" for p in DENIED_PROGRAMS] + [f"Bash(conn {c} *)" for c in HUMAN_ONLY]
    rules += [f"Read({config}/**)", f"Edit({config}/**)"]
    settings = _claude_dir() / "settings.json"
    data = _load_json(settings)
    if _merge_deny(data, rules):
        plan.writes[settings] = _dump_json(data)
    _add_skill(plan, _claude_dir() / "skills")
    claude = shutil.which("claude")
    if claude is None:
        add = "claude mcp add --scope user conning -- " + " ".join(command)
        plan.notes.append(f"claude is not on PATH; add the server with: {add}")
    elif subprocess.run([claude, "mcp", "get", "conning"], capture_output=True).returncode != 0:
        plan.commands.append([claude, "mcp", "add", "--scope", "user", "conning", "--", *command])
    return plan


def _codex_dir() -> Path:
    return Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")


def _toml_string(text: str) -> str:
    return json.dumps(text)  # a JSON string is a valid TOML basic string


def plan_codex(command: list[str]) -> Plan:
    plan = Plan()
    config = _codex_dir() / "config.toml"
    text = config.read_text(encoding="utf-8") if config.exists() else ""
    if "[mcp_servers.conning]" not in text:
        block = (
            "\n[mcp_servers.conning]\n"
            f"command = {_toml_string(command[0])}\n"
            f"args = [{', '.join(_toml_string(a) for a in command[1:])}]\n"
        )
        plan.writes[config] = text.rstrip("\n") + ("\n" if text else "") + block
    rules = _codex_dir() / "rules" / "conning.rules"
    lines = ["# Written by `conn mcp install codex`: remote machines go through Conning's tools.\n"]
    for pattern in [[p] for p in DENIED_PROGRAMS] + [["conn", *c.split()] for c in HUMAN_ONLY]:
        lines.append(
            f'prefix_rule(pattern = {json.dumps(pattern)}, decision = "forbidden", '
            f'justification = "use Conning\'s tools for remote machines")\n'
        )
    body = "".join(lines)
    if not rules.exists() or rules.read_text(encoding="utf-8") != body:
        plan.writes[rules] = body
    _add_skill(plan, _codex_dir() / "skills")
    plan.notes.append(f"codex rules cover commands only; it can still read {paths.config_dir()}")
    return plan


def _add_server(plan: Plan, path: Path, entry: dict) -> None:
    """Add `conning` to the `mcpServers` object most clients share (Cursor, pi)."""
    data = _load_json(path)
    if "conning" not in data.setdefault("mcpServers", {}):
        data["mcpServers"]["conning"] = entry
        plan.writes[path] = _dump_json(data)


def plan_cursor(command: list[str]) -> Plan:
    plan = Plan()
    _add_server(
        plan, Path.home() / ".cursor" / "mcp.json", {"type": "stdio", "command": command[0], "args": command[1:]}
    )
    cli = Path.home() / ".cursor" / "cli-config.json"
    data = _load_json(cli)
    if not data:
        data = {"version": 1, "editor": {"vimMode": False}, "permissions": {"allow": [], "deny": []}}
    config = paths.config_dir().resolve().as_posix()
    rules = [f"Shell({p})" for p in DENIED_PROGRAMS] + [f"Read({config}/**)", f"Write({config}/**)"]
    if _merge_deny(data, rules):
        plan.writes[cli] = _dump_json(data)
    _add_skill(plan, Path.home() / ".cursor" / "skills")
    plan.notes.append("the deny rules apply to the Cursor CLI agent; the editor asks before running commands")
    return plan


def plan_opencode(command: list[str]) -> Plan:
    """opencode: the server under `mcp`, and deny rules under `permission`, where the last match wins."""
    plan = Plan()
    path = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "opencode" / "opencode.json"
    _add_skill(plan, path.parent / "skills")
    data = _load_json(path)
    before = _dump_json(data)
    data.setdefault("mcp", {}).setdefault("conning", {"type": "local", "command": command, "enabled": True})
    permission = data.get("permission") or {}
    data["permission"] = permission = permission if isinstance(permission, dict) else {"*": permission}
    config = _home_relative(paths.config_dir(), "/")
    rules = {
        "bash": [f"{p} *" for p in DENIED_PROGRAMS] + [f"conn {c} *" for c in HUMAN_ONLY],
        "read": [f"{config}/**"],
        "edit": [f"{config}/**"],
    }
    for tool, patterns in rules.items():
        current = permission.get(tool) or {}
        permission[tool] = current = current if isinstance(current, dict) else {"*": current}
        for pattern in patterns:
            current.pop(pattern, None)  # re-added at the end, so it is the last match
            current[pattern] = "deny"
    if _dump_json(data) != before:
        plan.writes[path] = _dump_json(data)
    return plan


def plan_pi(command: list[str]) -> Plan:
    plan = Plan()
    _add_server(plan, Path.home() / ".pi" / "agent" / "mcp.json", {"command": command[0], "args": command[1:]})
    _add_skill(plan, Path.home() / ".pi" / "agent" / "skills")
    plan.notes.append("pi has no permission rules; it can still run ssh itself (a pi extension can block it)")
    return plan


PLANNERS = {"claude": plan_claude, "codex": plan_codex, "cursor": plan_cursor, "opencode": plan_opencode, "pi": plan_pi}


def install(io, client: str, *, dry_run: bool = False) -> int:
    try:
        plan = PLANNERS[client](server_command())
    except (OSError, ValueError) as e:
        io.say(f"error: can't read the {client} config: {e}; nothing changed")
        return 1
    for path, text in plan.writes.items():
        verb = "would write" if dry_run else "wrote"
        if not dry_run:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                shutil.copyfile(path, path.with_name(path.name + ".conning.bak"))
            tmp = path.with_name(path.name + ".conning.tmp")
            tmp.write_text(text, encoding="utf-8")
            os.replace(tmp, path)
        io.say(f"{verb} {path}")
    for argv in plan.commands:
        if dry_run:
            io.say("would run " + " ".join(argv))
            continue
        done = subprocess.run(argv, capture_output=True, text=True)
        if done.returncode != 0:
            io.say(f"error: {' '.join(argv)} failed: {(done.stdout + done.stderr).strip()[-500:]}")
            return 1
        io.say("ran " + " ".join(argv))
    if not plan.writes and not plan.commands:
        io.say(f"{client}: already installed, nothing to change")
    for note in plan.notes:
        io.say(f"note: {note}")
    return 0
