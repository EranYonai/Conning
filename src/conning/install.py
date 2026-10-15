"""`conn mcp install <client>`: add Conning to an agent client and deny the agent the ways around it.

Each client gets the MCP server entry plus permission rules that refuse raw `ssh`, `scp` and `sftp`,
the human-only `conn` commands, and reads of Conning's config dir (D44). Files are merged, never
replaced: what is already there stays, a backup of each changed file is kept next to it, and a second
run changes nothing. Rules in an agent's settings are a guardrail, not a sandbox: they match the
command the agent writes (`/usr/bin/ssh` or `sh -c 'ssh ...'` slip past), so the real wall stays
Conning's own toolset.
"""

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from conning import paths

CLIENTS = ("claude", "codex", "cursor")
DENIED_PROGRAMS = ("ssh", "scp", "sftp")
HUMAN_ONLY = ("approve", "lease", "allow")  # conn commands that grant trust


@dataclass
class Plan:
    """What an install would change. `notes` are told to the human; nothing else is printed."""

    client: str
    writes: dict[Path, str] = field(default_factory=dict)
    commands: list[list[str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def server_command() -> list[str]:
    """The installed `conn` by absolute path, so a client with a bare PATH still finds it."""
    conn = shutil.which("conn")
    return [conn, "mcp"] if conn else ["uvx", "conning", "mcp"]


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
    plan = Plan("claude")
    config = _home_relative(paths.config_dir(), "//")
    rules = [f"Bash({p} *)" for p in DENIED_PROGRAMS] + [f"Bash(conn {c} *)" for c in HUMAN_ONLY]
    rules += [f"Read({config}/**)", f"Edit({config}/**)"]
    settings = _claude_dir() / "settings.json"
    data = _load_json(settings)
    if _merge_deny(data, rules):
        plan.writes[settings] = _dump_json(data)
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
    plan = Plan("codex")
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
    for pattern in [[p] for p in DENIED_PROGRAMS] + [["conn", c] for c in HUMAN_ONLY]:
        lines.append(
            f'prefix_rule(pattern = {json.dumps(pattern)}, decision = "forbidden", '
            f'justification = "use Conning\'s tools for remote machines")\n'
        )
    body = "".join(lines)
    if not rules.exists() or rules.read_text(encoding="utf-8") != body:
        plan.writes[rules] = body
    plan.notes.append(f"codex rules cover commands only; it can still read {paths.config_dir()}")
    return plan


def plan_cursor(command: list[str]) -> Plan:
    plan = Plan("cursor")
    mcp = Path.home() / ".cursor" / "mcp.json"
    data = _load_json(mcp)
    servers = data.setdefault("mcpServers", {})
    if "conning" not in servers:
        servers["conning"] = {"type": "stdio", "command": command[0], "args": command[1:]}
        plan.writes[mcp] = _dump_json(data)
    cli = Path.home() / ".cursor" / "cli-config.json"
    data = _load_json(cli)
    if not data:
        data = {"version": 1, "editor": {"vimMode": False}, "permissions": {"allow": [], "deny": []}}
    config = paths.config_dir().resolve().as_posix()
    rules = [f"Shell({p})" for p in DENIED_PROGRAMS] + [f"Read({config}/**)", f"Write({config}/**)"]
    if _merge_deny(data, rules):
        plan.writes[cli] = _dump_json(data)
    plan.notes.append("the deny rules apply to the Cursor CLI agent; the editor asks before running commands")
    return plan


PLANNERS = {"claude": plan_claude, "codex": plan_codex, "cursor": plan_cursor}


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
