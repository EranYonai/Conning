"""The target file: one TOML table per remote machine, never any secret values.

Loading is fail-closed: an unknown key, a bad mode or a malformed allow rule is an error,
not a warning, so a typo can never silently widen what the agent may do.
"""

import json
import os
import re
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

MODES = ("observe", "ask", "lease")
AUTHS = ("ssh-agent", "key", "password")
STATUSES = ("active", "pending")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


class TargetFileError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    name: str
    host: str
    user: str
    port: int = 22
    auth: str = "ssh-agent"
    secret: str | None = None  # a reference such as "op://Lab/vm/password" or "keychain:lab/vm"
    key: str | None = None  # path to a private key file, for auth = "key"
    hostkey: str | None = None  # pinned fingerprint, "SHA256:..."
    os: str = "linux"
    shell: str = "bash"
    mode: str = "ask"
    tags: tuple[str, ...] = ()
    allow: tuple[tuple[str, ...], ...] = ()
    inject: dict[str, str] = field(default_factory=dict)
    status: str = "active"
    safe: bool = True  # the built-in read-only commands run without asking (D39)


KEYS = {f.name for f in fields(Target)} - {"name"}


def load_targets(path: Path) -> dict[str, Target]:
    if not path.exists():
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise TargetFileError(f"{path}: {e}") from e
    return {name: _parse(name, table, path) for name, table in data.items()}


def _parse(name: str, table: object, path: Path) -> Target:
    where = f"{path} [{name}]"
    if not NAME_RE.match(name):
        raise TargetFileError(f"{where}: bad target name (letters, digits, '.', '_', '-')")
    if not isinstance(table, dict):
        raise TargetFileError(f"{where}: expected a table")
    unknown = sorted(set(table) - KEYS)
    if unknown:
        raise TargetFileError(f"{where}: unknown key(s) {', '.join(unknown)}")
    for required in ("host", "user"):
        if not isinstance(table.get(required), str) or not table[required]:
            raise TargetFileError(f"{where}: '{required}' is required")
    _check_choice(where, table, "mode", MODES)
    _check_choice(where, table, "auth", AUTHS)
    _check_choice(where, table, "status", STATUSES)
    if table.get("auth") == "password" and not table.get("secret"):
        raise TargetFileError(f"{where}: auth = 'password' needs a secret reference")
    allow = table.get("allow", [])
    if not isinstance(allow, list) or not all(
        isinstance(rule, list) and rule and all(isinstance(w, str) and w for w in rule) for rule in allow
    ):
        raise TargetFileError(f"{where}: 'allow' must be a list of non-empty word lists, e.g. [[\"pytest\"]]")
    if not isinstance(table.get("safe", True), bool):
        raise TargetFileError(f"{where}: 'safe' must be true or false")
    inject = table.get("inject", {})
    if not isinstance(inject, dict) or not all(isinstance(v, str) for v in inject.values()):
        raise TargetFileError(f"{where}: 'inject' must map env names to secret references")
    return Target(
        name=name,
        host=table["host"],
        user=table["user"],
        port=int(table.get("port", 22)),
        auth=table.get("auth", "ssh-agent"),
        secret=table.get("secret"),
        key=table.get("key"),
        hostkey=table.get("hostkey"),
        os=table.get("os", "linux"),
        shell=table.get("shell", "pwsh" if table.get("os") == "windows" else "bash"),
        mode=table.get("mode", "ask"),
        tags=tuple(table.get("tags", ())),
        allow=tuple(tuple(rule) for rule in allow),
        inject=dict(inject),
        status=table.get("status", "active"),
        safe=table.get("safe", True),
    )


def _check_choice(where: str, table: dict, key: str, choices: tuple[str, ...]) -> None:
    if key in table and table[key] not in choices:
        raise TargetFileError(f"{where}: {key} must be one of {', '.join(choices)}")


def select(targets: dict[str, Target], selector: str | None) -> list[Target]:
    """`None` → all; `tag:x` → targets tagged x; otherwise a comma-separated list of names."""
    if not selector:
        return list(targets.values())
    if selector.startswith("tag:"):
        tag = selector[4:]
        return [t for t in targets.values() if tag in t.tags]
    return [targets[n] for n in (s.strip() for s in selector.split(",")) if n in targets]


def listing(targets: list[Target], reach: dict[str, str] | None = None, notes: dict[str, str] | None = None) -> str:
    """One line per target, with the user it logs in as. Never prints a host or a secret reference."""
    width = max(len(t.name) for t in targets)
    lines = []
    for t in targets:
        mode = t.mode
        if t.status == "pending":
            mode = f"pending ({notes[t.name]})" if notes and t.name in notes else "pending"
        tags = f"tags={','.join(t.tags)}" if t.tags else "tags=-"
        line = f"{t.name:<{width}}  {t.os:<7}  {t.shell:<4}  user={t.user}  {tags}  mode={mode}"
        lines.append(f"{line}  reach={reach[t.name]}" if reach and t.name in reach else line)
    return "\n".join(lines)


def _toml_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{k} = {_toml_value(v)}" for k, v in value.items()) + " }"
    raise TypeError(f"cannot write {type(value).__name__} to TOML")


def dump_targets(targets: dict[str, Target]) -> str:
    """Serialize targets back to TOML, leaving out fields that hold their default."""
    defaults = Target(name="", host="", user="")
    out = ["# Conning targets. Safe to read: this file holds no secrets, only references to them.\n"]
    for t in targets.values():
        out.append(f"[{t.name}]")
        for key in "host port user auth secret key hostkey os shell mode status safe".split():
            value = getattr(t, key)
            if value is not None and (key in ("host", "user") or value != getattr(defaults, key)):
                out.append(f"{key} = {_toml_value(value)}")
        for key in ("tags", "allow", "inject"):
            value = getattr(t, key)
            if value:
                out.append(f"{key} = {_toml_value(value)}")
        out.append("")
    return "\n".join(out)


def save_targets(path: Path, targets: dict[str, Target]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(dump_targets(targets), encoding="utf-8")
    os.replace(tmp, path)
