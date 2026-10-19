"""The audit log: one JSON line per thing that happened, in the state dir.

Every process appends to the same file, so `conn watch` in one terminal sees what the agent does
through the MCP server in another. Entries carry commands and decisions, never secret values:
the agent never sees a secret, so the commands it sends cannot contain one.

Each entry holds the sha256 of the line before it (`prev`), so an edited or deleted line breaks the
chain and `conn doctor` says where. It runs as your user, so this is tamper-evident, not tamper-proof.
"""

import hashlib
import json
import time
from contextlib import contextmanager
from pathlib import Path

from conning import paths

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None

GENESIS = "0" * 64


def log_file() -> Path:
    return paths.state_dir() / "audit.jsonl"


def record(event: str, **fields) -> None:
    """Append one entry. Best effort: a full disk must not stop a command that already ran."""
    entry = {"ts": round(time.time(), 3), "event": event, **{k: v for k, v in fields.items() if v is not None}}
    path = log_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("ab+") as f, _locked(f):
            entry["prev"] = _digest(_last_line(f))
            f.write((json.dumps(entry, separators=(",", ":")) + "\n").encode())
    except OSError:
        pass


@contextmanager
def _locked(f):
    """Serialize writers, so two processes never chain to the same previous line."""
    if fcntl is not None:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    try:
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def _last_line(f) -> bytes:
    f.seek(0, 2)
    size = f.tell()
    f.seek(max(0, size - 65536))
    lines = f.read().splitlines()
    return lines[-1] if lines else b""


def _digest(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest() if line else GENESIS


def verify() -> int | None:
    """The 1-based number of the first line whose `prev` does not match the line before it, or None."""
    path = log_file()
    if not path.exists():
        return None
    previous = b""
    for number, line in enumerate(path.read_bytes().splitlines(), 1):
        try:
            prev = json.loads(line).get("prev")
        except ValueError:
            return number
        if prev != _digest(previous):
            return number
        previous = line
    return None


def read_from(offset: int) -> tuple[list[dict], int]:
    """Entries appended after byte `offset`, and the offset to continue from. Partial lines wait."""
    path = log_file()
    if not path.exists():
        return [], 0
    with path.open("rb") as f:
        f.seek(offset)
        data = f.read()
    complete = data[: data.rfind(b"\n") + 1]
    entries = []
    for line in complete.splitlines():
        try:
            entries.append(json.loads(line))
        except ValueError:
            continue
    return entries, offset + len(complete)


def tail(count: int) -> tuple[list[dict], int]:
    """The last `count` entries and the end offset."""
    entries, end = read_from(0)
    return entries[-count:] if count > 0 else [], end


def describe(e: dict) -> str:
    """One human line for an entry, as `conn watch` prints it."""
    when = time.strftime("%H:%M:%S", time.localtime(e.get("ts", 0)))
    target = e.get("target", "")
    what = {
        "run": lambda: f"run      {target}  {e.get('command', '')}  ({e.get('decision', '')})",
        "start": lambda: f"start    {target}  j:{e.get('job')}  {e.get('command', '')}",
        "exit": lambda: f"exit={e.get('rc')}   {target}  j:{e.get('job')}",
        "approval": lambda: f"ASK      a:{e.get('id')}  {','.join(e.get('targets', []))}  {e.get('command', '')}",
        "approved": lambda: f"approved a:{e.get('id')}  by {e.get('by')}" + (" (always)" if e.get("always") else ""),
        "denied": lambda: f"denied   a:{e.get('id')}  by {e.get('by')}",
        "transfer": lambda: f"transfer {e.get('source')} -> {e.get('dest')}  ({e.get('result', '')})",
        "read-file": lambda: f"read     {target}:{e.get('path')}",
        "target": lambda: f"target   {target}  {e.get('change')}",
        "ssh": lambda: f"ssh      {target}  " + (f"closed exit={e['rc']}" if "rc" in e else "opened"),
        "rule": lambda: f"rule     {target}  {e.get('change')} '{e.get('rule')}'",
    }.get(e.get("event", ""), lambda: f"{e.get('event')} {target}")
    return f"{when}  {what()}"
