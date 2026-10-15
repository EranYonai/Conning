"""Small JSON records: jobs, approval requests and target problems in the state dir; leases in the config dir.

Every process (the MCP server, any `conn` CLI call) reads and writes the same files, so a job started
by the agent over MCP can be read from a terminal, and an approval granted in a terminal reaches the agent.
"""

import json
import os
import secrets as _random
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from conning import paths


def _dir(kind: str) -> Path:
    d = paths.state_dir() / kind
    d.mkdir(parents=True, exist_ok=True)
    return d


def new_id() -> str:
    return _random.token_hex(4)


def _write(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    os.replace(tmp, path)


@dataclass
class Job:
    id: str
    target: str
    command: str  # what was run, for display
    started: float
    posix: bool = True
    detached: bool = True  # polled on the target; false only when a Windows target couldn't detach
    fetched: int = 0  # bytes copied from the target's output file into the local log
    seen: int = 0  # bytes of the local log already returned to the agent through `read`
    rc: int | None = None
    finished: float | None = None
    pid: str | None = None

    @property
    def log(self) -> Path:
        return _dir("out") / f"{self.id}.log"

    def save(self) -> None:
        _write(_dir("jobs") / f"{self.id}.json", asdict(self))

    @classmethod
    def load(cls, job_id: str) -> "Job | None":
        path = _dir("jobs") / f"{job_id}.json"
        if not job_id.isalnum() or not path.exists():
            return None
        return cls(**json.loads(path.read_text(encoding="utf-8")))

    def append(self, data: str) -> None:
        with self.log.open("a", encoding="utf-8") as f:
            f.write(data)

    def text(self) -> str:
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""


@dataclass
class Approval:
    """A command waiting for the human. `status` is pending, approved or denied."""

    id: str
    targets: list[str]
    command: str | None
    argv: list[str] | None
    cwd: str | None
    timeout: int
    created: float = field(default_factory=time.time)
    status: str = "pending"
    jobs: dict[str, str] = field(default_factory=dict)  # target -> job id, once started

    def save(self) -> None:
        _write(_dir("approvals") / f"{self.id}.json", asdict(self))

    @classmethod
    def load(cls, approval_id: str) -> "Approval | None":
        path = _dir("approvals") / f"{approval_id}.json"
        if not approval_id.isalnum() or not path.exists():
            return None
        return cls(**json.loads(path.read_text(encoding="utf-8")))

    @property
    def display(self) -> str:
        from shlex import join

        return self.command if self.command is not None else join(self.argv or [])


def _leases_file() -> Path:
    return paths.config_dir() / "leases.json"  # a human grant, so it lives with the config


def lease_until(target: str) -> float | None:
    path = _leases_file()
    leases = json.loads(path.read_text()) if path.exists() else {}
    until = leases.get(target)
    return until if until and until > time.time() else None


def grant_lease(target: str, minutes: int) -> float:
    path = _leases_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    leases = json.loads(path.read_text()) if path.exists() else {}
    until = time.time() + minutes * 60
    leases[target] = until
    _write(path, leases)
    return until


def _problems_file() -> Path:
    return _dir("targets") / "problems.json"


def problems() -> dict[str, str]:
    """Why each pending target is pending, as recorded by the last enrolment attempt."""
    path = paths.state_dir() / "targets" / "problems.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def set_problem(target: str, reason: str | None) -> None:
    current = problems()
    if reason is None and target not in current:
        return
    if reason is None:
        current.pop(target)
    else:
        current[target] = reason
    _write(_problems_file(), current)


def pending_approvals() -> list[Approval]:
    """Commands still waiting for the human, oldest first."""
    found = [Approval.load(p.stem) for p in _dir("approvals").glob("*.json")]
    return sorted((a for a in found if a is not None and a.status == "pending"), key=lambda a: a.created)


def output_logs() -> list[Path]:
    return sorted(_dir("out").glob("*.log"))
