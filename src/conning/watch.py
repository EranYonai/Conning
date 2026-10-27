"""`conn watch`: the human's live view. Every command on every target as it happens, the output of
running jobs, and a prompt for each command that waits for approval.

It only reads local files (the audit log and the job logs that the agent's reads fill in), so it
never touches a target and can run next to any number of agents.
"""

import time
from collections.abc import Callable

from conning import admin, audit, state
from conning.core import Core
from conning.state import Job, output_logs, pending_approvals

TAIL_LINES = 40  # most lines of one job's new output shown per tick


def watch(
    core: Core,
    io: admin.IO,
    *,
    history: int = 10,
    follow: bool = True,
    prompt: bool = True,
    sleep: Callable[[float], None] = time.sleep,
    ticks: int | None = None,
) -> int:
    entries, offset = audit.tail(history)
    for e in entries:
        io.say(audit.describe(e))
    if not follow:
        return 0
    sizes = {p: p.stat().st_size for p in output_logs()}  # start at the end: old output is not news
    asked: set[str] = set()
    if prompt and not io.tty:
        io.say("(no terminal: showing activity only; approve with conn approve a:<id>)")
    io.say("watching; Ctrl-C to stop")
    with state.watching():  # an agent's read of a pending approval waits only while someone watches
        while ticks is None or ticks > 0:
            entries, offset = audit.read_from(offset)
            for e in entries:
                io.say(audit.describe(e))
            for path in output_logs():
                _show_new_output(io, path, sizes)
            if prompt and io.tty:
                for a in pending_approvals():
                    if a.id not in asked:
                        asked.add(a.id)
                        admin.approve(core, io, f"a:{a.id}")
            if ticks is not None:
                ticks -= 1
            sleep(1)
    return 0


def _show_new_output(io: admin.IO, path, sizes: dict) -> None:
    size = path.stat().st_size
    start = sizes.get(path, 0)
    sizes[path] = size
    if size <= start:
        return
    with path.open("rb") as f:
        f.seek(start)
        lines = f.read().decode(errors="replace").splitlines()
    job = Job.load(path.stem)
    label = f"{job.target} j:{path.stem}" if job else f"j:{path.stem}"
    if len(lines) > TAIL_LINES:
        io.say(f"  {label} | ... {len(lines) - TAIL_LINES} lines (conn read o:{path.stem})")
        lines = lines[-TAIL_LINES:]
    for line in lines:
        io.say(f"  {label} | {line}")
