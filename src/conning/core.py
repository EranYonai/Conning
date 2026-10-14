"""The engine behind the four agent tools. The MCP server and the CLI both call this, so their output
is identical. Policy is enforced here, in code, on every call.
"""

import shlex
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from conning import paths, remote
from conning.output import DEFAULT_MAX_BYTES, clamp_max_bytes, render, render_fanout
from conning.policy import is_allowed, split_command
from conning.secrets import SecretError, redact
from conning.ssh import SSHError
from conning.state import Approval, Job, lease_until, new_id
from conning.targets import Target, TargetFileError, listing, load_targets, select
from conning.transport import SSHTransport, Transport

POLL_CHUNK = 1 << 20
APPROVE_HINT = "human runs: conn approve a:{id}"


class Core:
    def __init__(
        self,
        transport: Transport | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        poll_interval: float = 0.5,
    ):
        self.transport = transport or SSHTransport()
        self.clock = clock
        self.sleep = sleep
        self.poll_interval = poll_interval

    # --- helpers ------------------------------------------------------------------------------

    def load(self) -> dict[str, Target]:
        return load_targets(paths.targets_file())

    def _pick(self, selector: str) -> tuple[list[Target], str | None]:
        targets = self.load()
        chosen = select(targets, selector)
        if not selector.startswith("tag:"):
            unknown = [n.strip() for n in selector.split(",") if n.strip() not in targets]
            if unknown:
                return [], f"error: unknown target(s) {', '.join(unknown)} (see targets)"
        if not chosen:
            return [], f"error: no target matches {selector!r} (see targets)"
        return chosen, None

    def _command_for(self, t: Target, cmd: str | None, argv: list[str] | None) -> str:
        if cmd is not None:
            return cmd
        if t.os == "windows":
            return "& " + " ".join("'" + a.replace("'", "''") + "'" for a in argv or [])
        return shlex.join(argv or [])

    def _decide(self, t: Target, policy_argv: list[str] | None) -> str:
        """run | approve | refused | blocked"""
        if t.status == "pending":
            return "blocked"
        if lease_until(t.name):
            return "run"
        if is_allowed(policy_argv, t.allow):
            return "run"
        return "refused" if t.mode == "observe" else "approve"

    # --- targets ------------------------------------------------------------------------------

    def targets(self, filter: str | None = None, check: bool = False) -> str:
        try:
            chosen = select(self.load(), filter)
        except TargetFileError as e:
            return f"error: {e}"
        if not check or not chosen:
            return listing(chosen)

        def probe(t: Target) -> str:
            if t.status == "pending":
                return "pending"
            try:
                rc, _ = self.transport.exec(t, "exit 0", timeout=15)
            except (SSHError, SecretError):
                return "unreachable"
            return "ok" if rc == 0 else "unreachable"

        with ThreadPoolExecutor(max_workers=16) as pool:
            reach = dict(zip((t.name for t in chosen), pool.map(probe, chosen), strict=True))
        return listing(chosen, reach)

    # --- run ----------------------------------------------------------------------------------

    def run(
        self,
        target: str,
        cmd: str | None = None,
        argv: list[str] | None = None,
        cwd: str | None = None,
        wait: int = 30,
        timeout: int = 3600,
        max_bytes: int = DEFAULT_MAX_BYTES,
        grep: str | None = None,
    ) -> str:
        if (cmd is None) == (argv is None) or (argv is not None and not argv):
            return "error: give exactly one of cmd (a string) or argv (a list)"
        try:
            chosen, err = self._pick(target)
        except TargetFileError as e:
            return f"error: {e}"
        if err:
            return err
        policy_argv = argv if argv is not None else split_command(cmd or "")
        decisions = {t.name: self._decide(t, policy_argv) for t in chosen}
        notes = []
        for t in chosen:
            if decisions[t.name] == "blocked":
                notes.append(f"blocked  {t.name}  (target is pending; human runs: conn approve {t.name})")
            elif decisions[t.name] == "refused":
                notes.append(f"refused  {t.name}  (mode=observe allows allowlisted commands only)")
        needs = [t.name for t in chosen if decisions[t.name] == "approve"]
        if needs:
            a = Approval(id=new_id(), targets=needs, command=cmd, argv=argv, cwd=cwd, timeout=timeout)
            a.save()
            reason = "shell syntax always asks" if policy_argv is None else "not on the allowlist"
            notes.append(
                f"status=pending_approval id=a:{a.id} targets={','.join(needs)} ({reason}; "
                f"{APPROVE_HINT.format(id=a.id)}); then read a:{a.id}"
            )
        runnable = [t for t in chosen if decisions[t.name] == "run"]
        if not runnable:
            return "\n".join(notes)
        result = self._start_and_wait(runnable, cmd, argv, cwd, wait, timeout, max_bytes, grep)
        return "\n".join([*notes, result]) if notes else result

    def _start(self, t: Target, cmd: str | None, argv: list[str] | None, cwd: str | None, timeout: int):
        """Start one job. Returns (Job, None) or (None, error line)."""
        command = self._command_for(t, cmd, argv)
        job = Job(id=new_id(), target=t.name, command=command, started=self.clock(), posix=t.os != "windows")
        try:
            env = self.transport.inject_env(t)
            if job.posix:
                script = remote.posix_start(job.id, command, cwd=cwd, timeout=timeout, env=env)
                rc, out = self.transport.exec(t, "sh -s", stdin=script.encode(), timeout=60)
                if rc != 0:
                    return None, f"error: {t.name}: {self.transport.explain(t, rc, out)}"
                job.pid = out.decode(errors="replace").strip().splitlines()[-1] if out.strip() else None
            else:  # PowerShell targets run synchronously until detached Windows jobs land
                script = remote.pwsh_script(command, cwd=cwd, env=env)
                rc, out = self.transport.exec(t, remote.pwsh_command(script, t.shell), timeout=timeout)
                if rc == 255 and self.transport.is_ssh_failure(rc, out):
                    return None, f"error: {t.name}: {self.transport.explain(t, rc, out)}"
                job.append(redact(out.decode(errors="replace"), self.transport.secrets(t)))
                job.rc, job.finished = rc, self.clock()
        except (SSHError, SecretError, ValueError) as e:
            return None, f"error: {t.name}: {e}"
        job.save()
        return job, None

    def _start_and_wait(self, targets, cmd, argv, cwd, wait, timeout, max_bytes, grep) -> str:
        with ThreadPoolExecutor(max_workers=16) as pool:
            started = list(pool.map(lambda t: self._start(t, cmd, argv, cwd, timeout), targets))
        jobs = [j for j, _ in started if j]
        errors = [e for _, e in started if e]
        until = self.clock() + max(0, wait)
        if jobs:
            with ThreadPoolExecutor(max_workers=16) as pool:
                list(pool.map(lambda j: self._drain(j, until), jobs))
        if len(targets) == 1 and jobs:
            return self._job_result(jobs[0], max_bytes, grep)
        if len(targets) == 1:
            return errors[0]
        results = {}
        for j in jobs:
            text = j.text()
            j.seen = len(text)
            j.save()
            results[f"{j.target} (j:{j.id})" if j.rc is None else j.target] = (j.rc, _grep(text, grep))
        out = render_fanout(results, max_bytes=max_bytes) if results else ""
        return "\n".join([*errors, out]).strip()

    def _drain(self, job: Job, until: float) -> None:
        """Copy new output from the target into the local log until the job ends or `until` passes."""
        t = self.load().get(job.target)
        if t is None or job.rc is not None or not job.posix:
            return
        while True:
            try:
                rc_ssh, out = self.transport.exec(
                    t, "sh -s", stdin=remote.posix_poll(job.id, job.fetched, POLL_CHUNK).encode(), timeout=60
                )
                rc, data = remote.parse_poll(out) if rc_ssh == 0 else (None, b"")
            except (SSHError, SecretError, ValueError):
                rc, data, rc_ssh = None, b"", 255
            if data:
                job.append(redact(data.decode(errors="replace"), self.transport.secrets(t)))
                job.fetched += len(data)
            if rc is not None and len(data) < POLL_CHUNK:
                job.rc, job.finished = rc, self.clock()
            job.save()
            if job.rc is not None or self.clock() >= until:
                return
            if len(data) < POLL_CHUNK:
                self.sleep(self.poll_interval)

    def _job_result(self, job: Job, max_bytes: int, grep: str | None) -> str:
        text = job.text()
        new = text[job.seen :]
        job.seen = len(text)
        job.save()
        dur = (job.finished or self.clock()) - job.started
        if job.rc is None:
            lines = new.count("\n")
            header = f"status=running job=j:{job.id} dur={dur:.1f}s +{lines} lines"
            return render(header, _grep(new, grep), max_bytes=max_bytes, head=0, tail=20, handle=f"o:{job.id}")
        header = f"exit={job.rc} dur={dur:.1f}s out=o:{job.id}"
        if job.rc == 124 and job.posix:
            header += " (timed out)"
        return render(header, _grep(new, grep), max_bytes=max_bytes, handle=f"o:{job.id}")

    # --- read ---------------------------------------------------------------------------------

    def read(
        self,
        id: str,
        wait: int = 0,
        range: str | None = None,
        grep: str | None = None,
        signal: str | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> str:
        max_bytes = clamp_max_bytes(max_bytes)
        kind, _, rest = id.partition(":")
        if kind == "j":
            return self._read_job(rest, wait, grep, signal, max_bytes)
        if kind == "o":
            return self._read_output(rest, range, grep, max_bytes)
        if kind == "a":
            return self._read_approval(rest, wait, grep, max_bytes)
        if rest:
            return self._read_file(kind, rest, range, grep, max_bytes)
        return "error: id must be j:<job>, o:<output>, a:<approval> or <target>:<path>"

    def _read_job(self, job_id, wait, grep, signal, max_bytes) -> str:
        job = Job.load(job_id)
        if job is None:
            return f"error: no job j:{job_id}"
        if signal:
            t = self.load().get(job.target)
            if t is None or not job.posix or job.rc is not None:
                return f"error: j:{job_id} is not a running job"
            try:
                rc, out = self.transport.exec(t, "sh -s", stdin=remote.posix_signal(job_id, signal).encode())
            except (SSHError, SecretError, ValueError) as e:
                return f"error: {e}"
            return f"signal={signal} sent to j:{job_id}" if rc == 0 else f"error: {out.decode(errors='replace')}"
        self._drain(job, self.clock() + max(0, wait))
        return self._job_result(job, max_bytes, grep)

    def _read_output(self, job_id, range_, grep, max_bytes) -> str:
        job = Job.load(job_id)
        if job is None:
            return f"error: no output o:{job_id}"
        lines = job.text().splitlines()
        try:
            picked, label = _slice(lines, range_)
        except ValueError:
            return "error: range must look like 200-260, 200- or -50"
        header = f"out=o:{job_id} {label} of {len(lines)}"
        return render(header, _grep("\n".join(picked), grep), max_bytes=max_bytes, handle=f"o:{job_id}")

    def _read_approval(self, approval_id, wait, grep, max_bytes) -> str:
        a = Approval.load(approval_id)
        if a is None:
            return f"error: no approval a:{approval_id}"
        until = self.clock() + max(0, wait)
        while a.status == "pending" and self.clock() < until:
            self.sleep(1)
            a = Approval.load(approval_id) or a
        if a.status == "pending":
            return f"status=pending_approval id=a:{a.id} ({APPROVE_HINT.format(id=a.id)})"
        if a.status == "denied":
            return f"status=denied id=a:{a.id} (the human declined: {a.display})"
        if not a.jobs:
            targets = {t.name: t for t in self.load().values()}
            chosen = [targets[n] for n in a.targets if n in targets]
            for t in chosen:
                job, err = self._start(t, a.command, a.argv, a.cwd, a.timeout)
                a.jobs[t.name] = job.id if job else err or "error"
            a.save()
        ids = [j for j in a.jobs.values() if not j.startswith("error")]
        lines = [
            f"approved a:{a.id}: started "
            + ", ".join(f"{n}={j}" if j.startswith("error") else f"{n}=j:{j}" for n, j in a.jobs.items())
        ]
        if len(ids) == 1:
            lines.append(self._read_job(ids[0], wait, grep, None, max_bytes))
        return "\n".join(lines)

    def _read_file(self, name, path, range_, grep, max_bytes) -> str:
        t = self.load().get(name)
        if t is None:
            return f"error: unknown target {name} (see targets)"
        if t.status == "pending":
            return f"error: {name} is pending; human runs: conn approve {name}"
        try:
            if t.os == "windows":
                rc, out = self.transport.exec(t, remote.pwsh_command(remote.pwsh_read_file(path, range_), t.shell))
            else:
                rc, out = self.transport.exec(t, "sh -s", stdin=remote.posix_read_file(path, range_).encode())
        except (SSHError, SecretError, ValueError) as e:
            return f"error: {e}"
        text = redact(out.decode(errors="replace"), self.transport.secrets(t))
        if rc != 0:
            return f"error: {name}:{path}: exit={rc}\n{text.strip()[:2000]}"
        header = f"file={name}:{path}" + (f" lines={range_}" if range_ else "") + " untrusted"
        return render(header, _grep(text, grep), max_bytes=max_bytes)

    # --- transfer -----------------------------------------------------------------------------

    def transfer(self, source: str, dest: str) -> str:
        src_kind, _, src_path = source.partition(":")
        dst_kind, _, dst_path = dest.partition(":")
        if not src_path or not dst_path:
            return "error: use local:<path> and <target>:<path>"
        if (src_kind == "local") == (dst_kind == "local"):
            return "error: exactly one side must be local:<path>"
        upload = src_kind == "local"
        name, remote_path, local_path = (
            (dst_kind, dst_path, Path(src_path).expanduser()) if upload else (src_kind, src_path, Path(dst_path))
        )
        t = self.load().get(name)
        if t is None:
            return f"error: unknown target {name} (see targets)"
        if t.status == "pending":
            return f"error: {name} is pending; human runs: conn approve {name}"
        if upload and t.mode == "observe" and not lease_until(name):
            return f"refused  {name}  (mode=observe: uploads are not allowed)"
        if upload and not local_path.exists():
            return f"error: local:{local_path} does not exist"
        if not upload and local_path.is_dir():
            local_path = local_path / Path(remote_path.replace("\\", "/")).name
        try:
            rc, out = self.transport.copy(t, local_path, remote_path, upload=upload)
        except (SSHError, SecretError) as e:
            return f"error: {e}"
        if rc != 0:
            return f"error: copy failed (exit={rc}): {out.decode(errors='replace').strip()[:500]}"
        if local_path.is_dir():
            files = [p for p in local_path.rglob("*") if p.is_file()]
            size = sum(p.stat().st_size for p in files)
            return f"ok directory, {len(files)} files, {_human(size)} (directories are not hashed)"
        local_sum = _sha256(local_path)
        check = remote.pwsh_sha256(remote_path) if t.os == "windows" else remote.posix_sha256(remote_path)
        try:
            if t.os == "windows":
                rc, out = self.transport.exec(t, remote.pwsh_command(check, t.shell))
            else:
                rc, out = self.transport.exec(t, "sh -s", stdin=check.encode())
        except (SSHError, SecretError) as e:
            return f"error: copied, but could not verify: {e}"
        remote_sum = out.decode(errors="replace").strip().lower()
        if rc != 0 or remote_sum != local_sum:
            return f"error: sha256 mismatch after copy (local {local_sum[:12]}, remote {remote_sum[:12] or '?'})"
        return f"ok 1 file, {_human(local_path.stat().st_size)}, sha256 verified"


def _grep(text: str, pattern: str | None) -> str:
    if not pattern:
        return text
    import re

    try:
        rx = re.compile(pattern)
    except re.error:
        return "\n".join(line for line in text.splitlines() if pattern in line)
    return "\n".join(line for line in text.splitlines() if rx.search(line))


def _slice(lines: list[str], range_: str | None) -> tuple[list[str], str]:
    if not range_:
        return lines, f"lines 1-{len(lines)}"
    if range_.startswith("-"):
        n = int(range_[1:])
        return lines[-n:] if n else [], f"last {n} lines"
    start_s, _, end_s = range_.partition("-")
    start = int(start_s)
    end = int(end_s) if end_s else len(lines)
    if start < 1 or end < start:
        raise ValueError(range_)
    return lines[start - 1 : end], f"lines {start}-{min(end, len(lines))}"


def _sha256(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n}B"  # pragma: no cover
