"""The engine behind the four agent tools. The MCP server and the CLI both call this, so their output
is identical. Policy is enforced here, in code, on every call.
"""

import codecs
import contextlib
import hashlib
import re
import shlex
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from conning import audit, notify, paths, remote
from conning.output import DEFAULT_MAX_BYTES, clamp_max_bytes, render, render_fanout
from conning.policy import is_allowed, is_safe, policy_argv
from conning.secrets import Redactor, SecretError, redact
from conning.ssh import SSHError
from conning.state import Approval, Job, new_id, problems
from conning.targets import Target, TargetFileError, listing, load_targets, select
from conning.transport import SSHTransport, Transport

POLL_CHUNK = 1 << 20
APPROVE_HINT = "human runs: conn approve a:{id}"
PENDING = re.compile(r"^status=pending_approval id=a:(\w+).*$", re.M)


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
        self.notify = True  # off when a human runs `conn run` at a terminal and is asked right there

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

    def _script(self, t: Target, script: str, timeout: float = 60) -> tuple[int, bytes]:
        """Run one of Conning's own scripts on the target, sent over stdin."""
        if t.os == "windows":
            if remote.PWSH_STDIN_END in script.splitlines():
                raise ValueError(f"script contains the line {remote.PWSH_STDIN_END}")
            stdin = f"{script}\n{remote.PWSH_STDIN_END}\n".encode()
            return self.transport.exec(t, remote.pwsh_stdin(t.shell), stdin=stdin, timeout=timeout)
        return self.transport.exec(t, "sh -s", stdin=script.encode(), timeout=timeout)

    def _one(self, name: str) -> tuple[Target | None, str | None]:
        """One live target by name, or the error line for the agent."""
        t = self.load().get(name)
        if t is None:
            return None, f"error: unknown target {name} (see targets)"
        if t.status == "pending":
            return None, f"error: {name} is pending; human runs: conn approve {name}"
        return t, None

    def _exec_short(self, t: Target, posix: str, pwsh: str) -> tuple[int, bytes]:
        """Run a short read-only script: on stdin to `sh -s`, or as an encoded PowerShell command."""
        if t.os == "windows":
            return self.transport.exec(t, remote.pwsh_command(pwsh, t.shell))
        return self.transport.exec(t, "sh -s", stdin=posix.encode())

    def _decide(self, t: Target, words: list[str] | None) -> str:
        """run | approve | blocked"""
        if t.status == "pending":
            return "blocked"
        if t.mode == "auto" or is_allowed(words, t.allow) or (t.safe and is_safe(words)):
            return "run"
        return "approve"

    def would_ask(self, target: str, cmd: str | None, argv: list[str] | None) -> list[str]:
        """The targets where this command would wait for approval. No side effects; errors mean none."""
        try:
            chosen, err = self._pick(target)
        except TargetFileError:
            return []
        return [] if err else [t.name for t in chosen if self._decide(t, policy_argv(cmd, argv)) == "approve"]

    # --- targets ------------------------------------------------------------------------------

    def targets(self, filter: str | None = None, check: bool = False) -> str:
        try:
            everything = self.load()
        except TargetFileError as e:
            return f"error: {e}"
        if not everything:
            return f"no targets in {paths.targets_file()} (add one with: conn targets add <name>)"
        chosen = select(everything, filter)
        if not chosen:
            return f"no target matches {filter!r} (conn targets lists all)"
        notes = problems()
        if not check:
            return listing(chosen, notes=notes)

        def probe(t: Target) -> str:
            if t.status == "pending":
                return "pending"
            try:
                rc, _ = self.transport.exec(t, "exit 0", timeout=15)
            except (SSHError, SecretError):
                return "unreachable"
            return "ok" if rc == 0 else "unreachable"

        reach = dict(zip((t.name for t in chosen), _each(probe, chosen), strict=True))
        return listing(chosen, reach, notes)

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
        words = policy_argv(cmd, argv)
        first = (words or [""])[0]
        if first in self.load():
            names = ",".join(dict.fromkeys([*(t.name for t in chosen), first]))
            return (
                f"error: '{first}' is a target, not a command; to run on several targets, "
                f"join them with commas: {names} <command>"
            )
        decisions = {t.name: self._decide(t, words) for t in chosen}
        shown = cmd if cmd is not None else shlex.join(argv or [])
        for t in chosen:
            audit.record("run", target=t.name, command=shown, decision=decisions[t.name], cwd=cwd)
        notes = []
        for t in chosen:
            if decisions[t.name] == "blocked":
                notes.append(f"blocked  {t.name}  (target is pending; human runs: conn approve {t.name})")
        needs = [t.name for t in chosen if decisions[t.name] == "approve"]
        if needs:
            a = Approval(id=new_id(), targets=needs, command=cmd, argv=argv, cwd=cwd, timeout=timeout)
            a.save()
            audit.record("approval", id=a.id, targets=needs, command=shown)
            if self.notify:
                notify.approval_waiting(a.id, needs, shown)
            reason = "shell syntax always asks" if words is None else "not on the allowlist"
            notes.append(
                f"status=pending_approval id=a:{a.id} targets={','.join(needs)} ({reason}; "
                f"{APPROVE_HINT.format(id=a.id)}); then read a:{a.id}"
            )
        runnable = [t for t in chosen if decisions[t.name] == "run"]
        if not runnable:
            return "\n".join(notes)
        result = self._start_and_wait(runnable, cmd, argv, cwd, wait, timeout, max_bytes, grep)
        return "\n".join([*notes, result]) if notes else result

    def live(
        self,
        target: str,
        cmd: str | None,
        argv: list[str] | None,
        cwd: str | None,
        confirm: Callable[[Target, list[str] | None, str], bool],
        write: Callable[[str], None],
    ) -> int | str:
        """`conn run --tty`: one POSIX target, in a pty, its output streamed to `write` (redacted) as it comes.
        Policy is run's; a command that would wait for approval is put to `confirm`, the human at this
        terminal. Returns the exit code, or an error line."""
        try:
            chosen, err = self._pick(target)
        except TargetFileError as e:
            return f"error: {e}"
        if err:
            return err
        if len(chosen) != 1:
            return "error: --tty runs on one target"
        t = chosen[0]
        if t.os == "windows":
            return f"error: --tty needs a Linux or macOS target; {t.name} is Windows"
        words = policy_argv(cmd, argv)
        decision = self._decide(t, words)
        shown = cmd if cmd is not None else shlex.join(argv or [])
        audit.record("run", target=t.name, command=shown, decision=decision, cwd=cwd, tty=True)
        if decision == "blocked":
            return f"error: {t.name} is pending; human runs: conn approve {t.name}"
        if decision == "approve" and not confirm(t, words, shown):
            return 1
        job_id = new_id()
        command = self._command_for(t, cmd, argv)
        decode = codecs.getincrementaldecoder("utf-8")(errors="replace").decode
        try:
            hide = Redactor(self.transport.secrets(t))  # resolved first: output that can't be redacted is never shown
            prepare, run_file = remote.posix_live(job_id, command, cwd=cwd, env=self.transport.inject_env(t))
            rc, out = self._script(t, prepare)
            if rc != 0:
                return f"error: {t.name}: {self.transport.explain(t, rc, out)}"
            audit.record("start", target=t.name, job=job_id, command=command, tty=True)
            rc = self.transport.live(t, run_file, lambda chunk: write(hide.feed(decode(chunk))))
            if rc == 255:  # ssh failed, maybe before the file could delete itself
                self._script(t, f'rm -f "$HOME/.conning/jobs/{job_id}.live.sh"\n')
        except (SSHError, SecretError, ValueError) as e:
            return f"error: {t.name}: {e}"
        write(hide.feed(decode(b"", final=True)) + hide.held)
        audit.record("exit", target=t.name, job=job_id, rc=rc)
        return rc

    def _start(self, t: Target, cmd: str | None, argv: list[str] | None, cwd: str | None, timeout: int):
        """Start one job. Returns (Job, None) or (None, error line)."""
        command = self._command_for(t, cmd, argv)
        job = Job(id=new_id(), target=t.name, command=command, started=self.clock(), posix=t.os != "windows")
        try:
            env = self.transport.inject_env(t)
            start = remote.posix_start if job.posix else remote.pwsh_start
            rc, out = self._script(t, start(job.id, command, cwd=cwd, timeout=timeout, env=env))
            if rc == 98 and remote.PWSH_DETACH_FAILED.encode() in out:
                # WMI is off on this machine: run while connected, as M1 did, and say so.
                job.detached = False
                rc, out = self._script(t, remote.pwsh_script(command, cwd=cwd, env=env), timeout=timeout)
                if rc == 255:
                    return None, f"error: {t.name}: {self.transport.explain(t, rc, out)}"
                job.append(redact(out.decode(errors="replace"), self.transport.secrets(t)))
                job.rc, job.finished = rc, self.clock()
                with contextlib.suppress(SSHError):  # the scripts written before WMI failed
                    self._script(t, remote.pwsh_cleanup(job.id))
            elif rc != 0:
                return None, f"error: {t.name}: {self.transport.explain(t, rc, out)}"
            else:
                job.pid = out.decode(errors="replace").strip().splitlines()[-1] if out.strip() else None
        except (SSHError, SecretError, ValueError) as e:
            return None, f"error: {t.name}: {e}"
        job.save()
        audit.record("start", target=t.name, job=job.id, command=command)
        if job.rc is not None:
            audit.record("exit", target=t.name, job=job.id, rc=job.rc)
        return job, None

    def _start_and_wait(self, targets, cmd, argv, cwd, wait, timeout, max_bytes, grep) -> str:
        started = _each(lambda t: self._start(t, cmd, argv, cwd, timeout), targets)
        jobs = [j for j, _ in started if j]
        errors = [e for _, e in started if e]
        until = self.clock() + max(0, wait)
        if jobs:
            _each(lambda j: self._drain(j, until), jobs)
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
        if t is None or job.rc is not None or not job.detached:
            return
        while True:
            if (saved := Job.load(job.id)) and saved.rc is not None:  # another process finished it, files gone
                vars(job).update(vars(saved))
                return
            try:
                hide = self.transport.secrets(t)  # resolved first: output that can't be redacted is never shown
                poll = remote.posix_poll if job.posix else remote.pwsh_poll
                rc_ssh, out = self._script(t, poll(job.id, job.fetched, POLL_CHUNK))
                rc, data = remote.parse_poll(out) if rc_ssh == 0 else (None, b"")
            except (SSHError, SecretError, ValueError):
                rc, data, rc_ssh = None, b"", 255
            full = len(data) == POLL_CHUNK
            final = rc is not None and not full
            used = len(data)
            if data and not job.posix:
                data, used = _without_clixml(data, final)
            if data:
                job.append(redact(data.decode(errors="replace"), hide))
            job.fetched += used
            if final:
                job.rc, job.finished = rc, self.clock()
                audit.record("exit", target=job.target, job=job.id, rc=rc)
            job.save()
            if job.rc is not None:
                with contextlib.suppress(SSHError, SecretError, ValueError):  # left behind is only clutter
                    self._script(t, (remote.posix_cleanup if job.posix else remote.pwsh_cleanup)(job.id))
                return
            if self.clock() >= until:
                return
            if not full:
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
        header = f"exit={job.rc}" + (f" dur={dur:.1f}s" if dur >= 1 else "")
        if grep:  # the full output is not on screen, so name its handle even when nothing was cut
            header += f" out=o:{job.id}"
        if job.rc == 124 and job.detached:
            header += " (timed out)"
        return render(header, _grep(new, grep), max_bytes=max_bytes, handle=f"o:{job.id}", name_handle=not grep)

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
            if t is None or not job.detached or job.rc is not None:
                return f"error: j:{job_id} is not a running job"
            try:
                rc, out = self._script(t, (remote.posix_signal if job.posix else remote.pwsh_signal)(job_id, signal))
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
            targets = self.load()
            for t in (targets[n] for n in a.targets if n in targets):
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
        t, err = self._one(name)
        if err:
            return err
        audit.record("read-file", target=name, path=path)
        try:
            hide = self.transport.secrets(t)
            rc, out = self._exec_short(t, remote.posix_read_file(path, range_), remote.pwsh_read_file(path, range_))
        except (SSHError, SecretError, ValueError) as e:
            return f"error: {e}"
        text = redact(out.decode(errors="replace"), hide)
        if rc != 0:
            return f"error: {name}:{path}: exit={rc}\n{text.strip()[:2000]}"
        header = f"file={name}:{path}" + (f" lines={range_}" if range_ else "") + " untrusted"
        return render(header, _grep(text, grep), max_bytes=max_bytes)

    # --- transfer -----------------------------------------------------------------------------

    def transfer(self, source: str, dest: str) -> str:
        result = self._transfer(source, dest)
        audit.record("transfer", source=source, dest=dest, result=result.splitlines()[0][:200])
        return result

    def _transfer(self, source: str, dest: str) -> str:
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
        t, err = self._one(name)
        if err:
            return err
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
        try:
            rc, out = self._exec_short(t, remote.posix_sha256(remote_path), remote.pwsh_sha256(remote_path))
        except (SSHError, SecretError) as e:
            return f"error: copied, but could not verify: {e}"
        remote_sum = out.decode(errors="replace").strip().lower()
        if rc != 0 or remote_sum != local_sum:
            return f"error: sha256 mismatch after copy (local {local_sum[:12]}, remote {remote_sum[:12] or '?'})"
        return f"ok 1 file, {_human(local_path.stat().st_size)}, sha256 verified"


CLIXML = re.compile(rb"#< CLIXML\r?\n|<Objs Version=.*?</Objs>(?:\r?\n)?", re.S)


def _progress_only(m: re.Match) -> bytes:
    """Keep a block holding anything but progress records (an error, user output that looks alike)."""
    kinds = set(re.findall(rb'<Obj S="(\w+)"', m[0]))
    return b"" if m[0].startswith(b"#") or kinds == {b"progress"} else m[0]


def _without_clixml(data: bytes, final: bool) -> tuple[bytes, int]:
    """Windows PowerShell writes progress records into redirected output as CLIXML: drop them. A block
    not yet complete is left for the next poll. Returns (output, bytes of `data` used)."""
    used = len(data)
    start = data.rfind(b"<Objs Version=")
    if not final and start != -1 and b"</Objs>" not in data[start:] and (start or used < POLL_CHUNK):
        used = start
    return CLIXML.sub(_progress_only, data[:used]), used


def _each(fn, items) -> list:
    """`fn` over `items` in parallel. On Ctrl-C, stop at once rather than wait for the calls still running."""
    pool = ThreadPoolExecutor(max_workers=16)
    try:
        return list(pool.map(fn, items))
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def _grep(text: str, pattern: str | None) -> str:
    if not pattern:
        return text
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
