"""Scripts Conning sends to targets. Each one goes over ssh's stdin to `sh -s` (POSIX) or as a
base64 `-EncodedCommand` (PowerShell), so quoting never breaks and nothing sensitive is on argv.

A POSIX job runs detached (nohup, in its own process group via setsid when present) and writes to files under
~/.conning/jobs on the target, so it survives a dropped connection and can be polled from any process.
"""

import base64
import shlex

JOBS_DIR = '"$HOME/.conning/jobs"'
POLL_MARK = "CONNING-RC"


def _job_base(job_id: str) -> str:
    if not job_id.isalnum():
        raise ValueError(f"bad job id {job_id!r}")
    return f"b={JOBS_DIR}/{job_id}"


def posix_start(job_id: str, command: str, *, cwd: str | None, timeout: int, env: dict[str, str]) -> str:
    """Start `command` detached. Prints the job's pid. `env` values travel inside this script, not argv."""
    delimiter = f"CONNING_EOF_{job_id}"
    if delimiter in command:
        raise ValueError("command contains the heredoc delimiter")
    body = []
    if cwd:
        body.append(f"cd -- {shlex.quote(cwd)} || exit 97")
    body.append(command)
    exports = "".join(f"export {k}={shlex.quote(v)}\n" for k, v in env.items())
    return (
        "set -e\n"
        'mkdir -p "$HOME/.conning/jobs" && chmod 700 "$HOME/.conning" "$HOME/.conning/jobs"\n'
        f"{_job_base(job_id)}\n"
        f"cat > \"$b.sh\" <<'{delimiter}'\n" + "\n".join(body) + f"\n{delimiter}\n"
        f"{exports}"
        "if command -v setsid >/dev/null 2>&1; then group=setsid; else group=; fi\n"
        f"if command -v timeout >/dev/null 2>&1; then limit='timeout -k 10 {int(timeout)}'; else limit=; fi\n"
        # The wrapper outlives the ssh session (nohup, no tty). The command runs in its own process
        # group, so a signal reaches its whole tree while the wrapper survives to record the exit code.
        'nohup sh -c \'$2 $3 sh "$1.sh" > "$1.out" 2>&1 < /dev/null & echo $! > "$1.pid"; wait $!;'
        ' echo $? > "$1.rc"\' conning "$b" "$group" "$limit" > /dev/null 2>&1 < /dev/null &\n'
        'echo "$!"\n'
    )


def posix_poll(job_id: str, offset: int, limit: int) -> str:
    """Print `CONNING-RC <rc|->` then up to `limit` bytes of output starting at byte `offset`.

    The rc file is written only after the command's output is complete, and it is read before the
    output, so once rc is known the bytes that follow are final."""
    return (
        f"{_job_base(job_id)}\n"
        'if [ -f "$b.rc" ]; then rc=$(cat "$b.rc"); else rc=-; fi\n'
        f'printf "{POLL_MARK} %s\\n" "$rc"\n'
        f'tail -c +{int(offset) + 1} "$b.out" 2>/dev/null | head -c {int(limit)}\n'
    )


def posix_signal(job_id: str, signal: str) -> str:
    if signal not in ("INT", "TERM", "KILL"):
        raise ValueError(f"unsupported signal {signal!r}")
    return (
        f"{_job_base(job_id)}\n"
        'pid=$(cat "$b.pid" 2>/dev/null) || { echo "no such job"; exit 1; }\n'
        f'kill -{signal} -- "-$pid" 2>/dev/null || kill -{signal} "$pid"\n'
    )


def parse_poll(output: bytes) -> tuple[int | None, bytes]:
    head, _, data = output.partition(b"\n")
    if not head.startswith(POLL_MARK.encode()):
        raise ValueError(f"unexpected poll output: {head[:200]!r}")
    rc = head.split()[-1].decode()
    return (None if rc == "-" else int(rc)), data


def posix_read_file(path: str, range_: str | None) -> str:
    """Print a remote file, or a line range of it: `200-260`, or `-50` for the last 50 lines."""
    q = shlex.quote(path)
    if not range_:
        return f"cat -- {q}\n"
    if range_.startswith("-"):
        return f"tail -n {int(range_[1:])} -- {q}\n"
    start, _, end = range_.partition("-")
    return f"sed -n '{int(start)},{int(end) if end else '$'}p' < {q}\n"  # BSD sed rejects --


def posix_sha256(path: str) -> str:
    q = shlex.quote(path)
    return f"(sha256sum -- {q} 2>/dev/null || shasum -a 256 -- {q}) | cut -d' ' -f1\n"


def pwsh_command(script: str, shell: str = "pwsh") -> str:
    """A PowerShell invocation whose script is base64 UTF-16LE, so no shell can mangle its quoting."""
    exe = "powershell" if shell == "powershell" else "pwsh"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    return f"{exe} -NoProfile -NonInteractive -EncodedCommand {encoded}"


def pwsh_script(command: str, *, cwd: str | None, env: dict[str, str]) -> str:
    lines = ["$ErrorActionPreference = 'Continue'"]
    lines += [f"$env:{k} = '{v.replace(chr(39), chr(39) * 2)}'" for k, v in env.items()]
    if cwd:
        lines.append(f"Set-Location -LiteralPath '{cwd.replace(chr(39), chr(39) * 2)}'")
    lines += [command, "if ($LASTEXITCODE -ne $null) { exit $LASTEXITCODE } elseif ($?) { exit 0 } else { exit 1 }"]
    return "\n".join(lines)


def pwsh_read_file(path: str, range_: str | None) -> str:
    p = path.replace("'", "''")
    if not range_:
        return f"Get-Content -LiteralPath '{p}'"
    if range_.startswith("-"):
        return f"Get-Content -LiteralPath '{p}' -Tail {int(range_[1:])}"
    start, _, end = range_.partition("-")
    first = f" -First {int(end) - int(start) + 1}" if end else ""
    return f"Get-Content -LiteralPath '{p}' | Select-Object -Skip {int(start) - 1}{first}"


def pwsh_sha256(path: str) -> str:
    p = path.replace("'", "''")
    return f"(Get-FileHash -Algorithm SHA256 -LiteralPath '{p}').Hash.ToLower()"
