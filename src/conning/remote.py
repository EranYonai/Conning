"""Scripts Conning sends to targets. Each one goes over ssh's stdin: to `sh -s` (POSIX), or to a
PowerShell whose base64 `-EncodedCommand` only reads stdin and runs it. Quoting never breaks and
nothing sensitive is on argv.

A job runs detached and writes to files under ~/.conning/jobs on the target, so it survives a dropped
connection and can be polled from any process. On POSIX that is nohup, in its own process group via
setsid when present. On Windows, OpenSSH kills everything a session started when it closes, so the
job's wrapper is created through WMI (Win32_Process), outside the session (D43).
"""

import base64
import shlex

JOBS_DIR = '"$HOME/.conning/jobs"'
POLL_MARK = "CONNING-RC"


def _job_base(job_id: str) -> str:
    if not job_id.isalnum():
        raise ValueError(f"bad job id {job_id!r}")
    return f"b={JOBS_DIR}/{job_id}"


def _posix_body(command: str, cwd: str | None) -> list[str]:
    # A non-interactive ssh session skips the login profile, so tools installed under ~/.local/bin
    # or /opt are "not found". Adopt the PATH a login shell would have; its other output is dropped.
    show = '\'printf "\\nCONNING_PATH=%s\\n" "$PATH"\''
    body = [
        f"p=$({{ bash -lc {show} || sh -lc {show}; }} 2>/dev/null </dev/null"
        " | sed -n 's/^CONNING_PATH=//p' | tail -n 1)",
        '[ -n "$p" ] && PATH=$p && export PATH',
    ]
    if cwd:
        body.append(f"cd -- {shlex.quote(cwd)} || exit 97")
    return [*body, command]


def posix_start(job_id: str, command: str, *, cwd: str | None, timeout: int, env: dict[str, str]) -> str:
    """Start `command` detached. Prints the job's pid. `env` values travel inside this script, not argv."""
    delimiter = f"CONNING_EOF_{job_id}"
    if delimiter in command:
        raise ValueError("command contains the heredoc delimiter")
    body = _posix_body(command, cwd)
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


def posix_live(job_id: str, command: str, *, cwd: str | None, env: dict[str, str]) -> tuple[str, str]:
    """For `conn run --tty`, whose stdin is the human's keyboard: a script (sent first, on stdin) that
    writes the command and its env to a file only the user can read, and the short command that runs
    that file in the pty. The file deletes itself as it starts."""
    delimiter = f"CONNING_EOF_{job_id}"
    exports = [f"export {k}={shlex.quote(v)}" for k, v in env.items()]
    lines = ['rm -f -- "$0"', *exports, *_posix_body(command, cwd)]
    if any(delimiter in line for line in lines):
        raise ValueError("command contains the heredoc delimiter")
    write = (
        "set -e\numask 077\n"
        'mkdir -p "$HOME/.conning/jobs" && chmod 700 "$HOME/.conning" "$HOME/.conning/jobs"\n'
        f"{_job_base(job_id)}\n"
        f"cat > \"$b.live.sh\" <<'{delimiter}'\n" + "\n".join(lines) + f"\n{delimiter}\n"
    )
    return write, f'sh "$HOME/.conning/jobs/{job_id}.live.sh"'


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


def posix_cleanup(job_id: str) -> str:
    """Delete a finished job's files once its output is copied home."""
    return f'{_job_base(job_id)}\nrm -f -- "$b".*\n'


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


# Runs the script that arrives on stdin, so a secret in it never shows up in a process listing. It reads
# up to an end line, not to end of input: Windows PowerShell over Windows OpenSSH may never see the EOF.
PWSH_STDIN_END = "# CONNING-STDIN-END"
PWSH_STDIN = (
    "[Console]::InputEncoding = [Text.UTF8Encoding]::new($false); $s = [Collections.Generic.List[string]]::new(); "
    f"while ((($l = [Console]::In.ReadLine()) -ne $null) -and $l -cne '{PWSH_STDIN_END}') {{ $s.Add($l) }}; "
    '. ([scriptblock]::Create($s -join "`n"))'
)
PWSH_DETACH_FAILED = "CONNING-NO-DETACH"
SIGNAL_RC = {"INT": 130, "TERM": 143, "KILL": 137}  # what a POSIX shell reports, so both read alike


def pwsh_stdin(shell: str = "pwsh") -> str:
    return pwsh_command(PWSH_STDIN, shell)


def _pwsh_job_base(job_id: str) -> str:
    if not job_id.isalnum():
        raise ValueError(f"bad job id {job_id!r}")
    return f"$d = [IO.Path]::Combine($HOME, '.conning', 'jobs')\n$b = [IO.Path]::Combine($d, '{job_id}')\n"


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


# The wrapper the job runs under, the counterpart of the POSIX `nohup sh -c ...`. It loads the
# injected env (and deletes the file), runs the command with stdout and stderr merged into $b.out,
# enforces the timeout on the whole process tree, and writes the exit code last.
PWSH_WRAPPER = r"""$b = $PSCommandPath.Substring(0, $PSCommandPath.Length - '.run.ps1'.Length)
$win = $env:OS -eq 'Windows_NT'
if (Test-Path -LiteralPath "$b.env") {
    foreach ($line in [IO.File]::ReadAllLines("$b.env")) {
        $k, $v = $line -split "`t", 2
        [Environment]::SetEnvironmentVariable($k, [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($v)))
    }
    Remove-Item -LiteralPath "$b.env" -Force
}
$exe = (Get-Process -Id $PID).Path
$run = "`"$exe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$b.ps1`" > `"$b.out`" 2>&1"
if ($win) { $p = Start-Process -FilePath $env:ComSpec -ArgumentList "/d /s /c `"$run`"" -NoNewWindow -PassThru }
else {
    [IO.File]::WriteAllText("$b.sh", "exec $run`n")
    $p = Start-Process -FilePath '/bin/sh' -ArgumentList "`"$b.sh`"" -PassThru
}
$null = $p.Handle  # keeps ExitCode readable after the process ends
[IO.File]::WriteAllText("$b.pid", "$($p.Id)")
if ($p.WaitForExit(TIMEOUT_MS)) { $p.WaitForExit(); $rc = $p.ExitCode }
else {
    if ($win) { & taskkill.exe /T /F /PID $p.Id *> $null } else { & pkill -KILL -P $p.Id; $p.Kill() }
    $p.WaitForExit(); $rc = 124
}
if (Test-Path -LiteralPath "$b.sig") {
    $rc = @{INT = 130; TERM = 143; KILL = 137}[[IO.File]::ReadAllText("$b.sig").Trim()]
}
[IO.File]::WriteAllText("$b.rc", "$rc")
"""


def pwsh_start(job_id: str, command: str, *, cwd: str | None, timeout: int, env: dict[str, str]) -> str:
    """Start `command` detached on a Windows target. Prints the wrapper's pid, or PWSH_DETACH_FAILED
    when WMI can't create the process (the caller then runs the command synchronously)."""
    # WMI starts the wrapper in the jobs folder; the command starts in $HOME, as over ssh.
    job = "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)\nSet-Location -LiteralPath $HOME\n"
    job += pwsh_script(command, cwd=cwd, env={})
    wrapper = PWSH_WRAPPER.replace("TIMEOUT_MS", str(int(timeout) * 1000))
    env_lines = "".join(f"{k}\t{_b64(v)}\n" for k, v in env.items())
    utf8 = "[Text.UTF8Encoding]::new($true)"  # a BOM, so Windows PowerShell reads -File scripts as UTF-8
    lines = [
        "$ErrorActionPreference = 'Stop'",
        _pwsh_job_base(job_id).rstrip("\n"),
        "$null = New-Item -ItemType Directory -Force -Path $d",
        "$win = $env:OS -eq 'Windows_NT'",
        # Only this user (and SYSTEM) may read the jobs folder, like chmod 700 on POSIX.
        "if ($win) { $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
        '& icacls.exe $d /inheritance:r /grant:r "*${sid}:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" *> $null }',
        "function Put($path, $b64) { [IO.File]::WriteAllText($path, "
        f"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)), {utf8}) }}",
        f"Put \"$b.ps1\" '{_b64(job)}'",
        f"Put \"$b.run.ps1\" '{_b64(wrapper)}'",
    ]
    if env_lines:
        lines.append(f"Put \"$b.env\" '{_b64(env_lines)}'")
    lines += [
        "$exe = (Get-Process -Id $PID).Path",
        '$line = "`"$exe`" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$b.run.ps1`""',
        "if ($win) {",
        "    try {",
        "        $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
        "-Arguments @{ CommandLine = $line; CurrentDirectory = $d }",
        '        if ($r.ReturnValue -ne 0) { throw "Win32_Process.Create returned $($r.ReturnValue)" }',
        "        $r.ProcessId",
        "    } catch {",
        '        Remove-Item -LiteralPath "$b.env" -Force -ErrorAction SilentlyContinue',
        f'        "{PWSH_DETACH_FAILED} $_"; exit 98',
        "    }",
        "} else {",
        "    $p = Start-Process -FilePath $exe "
        "-ArgumentList @('-NoProfile', '-NonInteractive', '-File', \"$b.run.ps1\") "
        '-RedirectStandardOutput "$b.wrap" -RedirectStandardError "$b.wrap.err" -PassThru',
        "    $p.Id",
        "}",
    ]
    return "\n".join(lines) + "\n"


def pwsh_poll(job_id: str, offset: int, limit: int) -> str:
    """The PowerShell twin of posix_poll: `CONNING-RC <rc|->`, then raw output bytes from `offset`."""
    return _pwsh_job_base(job_id) + (
        '$rc = if (Test-Path -LiteralPath "$b.rc") { [IO.File]::ReadAllText("$b.rc").Trim() } else { \'-\' }\n'
        "$o = [Console]::OpenStandardOutput()\n"
        f'$h = [Text.Encoding]::ASCII.GetBytes("{POLL_MARK} $rc`n"); $o.Write($h, 0, $h.Length)\n'
        'if (Test-Path -LiteralPath "$b.out") {\n'
        "    $f = [IO.File]::Open(\"$b.out\", 'Open', 'Read', 'ReadWrite')\n"
        f"    try {{ $null = $f.Seek({int(offset)}, 'Begin'); $buf = New-Object byte[] {int(limit)}; $n = 0\n"
        "        while ($n -lt $buf.Length) {\n"
        "            $k = $f.Read($buf, $n, $buf.Length - $n); if ($k -le 0) { break }; $n += $k\n"
        "        }\n"
        "        $o.Write($buf, 0, $n) } finally { $f.Close() }\n"
        "}\n"
        "$o.Flush()\n"
    )


def pwsh_cleanup(job_id: str) -> str:
    return _pwsh_job_base(job_id) + f"Get-ChildItem -LiteralPath $d -Filter '{job_id}.*' | Remove-Item -Force\n"


def pwsh_signal(job_id: str, signal: str) -> str:
    """Windows has no signals: any of them records its name (so the exit code reads like POSIX) and
    ends the job's whole process tree."""
    if signal not in SIGNAL_RC:
        raise ValueError(f"unsupported signal {signal!r}")
    return _pwsh_job_base(job_id) + (
        "if (-not (Test-Path -LiteralPath \"$b.pid\")) { 'no such job'; exit 1 }\n"
        '$id = [int][IO.File]::ReadAllText("$b.pid").Trim()\n'
        f"[IO.File]::WriteAllText(\"$b.sig\", '{signal}')\n"
        "if ($env:OS -eq 'Windows_NT') { & taskkill.exe /T /F /PID $id *> $null }\n"
        "else { & pkill -KILL -P $id; Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }\n"
        "exit 0\n"
    )


def pwsh_script(command: str, *, cwd: str | None, env: dict[str, str]) -> str:
    # No progress records: Windows PowerShell writes them to the log as CLIXML.
    lines = ["$ErrorActionPreference = 'Continue'", "$ProgressPreference = 'SilentlyContinue'"]
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
