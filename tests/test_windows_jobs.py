"""D43: Windows jobs run detached like POSIX ones. The real PowerShell scripts run against a local
`pwsh` behind the fake transport; on Windows runners that includes the WMI launch itself."""

import base64
import sys

import pytest
from conftest import needs_pwsh, target, write_targets

from conning import remote
from conning.state import Job, grant_lease

pytestmark = needs_pwsh


def win(**kw):
    return target("win", os="windows", shell="pwsh", **kw)


@pytest.fixture(autouse=True)
def _lease(home):
    grant_lease("win", 10)  # these tests are about jobs, not approvals


def jobs_dir(transport):
    return transport.remote_home / ".conning" / "jobs"


def job_of(out: str) -> str:
    return out.split("job=j:")[1].split()[0]


def test_a_job_streams_output_and_keeps_secrets_off_argv(core, transport):
    write_targets(win(inject={"TOK": "env:TOK"}))
    transport.env["win"] = {"TOK": "s3cret-tok"}
    out = core.run(
        "win", cmd="Write-Output tick-1; Write-Output $env:TOK; [Console]::Error.WriteLine('oops'); exit 3", wait=60
    )
    assert out.startswith("exit=3") and "tick-1" in out and "oops" in out
    assert "s3cret-tok" not in out and "[REDACTED]" in out
    assert all("s3cret" not in command for _, command, _ in transport.calls)  # argv carries no secret
    first = transport.calls[0][1]
    assert base64.b64decode(first.rsplit(" ", 1)[1]).decode("utf-16-le") == remote.PWSH_STDIN
    assert not list(jobs_dir(transport).glob("*.env"))  # the wrapper deleted it after reading


def test_a_long_job_is_polled_for_new_lines_then_signalled(core):
    write_targets(win())
    out = core.run("win", cmd="Write-Output started; Start-Sleep 120", wait=0)
    job = job_of(out)
    for _ in range(40):
        out = core.read(f"j:{job}", wait=2)
        if "started" in out:
            break
    assert out.startswith("status=running") and "started" in out
    assert core.read(f"j:{job}", signal="TERM") == f"signal=TERM sent to j:{job}"
    assert core.read(f"j:{job}", wait=60).startswith("exit=143")
    assert core.read(f"j:{job}", signal="TERM") == f"error: j:{job} is not a running job"


def test_timeout_ends_the_job_tree(core):
    write_targets(win())
    out = core.run("win", cmd="Start-Sleep 120", wait=60, timeout=2)
    assert out.startswith("exit=124") and "(timed out)" in out


def test_without_wmi_it_runs_while_connected(core, transport, monkeypatch):
    write_targets(win())
    monkeypatch.setattr(remote, "pwsh_start", lambda *a, **k: f"'{remote.PWSH_DETACH_FAILED} no WMI'; exit 98\n")
    out = core.run("win", argv=["Write-Output", "sync"], wait=30)
    assert out.startswith("exit=0") and "sync" in out
    job = Job.load(out.split("out=o:")[1].split()[0])
    assert job.detached is False and job.posix is False
    assert core.read(f"j:{job.id}", signal="INT") == f"error: j:{job.id} is not a running job"


def test_without_wmi_an_ssh_failure_is_an_error(core, transport, monkeypatch):
    write_targets(win())
    monkeypatch.setattr(remote, "pwsh_start", lambda *a, **k: f"'{remote.PWSH_DETACH_FAILED} no WMI'; exit 98\n")
    calls = []
    real = transport.exec

    def exec_(t, command, *, stdin=None, timeout=60):
        calls.append(command)
        return real(t, command, stdin=stdin, timeout=timeout) if len(calls) == 1 else (255, b"Connection reset")

    transport.exec = exec_
    assert core.run("win", argv=["Write-Output", "x"]) == "error: win: explained rc=255"


def test_a_failed_start_is_an_error(core, transport, monkeypatch):
    write_targets(win())
    monkeypatch.setattr(remote, "pwsh_start", lambda *a, **k: "'denied'; exit 5\n")
    assert core.run("win", argv=["Write-Output", "x"]) == "error: win: explained rc=5"


@pytest.mark.skipif(sys.platform == "win32", reason="checks the non-Windows test branch of the wrapper")
def test_scripts_validate_their_inputs():
    with pytest.raises(ValueError):
        remote.pwsh_poll("../x", 0, 10)
    with pytest.raises(ValueError):
        remote.pwsh_signal("abc", "HUP")
    assert (
        "TIMEOUT_MS"
        not in base64.b64decode(
            remote.pwsh_start("abc", "x", cwd=None, timeout=5, env={}).split("$b.run.ps1\" '")[1].split("'")[0]
        ).decode()
    )
