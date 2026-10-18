import time
from dataclasses import replace

import pytest
from conftest import needs_sh, target, write_targets

from conning.state import Approval, Job

ALLOW_ECHO = (("echo",), ("sleep",), ("printf",), ("cat",))


def lab(**kw):
    kw.setdefault("allow", ALLOW_ECHO)
    return target("lab", **kw)


def shell_lab(*others):
    """`sh -c` is a wrapper and always asks, so tests that need a shell put lab in mode=auto."""
    write_targets(lab(mode="auto"), *others)


# --- argument and target checks ---------------------------------------------------------------


def test_run_needs_exactly_one_of_cmd_or_argv(core):
    assert core.run("lab").startswith("error: give exactly one")
    assert core.run("lab", cmd="x", argv=["x"]).startswith("error: give exactly one")
    assert core.run("lab", argv=[]).startswith("error: give exactly one")


def test_unknown_targets_and_empty_tags(core):
    write_targets(lab())
    assert core.run("nope", argv=["echo"]) == "error: unknown target(s) nope (see targets)"
    assert core.run("tag:none", argv=["echo"]) == "error: no target matches 'tag:none' (see targets)"


def test_bad_target_file_is_an_error_not_a_crash(core, home):
    (home / "targets.toml").write_text("[x]\nhost='h'\n")
    assert core.run("x", argv=["echo"]).startswith("error: ")
    assert core.targets().startswith("error: ")


# --- policy -----------------------------------------------------------------------------------


def test_pending_target_is_blocked(core):
    write_targets(lab(status="pending"))
    assert core.run("lab", argv=["echo", "hi"]).startswith("blocked  lab  (target is pending")


def test_ask_creates_one_approval(core, transport):
    write_targets(lab())
    out = core.run("lab", argv=["systemctl", "stop", "x"])
    assert out.startswith("status=pending_approval id=a:") and "not on the allowlist" in out
    assert transport.calls == []  # nothing ran
    a = Approval.load(out.split("id=a:")[1].split()[0])
    assert a.targets == ["lab"] and a.argv == ["systemctl", "stop", "x"]


def test_shell_syntax_always_asks(core):
    write_targets(lab())
    assert "shell syntax always asks" in core.run("lab", cmd="echo hi | sh")


@needs_sh
def test_auto_runs_anything_without_asking(core):
    write_targets(lab(allow=(), mode="auto"))
    assert core.run("lab", cmd="uname | cat").startswith("exit=0")


# --- running jobs -----------------------------------------------------------------------------


@needs_sh
def test_run_returns_exit_code_first_and_output(core):
    shell_lab()
    out = core.run("lab", argv=["sh", "-c", "echo hello; exit 3"])
    assert out == "exit=3\nhello"  # fast and complete: no duration, no handle


@needs_sh
def test_the_header_names_the_handle_only_when_output_is_hidden(core):
    shell_lab()
    cut = core.run("lab", cmd="seq 1 500").splitlines()[0]
    assert cut.startswith("exit=0 out=o:") and "(500 lines" in cut
    grepped = core.run("lab", cmd="seq 1 20", grep="^1$")
    assert grepped.startswith("exit=0 out=o:") and grepped.endswith("\n1")
    slow = core.run("lab", cmd="sleep 1.1; echo done")
    assert slow.startswith("exit=0 dur=1.") and slow.endswith("\ndone")


@needs_sh
def test_a_finished_job_leaves_no_files_on_the_target(core, transport):
    shell_lab()
    assert core.run("lab", cmd="seq 1 3") == "exit=0\n1\n2\n3"
    assert list((transport.remote_home / ".conning" / "jobs").iterdir()) == []


@needs_sh
def test_cmd_string_and_cwd(core, transport):
    write_targets(lab())
    (transport.remote_home / "work").mkdir()
    out = core.run("lab", cmd="cat note.txt", cwd=str(transport.remote_home / "work"))
    assert out.startswith("exit=1")  # file does not exist, but cd worked
    assert "note.txt" in out
    bad = core.run("lab", cmd="echo x", cwd="/definitely/not/here")
    assert bad.startswith("exit=97")


@needs_sh
def test_long_job_returns_a_handle_then_streams_new_lines(core):
    shell_lab()
    out = core.run("lab", argv=["sh", "-c", "echo one; sleep 1; echo two"], wait=0)
    assert out.startswith("status=running job=j:")
    job_id = out.split("job=j:")[1].split()[0]
    final = core.read(f"j:{job_id}", wait=10)
    assert final.startswith("exit=0")
    assert "two" in final
    again = core.read(f"j:{job_id}")
    assert again.split("\n")[0].startswith("exit=0") and "one" not in again  # only new lines


@needs_sh
def test_timeout_is_labelled(core):
    shell_lab()
    out = core.run("lab", argv=["sh", "-c", "exit 124"])
    assert out.startswith("exit=124") and "(timed out)" in out


@needs_sh
def test_signal_stops_a_running_job(core):
    write_targets(lab())
    out = core.run("lab", argv=["sleep", "30"], wait=0)
    job_id = out.split("job=j:")[1].split()[0]
    for _ in range(50):  # the wrapper writes the pid file just after starting
        if (core.transport.remote_home / ".conning/jobs" / f"{job_id}.pid").exists():
            break
        time.sleep(0.05)
    assert core.read(f"j:{job_id}", signal="TERM") == f"signal=TERM sent to j:{job_id}"
    assert core.read(f"j:{job_id}", wait=10).startswith("exit=143")
    assert core.read(f"j:{job_id}", signal="TERM").startswith("error: ")


@needs_sh
def test_secrets_injected_as_env_are_redacted(core, transport):
    shell_lab()
    transport.env["lab"] = {"TOKEN": "hunter2-secret"}
    out = core.run("lab", argv=["sh", "-c", "echo token=$TOKEN"])
    assert "hunter2-secret" not in out and "token=[REDACTED]" in out


@needs_sh
def test_fanout_collapses_identical_output(core):
    write_targets(lab(), replace(lab(), name="lab2"), replace(lab(), name="lab3", tags=("x",)))
    out = core.run("lab,lab2", argv=["echo", "same"])
    assert out.splitlines()[0] == "2 targets: 2 ok, 0 failed"
    assert "exit=0  lab,lab2  (identical output)" in out


def test_start_failure_is_reported(core, transport):
    write_targets(lab(), replace(lab(), name="lab2"))
    transport.canned["sh -s"] = (255, b"Connection refused")
    assert core.run("lab", argv=["echo"]) == "error: lab: explained rc=255"
    out = core.run("lab,lab2", argv=["echo"])
    assert "error: lab: explained rc=255" in out and "error: lab2" in out


def test_transport_exceptions_become_errors(core, transport):
    write_targets(lab())
    transport.raise_on = "sh -s"
    assert core.run("lab", argv=["echo"]) == "error: lab: boom"


def test_drain_survives_poll_errors(core, transport, home):
    write_targets(lab())
    job = Job(id="abc123", target="lab", command="x", started=time.time())
    job.save()
    transport.raise_on = "sh -s"
    out = core.read("j:abc123", wait=0)
    assert out.startswith("status=running job=j:abc123")


def test_read_job_for_a_removed_target(core):
    Job(id="aa11", target="gone", command="x", started=time.time()).save()
    assert core.read("j:aa11").startswith("status=running")
    assert core.read("j:aa11", signal="INT") == "error: j:aa11 is not a running job"


def test_signal_errors(core, transport):
    write_targets(lab())
    Job(id="bb22", target="lab", command="x", started=time.time()).save()
    transport.canned["sh -s"] = (1, b"no such job")
    assert core.read("j:bb22", signal="INT") == "error: no such job"
    transport.raise_on = "sh -s"
    assert core.read("j:bb22", signal="INT") == "error: boom"


# --- reading outputs ----------------------------------------------------------------------------


def test_read_output_ranges_and_grep(core, home):
    job = Job(id="cc33", target="lab", command="x", started=time.time(), rc=0, finished=time.time())
    job.save()
    job.append("\n".join(f"line {i}" for i in range(1, 11)) + "\n")
    assert core.read("o:cc33", range="2-3").splitlines() == ["out=o:cc33 lines 2-3 of 10", "line 2", "line 3"]
    assert core.read("o:cc33", range="9-").splitlines()[1:] == ["line 9", "line 10"]
    assert core.read("o:cc33", range="-1").splitlines() == ["out=o:cc33 last 1 lines of 10", "line 10"]
    assert core.read("o:cc33", range="-0").splitlines() == ["out=o:cc33 last 0 lines of 10"]
    assert core.read("o:cc33", grep=r"line 1\d?$").splitlines()[1:] == ["line 1", "line 10"]
    assert core.read("o:cc33", grep="(").splitlines()[0].startswith("out=o:cc33")  # bad regex -> substring
    assert core.read("o:cc33", range="5-2").startswith("error: range")
    assert core.read("o:cc33", range="x").startswith("error: range")
    assert core.read("o:cc33").splitlines()[0] == "out=o:cc33 lines 1-10 of 10"


def test_read_unknown_ids(core):
    assert core.read("j:nope") == "error: no job j:nope"
    assert core.read("o:nope") == "error: no output o:nope"
    assert core.read("a:nope") == "error: no approval a:nope"
    assert core.read("j:../../etc") == "error: no job j:../../etc"
    assert core.read("whatever").startswith("error: id must be")


# --- approvals ----------------------------------------------------------------------------------


def test_read_approval_pending_then_denied(core):
    a = Approval(id="dd44", targets=["lab"], command=None, argv=["reboot"], cwd=None, timeout=60)
    a.save()
    assert core.read("a:dd44").startswith("status=pending_approval id=a:dd44")
    a.status = "denied"
    a.save()
    assert core.read("a:dd44") == "status=denied id=a:dd44 (the human declined: reboot)"


def test_read_approval_long_polls_until_decided(home, transport):
    from conning.core import Core

    a = Approval(id="ee55", targets=["lab"], command="reboot now", argv=None, cwd=None, timeout=60)
    a.save()
    clock = [0.0]

    def sleep(seconds):
        clock[0] += seconds
        a.status = "denied"
        a.save()

    c = Core(transport=transport, clock=lambda: clock[0], sleep=sleep)
    assert c.read("a:ee55", wait=5).startswith("status=denied")


@needs_sh
def test_approved_command_starts_once(core):
    write_targets(lab(allow=()))
    out = core.run("lab", argv=["echo", "approved!"])
    approval_id = out.split("id=a:")[1].split()[0]
    a = Approval.load(approval_id)
    a.status = "approved"
    a.save()
    first = core.read(f"a:{approval_id}", wait=10)
    assert first.startswith(f"approved a:{approval_id}: started lab=j:") and "approved!" in first
    second = core.read(f"a:{approval_id}")
    assert second.splitlines()[0] == first.splitlines()[0]  # not started twice


def test_approved_command_on_several_targets_lists_jobs(core, transport):
    write_targets(lab(), replace(lab(), name="lab2"))
    a = Approval(
        id="ff66", targets=["lab", "lab2", "gone"], command=None, argv=["echo"], cwd=None, timeout=5, status="approved"
    )
    a.save()
    transport.canned["sh -s"] = (255, b"down")
    out = core.read("a:ff66")
    assert out.startswith("approved a:ff66: started lab=error: lab: explained rc=255")


# --- remote files -------------------------------------------------------------------------------


@needs_sh
def test_read_remote_file(core, transport):
    write_targets(lab())
    f = transport.remote_home / "app.log"
    f.write_text("a\nb\nc\nd\n")
    assert core.read(f"lab:{f}").splitlines() == [f"file=lab:{f} untrusted", "a", "b", "c", "d"]
    assert core.read(f"lab:{f}", range="2-3").splitlines()[1:] == ["b", "c"]
    assert core.read(f"lab:{f}", range="-1").splitlines()[1:] == ["d"]
    assert core.read(f"lab:{f}", range="3-").splitlines()[1:] == ["c", "d"]
    assert core.read(f"lab:{f}", grep="b|d").splitlines()[1:] == ["b", "d"]
    assert core.read("lab:/no/such/file").startswith("error: lab:/no/such/file: exit=")


def test_read_remote_file_errors(core, transport):
    write_targets(lab(), replace(lab(), name="pend", status="pending"))
    assert core.read("nope:/x").startswith("error: unknown target nope")
    assert core.read("pend:/x").startswith("error: pend is pending")
    transport.raise_on = "sh -s"
    assert core.read("lab:/x") == "error: boom"


# --- Windows targets ----------------------------------------------------------------------------


def win(**kw):
    return target("win", os="windows", shell="pwsh", allow=(("Get-Service",),), **kw)


def test_windows_ssh_failure(core, transport):
    write_targets(win())
    transport.canned["pwsh"] = (255, b"Connection refused")
    assert core.run("win", argv=["Get-Service"]) == "error: win: explained rc=255"


def test_windows_read_file(core, transport):
    write_targets(win())
    transport.canned["pwsh"] = (0, b"line\n")
    assert core.read("win:C:\\logs\\a.log", range="-5").splitlines() == [
        "file=win:C:\\logs\\a.log lines=-5 untrusted",
        "line",
    ]


# --- transfer -----------------------------------------------------------------------------------


@needs_sh
def test_upload_and_download_are_verified(core, transport, tmp_path):
    write_targets(lab())
    local = tmp_path / "local.txt"
    local.write_text("payload\n")
    remote_file = transport.remote_home / "up.txt"
    assert core.transfer(f"local:{local}", f"lab:{remote_file}") == "ok 1 file, 8B, sha256 verified"
    downloads = tmp_path / "dl"
    downloads.mkdir()
    assert core.transfer(f"lab:{remote_file}", f"local:{downloads}") == "ok 1 file, 8B, sha256 verified"
    assert (downloads / "up.txt").read_text() == "payload\n"


def test_transfer_argument_errors(core, tmp_path):
    write_targets(lab(), replace(lab(), name="pend", status="pending"))
    assert core.transfer("a", "b").startswith("error: use local:")
    assert core.transfer("local:/a", "local:/b").startswith("error: exactly one side")
    assert core.transfer("lab:/a", "pend:/b").startswith("error: exactly one side")
    assert core.transfer("local:/a", "nope:/b").startswith("error: unknown target nope")
    assert core.transfer("local:/a", "pend:/b").startswith("error: pend is pending")
    assert core.transfer(f"local:{tmp_path / 'missing'}", "lab:/b").startswith("error: local:")


def test_transfer_copy_and_verify_failures(core, transport, tmp_path):
    write_targets(lab())
    local = tmp_path / "f.txt"
    local.write_text("x")
    transport.copy_result = (1, b"scp: permission denied")
    assert core.transfer(f"local:{local}", "lab:/tmp/f").startswith("error: copy failed (exit=1)")
    transport.copy_result = (0, b"")
    transport.canned["sh -s"] = (0, b"deadbeef\n")
    assert core.transfer(f"local:{local}", "lab:/tmp/f").startswith("error: sha256 mismatch")
    transport.raise_on = "sh -s"
    assert core.transfer(f"local:{local}", "lab:/tmp/f").startswith("error: copied, but could not verify")
    transport.raise_on = None

    def broken_copy(*a, **k):
        from conning.ssh import SSHError

        raise SSHError("no scp")

    transport.copy = broken_copy
    assert core.transfer(f"local:{local}", "lab:/tmp/f") == "error: no scp"


def test_transfer_directory(core, transport, tmp_path):
    write_targets(lab())
    src = tmp_path / "dir"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_text("aa")
    (src / "sub" / "b.txt").write_text("bbbb")
    out = core.transfer(f"local:{src}", f"lab:{transport.remote_home / 'dir'}")
    assert out == "ok directory, 2 files, 6B (directories are not hashed)"


def test_transfer_windows_verifies_with_get_filehash(core, transport, tmp_path):
    import hashlib

    write_targets(win())
    local = tmp_path / "f.txt"
    local.write_text("x")
    transport.copy_result = (0, b"")
    transport.canned["pwsh"] = (0, hashlib.sha256(b"x").hexdigest().upper().encode())
    assert core.transfer(f"local:{local}", "win:C:\\f.txt") == "ok 1 file, 1B, sha256 verified"


# --- targets --------------------------------------------------------------------------------------


def test_targets_check(core, transport):
    write_targets(
        lab(), replace(lab(), name="down"), replace(lab(), name="pend", status="pending"), replace(lab(), name="err")
    )
    transport.canned["exit 0"] = (0, b"")

    def exec_(t, command, *, stdin=None, timeout=60):
        if t.name == "down":
            return 255, b""
        if t.name == "err":
            from conning.ssh import SSHError

            raise SSHError("x")
        return 0, b""

    transport.exec = exec_
    out = core.targets(check=True)
    assert "reach=ok" in out and "down" in out and "reach=unreachable" in out and "reach=pending" in out
    assert core.targets("tag:none") == "no target matches 'tag:none' (conn targets lists all)"


def test_helpers():
    from conning.core import _human

    assert _human(10) == "10B"
    assert _human(2048) == "2.0KB"
    assert _human(5 * 1024**3) == "5.0GB"


@pytest.mark.parametrize("bad", ["../x", "a b"])
def test_job_ids_are_validated(core, bad):
    assert core.read(f"j:{bad}").startswith("error: no job")


@needs_sh
def test_unresolvable_secret_is_an_error_not_a_crash(core, transport):
    """Found by the MCP smoke test: an unset env: reference used to raise out of read."""
    shell_lab()
    f = transport.remote_home / "app.log"
    f.write_text("token=abc\n")
    out = core.run("lab", argv=["sh", "-c", "echo one; sleep 1; echo two"], wait=0)
    job_id = out.split("job=j:")[1].split()[0]
    transport.secret_error = "secret env:DEMO_TOKEN: environment variable is not set"
    assert core.read(f"lab:{f}") == "error: secret env:DEMO_TOKEN: environment variable is not set"
    assert "token=abc" not in core.read(f"lab:{f}")
    assert core.read(f"j:{job_id}").startswith("status=running")  # nothing shown that could not be redacted
    transport.secret_error = None
    assert "two" in core.read(f"j:{job_id}", wait=10)


def test_clixml_split_across_polls_is_held_back_until_complete():
    from conning.core import POLL_CHUNK, _without_clixml

    assert _without_clixml(b'#< CLIXML\r\nhi\r\n<Objs Version="1"><Obj/></Objs>\r\nbye', False) == (b"hi\r\nbye", 51)
    assert _without_clixml(b'hi\n<Objs Version="1"><Obj', False) == (b"hi\n", 3)
    assert _without_clixml(b'hi\n<Objs Version="1"><Obj', True) == (b'hi\n<Objs Version="1"><Obj', 25)
    full = b"<Objs Version=" + b"x" * (POLL_CHUNK - 14)  # a block bigger than a poll is let through
    assert _without_clixml(full, False) == (full, POLL_CHUNK)
