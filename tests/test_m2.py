"""M2: the audit log, desktop notices, allow/deny, watch, doctor and approvals in the agent client."""

import asyncio
import json
import time

import pytest
from conftest import needs_sh, target, write_targets
from test_admin import FakeIO

from conning import admin, audit, cli, doctor, notify, paths, secrets, server, ssh, watch
from conning.state import Approval, Job, grant_lease, set_problem
from conning.targets import load_targets


def events(kind=None):
    entries, _ = audit.read_from(0)
    return [e for e in entries if kind is None or e["event"] == kind]


def pending(command="uname -a", targets=("lab",)):
    from conning.state import new_id

    a = Approval(id=new_id(), targets=list(targets), command=command, argv=None, cwd=None, timeout=60)
    a.save()
    return a


# --- audit log ------------------------------------------------------------------------------------


def test_audit_appends_and_reads_from_an_offset():
    audit.record("run", target="lab", command="uname", decision="run", cwd=None)
    first, offset = audit.read_from(0)
    assert first[0]["event"] == "run" and "cwd" not in first[0]  # None fields are left out
    audit.record("exit", target="lab", job="ab", rc=0)
    more, end = audit.read_from(offset)
    assert [e["event"] for e in more] == ["exit"] and end > offset
    assert audit.tail(1)[0][0]["event"] == "exit" and audit.tail(0)[0] == []


def test_audit_waits_for_partial_lines_and_skips_junk():
    path = audit.log_file()
    path.parent.mkdir(parents=True)
    path.write_bytes(b'not json\n{"event":"run","ts":1}\n{"event":"ha')  # bytes: no CRLF on Windows
    entries, offset = audit.read_from(0)
    assert [e["event"] for e in entries] == ["run"] and offset == len('not json\n{"event":"run","ts":1}\n')


def test_audit_without_a_file_or_a_writable_dir(monkeypatch, tmp_path):
    assert audit.read_from(0) == ([], 0)
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setenv("CONNING_STATE", str(blocker / "state"))  # a path under a file can't be created
    audit.record("run")  # no exception: the command already ran


@pytest.mark.parametrize(
    "entry, expected",
    [
        ({"event": "run", "target": "lab", "command": "ls", "decision": "approve"}, "run      lab  ls  (approve)"),
        ({"event": "start", "target": "lab", "job": "ab", "command": "ls"}, "start    lab  j:ab  ls"),
        ({"event": "exit", "target": "lab", "job": "ab", "rc": 2}, "exit=2   lab  j:ab"),
        ({"event": "approval", "id": "cd", "targets": ["a", "b"], "command": "ls"}, "ASK      a:cd  a,b  ls"),
        ({"event": "approved", "id": "cd", "by": "client", "always": True}, "approved a:cd  by client (always)"),
        ({"event": "denied", "id": "cd", "by": "terminal"}, "denied   a:cd  by terminal"),
        ({"event": "transfer", "source": "local:a", "dest": "lab:/b", "result": "ok"}, "transfer local:a -> lab:/b"),
        ({"event": "read-file", "target": "lab", "path": "/etc/hosts"}, "read     lab:/etc/hosts"),
        ({"event": "lease", "target": "lab", "minutes": 5}, "lease    lab  5 min"),
        ({"event": "target", "target": "lab", "change": "live"}, "target   lab  live"),
        ({"event": "rule", "target": "lab", "change": "allow", "rule": "df"}, "rule     lab  allow 'df'"),
        ({"event": "other", "target": "lab"}, "other lab"),
    ],
)
def test_audit_describe(entry, expected):
    assert expected in audit.describe({"ts": time.time(), **entry})


# --- desktop notices ------------------------------------------------------------------------------


def test_notice_off_by_env(monkeypatch):
    called = []
    monkeypatch.setattr(notify.subprocess, "run", lambda *a, **k: called.append(a))
    assert notify.approval_waiting("ab", ["lab"], "ls") is False and called == []


def test_notice_per_platform(monkeypatch):
    monkeypatch.setenv("CONNING_NOTIFY", "1")
    sent = []
    monkeypatch.setattr(notify.subprocess, "run", lambda argv, **k: sent.append(argv))
    monkeypatch.setattr(notify.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(notify.sys, "platform", "darwin")
    assert notify.approval_waiting("ab", ["lab"], 'echo "hi"\\  ' + "x" * 200)
    script = sent[-1][2]
    assert sent[-1][:2] == ["osascript", "-e"] and '\\"hi\\"' in script and "…" in script
    monkeypatch.setattr(notify.sys, "platform", "linux")
    assert notify.approval_waiting("ab", ["lab"], "ls")
    assert sent[-1][:2] == ["notify-send", "--app-name=Conning"] and "conn approve a:ab" in sent[-1][3]
    monkeypatch.setattr(notify.sys, "platform", "win32")
    assert notify.approval_waiting("ab", ["lab"], "ls") is False


def test_notice_failure_is_quiet(monkeypatch):
    monkeypatch.setenv("CONNING_NOTIFY", "1")
    monkeypatch.setattr(notify.sys, "platform", "linux")
    monkeypatch.setattr(notify.shutil, "which", lambda name: "/usr/bin/notify-send")

    def broken(*a, **k):
        raise OSError("no display")

    monkeypatch.setattr(notify.subprocess, "run", broken)
    assert notify.approval_waiting("ab", ["lab"], "ls") is False


# --- the engine writes the audit log --------------------------------------------------------------


@needs_sh
def test_run_and_approval_are_audited(core, monkeypatch):
    noticed = []
    monkeypatch.setattr(notify, "approval_waiting", lambda *a: noticed.append(a))
    write_targets(target("lab", allow=(("echo",),)))
    assert core.run("lab", argv=["echo", "hi"]).startswith("exit=0")
    out = core.run("lab", cmd="uname -a")
    approval_id = out.split("id=a:")[1].split()[0]
    assert [e["event"] for e in events()] == ["run", "start", "exit", "run", "approval"]
    assert events("run")[1]["decision"] == "approve" and events("approval")[0]["id"] == approval_id
    assert noticed == [(approval_id, ["lab"], "uname -a")]


@needs_sh
def test_long_job_exit_and_file_reads_are_audited(core, transport):
    write_targets(target("lab", allow=(("sleep",),)))
    out = core.run("lab", argv=["sleep", "1"], wait=0)
    job_id = out.split("job=j:")[1].split()[0]
    assert core.read(f"j:{job_id}", wait=10).startswith("exit=0")
    assert events("exit")[0]["job"] == job_id
    (transport.remote_home / "f.txt").write_text("x\n")
    core.read(f"lab:{transport.remote_home / 'f.txt'}")
    assert events("read-file")[0]["path"].endswith("f.txt")


def test_windows_sync_job_and_transfer_are_audited(core, transport, tmp_path):
    write_targets(target("win", os="windows", shell="pwsh", allow=(("hostname",),)))
    transport.canned["pwsh"] = (0, b"WIN-1\n")
    assert core.run("win", argv=["hostname"]).startswith("exit=0")
    assert [e["event"] for e in events()][-2:] == ["start", "exit"]
    assert core.transfer("local:/nope", "win:/x").startswith("error:")
    assert events("transfer")[0]["result"].startswith("error: local:")


# --- answering approvals --------------------------------------------------------------------------


def test_decide_once_always_deny(home):
    write_targets(target("lab"))
    a = pending("systemctl status sshd")
    assert admin.decide(a, "always", by="client").startswith("always allowing 'systemctl status' on lab")
    assert ("systemctl", "status") in load_targets(paths.targets_file())["lab"].allow
    assert admin.decide(a, "once", by="client") == f"a:{a.id} is already approved"
    b = pending("ls -la | wc -l")  # shell syntax: nothing to remember, so 'always' is just once
    said = admin.decide(b, "always", by="terminal")
    assert said == f"approved a:{b.id}; the agent sees the result with read a:{b.id}"
    c = pending()
    assert admin.decide(c, "deny", by="terminal") == f"denied a:{c.id}"
    assert [(e["event"], e["by"]) for e in events() if e["event"] in ("approved", "denied")] == [
        ("approved", "client"),
        ("approved", "terminal"),
        ("denied", "terminal"),
    ]
    assert events("approved")[0]["always"] is True and "always" not in events("approved")[1]


# --- allow / deny ---------------------------------------------------------------------------------


def test_allow_lists_rules_without_a_terminal(home):
    write_targets(target("lab", allow=(("df",), ("systemctl", "status"))), target("db", tags=("x",)))
    io = FakeIO(tty=False)
    assert admin.allow(io, "lab,db", []) == 0
    assert io.said == ["lab: 'df', 'systemctl status'", "db: (none)"]


def test_allow_adds_a_rule_after_confirming(home):
    write_targets(target("lab"), target("db", tags=("x",)))
    io = FakeIO("y")
    assert admin.allow(io, "tag:x", ["Systemctl", "status"]) == 0
    assert load_targets(paths.targets_file())["db"].allow == (("systemctl", "status"),)
    assert "allowing 'systemctl status' on db" in io.text
    assert events("rule")[0] == {**events("rule")[0], "target": "db", "change": "allow"}
    io = FakeIO("y")
    assert admin.allow(io, "db", ["systemctl", "status"]) == 0 and "was already allowed" in io.text


@pytest.mark.parametrize(
    "words, answer, message",
    [
        (["sh", "-c"], None, "error: rules match words, not flags"),
        (["bash", "x"], None, "error: 'bash' can run anything"),
        (["df"], "n", "no change"),
    ],
)
def test_allow_refusals(home, words, answer, message):
    write_targets(target("lab"))
    io = FakeIO(*([answer] if answer else []))
    assert admin.allow(io, "lab", words) == 1
    assert message in io.text and load_targets(paths.targets_file())["lab"].allow == ()


def test_allow_needs_a_terminal_and_a_target(home):
    write_targets(target("lab"))
    io = FakeIO(tty=False)
    assert admin.allow(io, "lab", ["df"]) == 1 and "needs a human" in io.text
    io = FakeIO()
    assert admin.allow(io, "nope", ["df"]) == 1 and "no target matches 'nope'" in io.text


def test_deny_removes_a_rule_without_a_terminal(home):
    write_targets(target("lab", allow=(("df",), ("uname",))), target("db"))
    io = FakeIO(tty=False)
    assert admin.deny(io, "lab,db", ["df"]) == 0
    assert load_targets(paths.targets_file())["lab"].allow == (("uname",),)
    assert "'df' now asks again on lab" in io.text and events("rule")[0]["change"] == "deny"
    assert admin.deny(io, "lab", ["df"]) == 0 and "no target had the rule 'df'" in io.text
    assert admin.deny(io, "nope", ["df"]) == 1
    assert admin.deny(io, "lab", []) == 1 and "give the command words" in io.text


def test_lease_add_and_remove_are_audited(core, monkeypatch):
    monkeypatch.setattr(ssh, "scan_host_keys", lambda host, port: [("ssh-ed25519", "SHA256:abc", "QUFB")])
    monkeypatch.setattr(admin, "probe", lambda core, t: ("linux", "bash", None))
    assert admin.add(core, FakeIO(tty=False), "lab", host="192.0.2.10", user="u") == 0
    assert admin.approve(core, FakeIO("y"), "lab") == 0
    assert admin.lease(FakeIO("y"), "lab", 5) == 0
    monkeypatch.setattr(ssh, "pin_host_keys", lambda name, keys: None)
    assert admin.remove(FakeIO(), "lab") == 0
    assert [(e["event"], e.get("change")) for e in events()] == [
        ("target", "proposed"),
        ("target", "live"),
        ("lease", None),
        ("target", "removed"),
    ]


# --- watch ----------------------------------------------------------------------------------------


def test_watch_shows_history_and_stops(home):
    for i in range(3):
        audit.record("lease", target=f"t{i}", minutes=i)
    io = FakeIO(tty=False)
    assert watch.watch(None, io, history=2, follow=False) == 0
    assert len(io.said) == 2 and "t2" in io.said[-1]


def test_watch_follows_events_output_and_prompts(home, monkeypatch):
    write_targets(target("lab"))
    old = Job(id="old1", target="lab", command="x", started=0)
    old.save()
    old.append("already seen\n")
    asked = []
    monkeypatch.setattr(admin, "approve", lambda core, io, what: asked.append(what) or 0)
    a = pending()

    def tick(_):
        if not tick.done:  # things that happen while watching
            tick.done = True
            audit.record("exit", target="lab", job="old1", rc=0)
            old.append("new line\n")
            j = Job(id="new1", target="lab", command="y", started=0)
            j.save()
            j.append("".join(f"l{i}\n" for i in range(watch.TAIL_LINES + 5)))
            (paths.state_dir() / "out" / "gone1.log").write_text("orphan\n")

    tick.done = False
    io = FakeIO()
    assert watch.watch(None, io, ticks=2, sleep=tick) == 0
    assert asked == [f"a:{a.id}"]  # asked once, not every tick
    text = io.text
    assert "already seen" not in text and "lab j:old1 | new line" in text and "exit=0" in text
    assert "lab j:new1 | ... 5 lines (conn read o:new1)" in text and f"l{watch.TAIL_LINES + 4}" in text
    assert "j:gone1 | orphan" in text


def test_watch_without_a_terminal_never_prompts(home, monkeypatch):
    monkeypatch.setattr(admin, "approve", lambda *a: pytest.fail("must not prompt"))
    pending()
    io = FakeIO(tty=False)
    assert watch.watch(None, io, ticks=1, sleep=lambda s: None) == 0
    assert "showing activity only" in io.text


# --- doctor ---------------------------------------------------------------------------------------


@pytest.fixture
def tools(monkeypatch):
    found = {"ssh", "scp", "ssh-keyscan", "op"}
    monkeypatch.setattr(doctor.shutil, "which", lambda name: name if name in found else None)
    monkeypatch.setattr(doctor.ssh, "control_dir", lambda: paths.state_dir())
    return found


def test_doctor_with_no_targets(home, tools):
    io = FakeIO()
    assert doctor.doctor(io) == 0  # a warning, not a failure
    assert io.said[0].startswith("ok   conning ") and "warn no targets in" in io.text


def test_doctor_healthy_setup(home, tools, monkeypatch):
    write_targets(target("lab", hostkey="SHA256:x"))
    ssh.pin_host_keys("lab", [("ssh-ed25519", "SHA256:x", "QUFB")])
    io = FakeIO()
    assert doctor.doctor(io) == 0
    assert all(line.startswith("ok") for line in io.said), io.text


def test_doctor_reports_problems(home, tools, monkeypatch):
    class BrokenKeyring:
        def get_password(self, *a):
            raise RuntimeError("Keychain error -60008")

    monkeypatch.setattr(secrets, "_keyring", lambda: BrokenKeyring())
    tools.discard("op")
    tools.discard("scp")
    monkeypatch.setattr(doctor.ssh, "control_dir", lambda: None)
    write_targets(
        target("lab", auth="password", secret="keychain:conning/lab"),
        target("ci", secret="op://v/i/f", inject={"TOKEN": "env:CONNING_DOCTOR_UNSET"}),
        target("new", status="pending"),
    )
    set_problem("new", "no SSH server answered")
    grant_lease("lab", 5)
    io = FakeIO()
    assert doctor.doctor(io) == 1
    text = io.text
    for expected in (
        "FAIL scp not found",
        "warn SSH connection reuse is off here",
        "FAIL OS keychain not reachable here (RuntimeError: Keychain error -60008)",
        "FAIL a secret uses op://",
        "warn secret env:CONNING_DOCTOR_UNSET is not set",
        "warn new is pending (no SSH server answered)",
        "FAIL lab has no pinned host key",
        "warn lab has a lease",
    ):
        assert expected in text, expected


def test_doctor_keychain_ok_and_socket_error(home, tools, monkeypatch):
    class Keyring:
        def get_password(self, *a):
            return None

    monkeypatch.setattr(secrets, "_keyring", lambda: Keyring())

    def unsafe():
        raise ssh.SSHError("/tmp/conning-0 is not a private directory owned by you")

    monkeypatch.setattr(doctor.ssh, "control_dir", unsafe)
    write_targets(target("lab", auth="password", secret="keychain:conning/lab", status="pending"))
    io = FakeIO()
    assert doctor.doctor(io) == 0
    assert "ok   OS keychain reachable" in io.text and "not a private directory" in io.text


def test_doctor_read_only_config_and_broken_state(home, tools, monkeypatch, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    monkeypatch.setenv("CONNING_STATE", str(blocker / "state"))
    monkeypatch.setattr(doctor.os, "access", lambda path, mode: False)
    paths.targets_file().write_text("[lab]\nhost = 1\n")
    io = FakeIO()
    assert doctor.doctor(io) == 1
    assert "is read-only here" in io.text and "is not writable" in io.text and "FAIL " in io.said[-1]


def test_writable_walks_up_to_an_existing_dir(tmp_path):
    assert doctor._writable(tmp_path / "a" / "b")


# --- approvals in the agent client ----------------------------------------------------------------


class EngineStub:
    """Answers `run` with a pending approval, and `read a:<id>` with a result."""

    def __init__(self, command="systemctl status sshd", asks=("lab",)):
        self.command = command
        self.asks = list(asks)
        self.reads = []
        self.approval = None

    def would_ask(self, target, cmd, argv):
        return self.asks

    def run(self, target, cmd, argv, cwd, wait, timeout, max_bytes, grep):
        if not self.asks:
            return "exit=0 dur=0.1s"
        self.approval = pending(self.command)
        note = f"status=pending_approval id=a:{self.approval.id} targets=lab (not on the allowlist)"
        return "refused  db  (observe)\n" + note

    def read(self, id, wait=0, grep=None, max_bytes=0, **kw):
        self.reads.append((id, wait))
        return "exit=0 dur=0.1s out=o:xy\nactive"


MODES = pytest.mark.parametrize("mode", ["auto", "legacy"])  # protocol 2026-07-28 retries; older asks mid-call


def call_run(srv, answer=None, raise_error=False, capable=True, mode="auto", args=None):
    from mcp import Client

    seen = []

    async def on_elicit(context, params):
        seen.append(params)
        if raise_error:
            raise RuntimeError("client broke")
        return answer

    async def go():
        kw = {"elicitation_callback": on_elicit} if capable else {}
        async with Client(srv, mode=mode, **kw) as client:
            result = await client.call_tool("run", args or {"target": "lab", "cmd": "systemctl status sshd", "wait": 7})
            return result.content[0].text

    return asyncio.run(go()), seen


def answer(action, decision=None):
    from mcp_types import ElicitResult

    return ElicitResult(action=action, content={"decision": decision} if decision else None)


@MODES
def test_client_prompt_allows_always(home, mode):
    write_targets(target("lab"))
    engine = EngineStub()
    text, seen = call_run(server.build_server(engine, approve_in_client=True), answer("accept", "always"), mode=mode)
    assert "systemctl status sshd" in seen[0].message and "'systemctl status ...'" in seen[0].message
    assert seen[0].requested_schema["properties"]["decision"]["enum"] == ["once", "always", "deny"]
    assert text == "refused  db  (observe)\nexit=0 dur=0.1s out=o:xy\nactive"
    assert engine.reads == [(f"a:{engine.approval.id}", 7)]
    assert ("systemctl", "status") in load_targets(paths.targets_file())["lab"].allow
    assert events("approved")[0]["by"] == "client"


def test_client_prompt_for_a_shell_string_with_cwd(home):
    engine = EngineStub("ls | wc -l")
    args = {"target": "lab", "cmd": "ls | wc -l", "cwd": "/srv"}
    text, seen = call_run(server.build_server(engine, approve_in_client=True), answer("accept", "once"), args=args)
    assert "(in /srv)" in seen[0].message and "never remembered" in seen[0].message
    assert text.endswith("active") and Approval.load(engine.approval.id).status == "approved"


@MODES
@pytest.mark.parametrize("action, decision", [("accept", "deny"), ("decline", None)])
def test_client_prompt_denies(home, action, decision, mode):
    engine = EngineStub()
    text, _ = call_run(server.build_server(engine, approve_in_client=True), answer(action, decision), mode=mode)
    assert f"status=denied id=a:{engine.approval.id} (the human declined: systemctl status sshd)" in text
    assert engine.reads == [] and Approval.load(engine.approval.id).status == "denied"


@MODES
def test_client_prompt_cancel_leaves_it_pending(home, mode):
    engine = EngineStub()
    text, _ = call_run(server.build_server(engine, approve_in_client=True), answer("cancel"), mode=mode)
    assert "status=pending_approval" in text and Approval.load(engine.approval.id).status == "pending"


def test_client_prompt_needs_opt_in_and_capability(home):
    engine = EngineStub()
    text, seen = call_run(server.build_server(engine), answer("accept", "once"))
    assert seen == [] and "status=pending_approval" in text
    text, seen = call_run(server.build_server(engine, approve_in_client=True), capable=False)
    assert seen == [] and "status=pending_approval" in text


def test_client_prompt_only_when_the_command_would_wait(home):
    text, seen = call_run(server.build_server(EngineStub(asks=()), approve_in_client=True), answer("accept", "once"))
    assert text == "exit=0 dur=0.1s" and seen == []


def test_client_prompt_skips_engine_errors(home):
    class Broken(EngineStub):
        def would_ask(self, *a):
            raise PermissionError(13, "Permission denied", "/cfg")

    engine = Broken()
    text, seen = call_run(server.build_server(engine, approve_in_client=True), answer("accept", "once"))
    assert seen == [] and "status=pending_approval" in text


def test_would_ask(core):
    write_targets(target("lab", allow=(("df",),)), target("obs", mode="observe"))
    assert core.would_ask("lab,obs", None, ["uname"]) == ["lab"]
    assert core.would_ask("lab", "df -h", None) == []
    assert core.would_ask("nope", None, ["x"]) == []
    paths.targets_file().write_text("[bad\n")
    assert core.would_ask("lab", None, ["x"]) == []


# --- CLI wiring -----------------------------------------------------------------------------------


@pytest.fixture
def wired(monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "_core", lambda: "core")
    monkeypatch.setattr(cli, "_io", lambda: "io")
    for name in ("allow", "deny"):
        monkeypatch.setattr(admin, name, lambda *a, _n=name: seen.append((_n, a)) or 0)
    monkeypatch.setattr(doctor, "doctor", lambda io: seen.append(("doctor", io)) or 0)
    return seen


def test_cli_allow_deny_doctor(wired):
    assert cli.main(["allow", "lab"]) == 0
    assert cli.main(["allow", "tag:x", "systemctl", "status"]) == 0
    assert cli.main(["deny", "lab", "df"]) == 0
    assert cli.main(["doctor"]) == 0
    assert wired == [
        ("allow", ("io", "lab", [])),
        ("allow", ("io", "tag:x", ["systemctl", "status"])),
        ("deny", ("io", "lab", ["df"])),
        ("doctor", "io"),
    ]


def test_cli_watch(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "_core", lambda: "core")
    monkeypatch.setattr(cli, "_io", lambda: "io")
    monkeypatch.setattr(watch, "watch", lambda core, io, **kw: calls.append(kw) or 0)
    assert cli.main(["watch", "--history", "3", "--no-prompt"]) == 0
    assert calls == [{"history": 3, "prompt": False}]

    def interrupted(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(watch, "watch", interrupted)
    assert cli.main(["watch"]) == 0


def test_audit_file_is_json_lines(home):
    audit.record("lease", target="lab", minutes=5)
    line = audit.log_file().read_text().strip()
    assert json.loads(line)["minutes"] == 5


def test_audit_chain_detects_edits_and_deletions(home, tools):
    assert audit.verify() is None
    for minutes in (1, 2, 3):
        audit.record("lease", target="lab", minutes=minutes)
    assert audit.verify() is None and audit.read_from(0)[0][0]["prev"] == audit.GENESIS
    path = audit.log_file()
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[1].replace('"minutes":2', '"minutes":9'), lines[2]]) + "\n")
    assert audit.verify() == 3  # the line after the edited one no longer matches
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert audit.verify() == 2
    path.write_text("junk\n")
    assert audit.verify() == 1
    io = FakeIO()
    doctor.doctor(io)
    assert "was edited or truncated at line 1" in io.text
