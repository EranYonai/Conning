"""`conn run` at a terminal asks right there when a command needs approval (D40), and a target name
typed where the command goes is caught instead of being run as a program."""

import json

from conftest import needs_sh, target, write_targets
from test_admin import FakeIO

from conning import admin, audit, cli, notify, paths
from conning.state import pending_approvals
from conning.targets import load_targets


def run_here(core, io, *argv, wait=5):
    result = core.run("lab", argv=list(argv), wait=wait)
    return admin.run_here(core, io, result, wait=wait, max_bytes=8192, grep=None)


def test_a_target_name_in_the_command_is_caught(core):
    write_targets(target("lab"), target("lab-lin1"))
    out = core.run("lab", argv=["lab-lin1", "cortest", "status"])
    assert out == (
        "error: 'lab-lin1' is a target, not a command; to run on several targets, "
        "join them with commas: lab,lab-lin1 <command>"
    )
    assert pending_approvals() == []


@needs_sh
def test_once_runs_it_right_here(core):
    write_targets(target("lab"))
    io = FakeIO("a")
    assert run_here(core, io, "echo", "hi") == 0
    assert io.said[0] == "needs approval on lab: echo hi"
    assert io.said[1].startswith("[a]llow once, [e] always allow 'echo hi', [d]eny")
    assert io.said[2].startswith("exit=0") and "hi" in io.said[2]
    assert not any("pending_approval" in s or "read a:" in s for s in io.said)


@needs_sh
def test_always_remembers_the_rule(core):
    write_targets(target("lab"))
    io = FakeIO("e")
    assert run_here(core, io, "echo", "x") == 0
    assert io.said[2] == "always allowing 'echo x' on lab"
    assert ("echo", "x") in load_targets(paths.targets_file())["lab"].allow


def test_deny_exits_nonzero_and_runs_nothing(core, transport):
    write_targets(target("lab"))
    io = FakeIO("d")
    assert run_here(core, io, "make", "test") == 1
    assert io.said[-1].startswith("denied a:")
    assert transport.calls == []


def test_without_a_terminal_the_agent_gets_the_id(core):
    write_targets(target("lab"))
    io = FakeIO(tty=False)
    assert run_here(core, io, "make") == 0
    assert io.said[0].startswith("status=pending_approval id=a:")


@needs_sh
def test_fan_out_prints_what_ran_then_asks(core):
    write_targets(target("lab"), target("lab2", allow=(("echo",),)))
    io = FakeIO("a")
    result = core.run("lab,lab2", argv=["echo", "fan"], wait=5)
    assert admin.run_here(core, io, result, wait=5, max_bytes=8192, grep=None) == 0
    assert io.said[0].startswith("exit=0") and "fan" in io.said[0]  # lab2 ran: its name is on the allowlist
    assert io.said[1] == "needs approval on lab: echo fan"


def test_cli_asks_at_a_terminal_without_a_pop_up(core, monkeypatch, capsys):
    write_targets(target("lab"))
    io = FakeIO("d")
    seen = []
    monkeypatch.setattr(cli, "_core", lambda: core)
    monkeypatch.setattr(cli, "_io", lambda: io)
    monkeypatch.setattr(notify, "approval_waiting", lambda *a: seen.append(a))
    assert cli.main(["run", "lab", "make"]) == 1
    assert seen == [] and io.said[-1].startswith("denied a:")
    assert cli.main(["run", "lab-lin9"]) == 1
    assert "conn run lab-lin9 uname -a" in capsys.readouterr().out
    lines = [json.loads(x) for x in audit.log_file().read_text().splitlines()]
    assert [e["event"] for e in lines][-1] == "denied"
