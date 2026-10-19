"""`conn ssh`: an interactive shell on one live target, for a human at a terminal, audited."""

import json
import os

import pytest
from conftest import target, write_targets
from test_admin import FakeIO

from conning import audit, cli, complete, ssh
from conning.transport import SSHTransport


def test_cli_opens_a_shell_and_audits_it(core, transport, monkeypatch, capsys):
    write_targets(target("lab"), target("p", status="pending"))
    monkeypatch.setattr(cli, "_core", lambda: core)
    monkeypatch.setattr(cli, "_io", lambda: FakeIO(tty=False))
    assert cli.main(["ssh", "lab"]) == 1 and "conn ssh needs a terminal" in capsys.readouterr().out
    monkeypatch.setattr(cli, "_io", lambda: FakeIO(tty=True))
    assert cli.main(["ssh", "lab"]) == 0 and transport.calls == [("lab", "shell", None)]
    entries = [json.loads(x) for x in audit.log_file().read_text().splitlines()]
    assert [(e["event"], e.get("rc")) for e in entries] == [("ssh", None), ("ssh", 0)]
    assert cli.main(["ssh", "p"]) == 1 and "conn approve p" in capsys.readouterr().out
    assert cli.main(["ssh", "nope"]) == 1 and "unknown target nope" in capsys.readouterr().out


def test_ssh_shell_swaps_in_a_tty_and_allows_a_passphrase():
    script = 'test "$*" = "-t -o BatchMode=no conning-target"'
    assert ssh.shell(ssh.Connection(["sh", "-c", script, "sh", "-T", "conning-target"], {}, [])) == 0


@pytest.mark.parametrize("term, sent", [("xterm-ghostty", "xterm-256color"), ("screen", "screen"), (None, "")])
def test_an_unusual_terminal_type_is_sent_as_xterm_256color(term, sent):
    env = {"PATH": os.environ.get("PATH", "")} | ({"TERM": term} if term else {})
    script = f'test "${{TERM:-}}" = "{sent}"'
    assert ssh.shell(ssh.Connection(["sh", "-c", script, "sh", "-T", "conning-target"], env, [])) == 0
    assert env.get("TERM") == term  # the shared connection's env is left alone


def test_ctrl_c_is_left_to_ssh(monkeypatch):
    class Ssh:
        waits = iter([KeyboardInterrupt, 255])

        def __init__(self, argv, env):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            pass

        def wait(self):
            got = next(self.waits)
            if got is KeyboardInterrupt:
                raise got
            return got

    monkeypatch.setattr(ssh.subprocess, "Popen", Ssh)
    assert ssh.shell(ssh.Connection(["ssh", "-T", "conning-target"], {}, [])) == 255


def test_a_connection_error_is_one_line_and_closes_the_audit_entry(core, transport, monkeypatch):
    write_targets(target("lab"))

    def fail(t):
        raise ssh.SSHError("jump host gw is pending")

    monkeypatch.setattr(transport, "shell", fail)
    assert core.shell("lab") == "error: lab: jump host gw is pending"
    entries = [json.loads(x) for x in audit.log_file().read_text().splitlines()]
    assert entries[-1]["rc"] == 255


def test_ssh_transport_shell(monkeypatch):
    monkeypatch.setattr(ssh, "connect", lambda t: "conn")
    monkeypatch.setattr(ssh, "shell", lambda conn: 5 if conn == "conn" else 0)
    assert SSHTransport().shell(target("lab")) == 5


def test_target_names_complete_after_ssh(home):
    write_targets(target("lab"))
    assert complete.complete(["ssh", "l"]) == ["lab"]
