"""`conn run --tty`: one target in a pty, output streamed as it comes, still redacted and still asked
about when it would need approval (D55)."""

import json

import pytest
from conftest import needs_sh, target, write_targets
from test_admin import FakeIO

from conning import admin, audit, cli, paths, remote, ssh
from conning.secrets import REDACTED, Redactor
from conning.targets import load_targets
from conning.transport import SSHTransport


def live(core, *argv, confirm=None, cwd=None, cmd=None):
    out = []
    asked = []

    def ask(t, words, shown):
        asked.append(words)
        return confirm

    rc = core.live("lab", cmd, None if cmd else list(argv), cwd, ask, out.append)
    return rc, "".join(out), asked


def events():
    return [json.loads(x) for x in audit.log_file().read_text().splitlines()]


def test_redactor_holds_back_only_what_could_start_a_secret():
    r = Redactor(["hunter22"])
    assert r.feed("ok hun") == "ok "
    assert r.feed("ter22 done h") == f"{REDACTED} done "
    assert r.feed("i") == "hi"
    assert r.held == ""
    assert Redactor([]).feed("spinner |/-\\") == "spinner |/-\\"


@needs_sh
def test_streams_output_with_env_and_cwd_and_leaves_no_file(core, transport, tmp_path):
    write_targets(target("lab", mode="auto"))
    transport.env["lab"] = {"TOKEN": "s3cr3t-value"}
    rc, out, asked = live(core, cmd='printf "%s in %s\\n" "$TOKEN" "$(pwd)"; exit 3', cwd=str(tmp_path))
    assert rc == 3 and asked == []
    assert out == f"{REDACTED} in {tmp_path}\n"
    assert list((transport.remote_home / ".conning" / "jobs").iterdir()) == []
    run, start, exit_ = [e for e in events() if e["event"] in ("run", "start", "exit")]
    assert run["tty"] and run["decision"] == "run" and start["tty"] and exit_["rc"] == 3


@needs_sh
def test_a_command_that_would_ask_is_put_to_the_human(core, transport):
    write_targets(target("lab"))
    assert live(core, "make", confirm=False) == (1, "", [["make"]])
    assert not [c for c in transport.calls if "live" in c[1]]
    rc, out, asked = live(core, "echo", "hi", confirm=True)
    assert (rc, out, asked) == (0, "hi\n", [["echo", "hi"]])


@needs_sh
def test_when_ssh_fails_the_env_file_is_removed(core, transport):
    write_targets(target("lab", mode="auto"))
    transport.env["lab"] = {"TOKEN": "s3cr3t-value"}
    transport.live = lambda t, command, write: 255
    assert live(core, "true")[0] == 255
    assert list((transport.remote_home / ".conning" / "jobs").iterdir()) == []


@pytest.mark.parametrize(
    ("targets", "selector", "error"),
    [
        ([target("lab"), target("lab2")], "lab,lab2", "error: --tty runs on one target"),
        ([target("lab", os="windows")], "lab", "error: --tty needs a Linux or macOS target; lab is Windows"),
        ([target("lab", status="pending")], "lab", "error: lab is pending; human runs: conn approve lab"),
        ([target("lab")], "nope", "error: unknown target(s) nope (see targets)"),
    ],
)
def test_refusals(core, targets, selector, error):
    write_targets(*targets)
    assert core.live(selector, None, ["ls"], None, lambda *a: True, print) == error


def test_bad_target_file_and_ssh_failures(core, transport):
    paths.targets_file().write_text("[lab]\nbogus = 1\n")
    assert core.live("lab", None, ["ls"], None, lambda *a: True, print).startswith("error: ")
    write_targets(target("lab", mode="auto"))
    transport.canned["sh -s"] = (255, b"nope")
    assert core.live("lab", None, ["ls"], None, lambda *a: True, print) == "error: lab: explained rc=255"
    transport.secret_error = "env:X is not set"
    assert core.live("lab", None, ["ls"], None, lambda *a: True, print) == "error: lab: env:X is not set"


def test_confirm_live_once_always_deny(home):
    write_targets(target("lab"))
    t = load_targets(paths.targets_file())["lab"]
    io = FakeIO("a", "e", "d")
    assert admin.confirm_live(io, t, ["make", "all"], "make all")
    assert admin.confirm_live(io, t, ["make", "all"], "make all")
    assert load_targets(paths.targets_file())["lab"].allow == (("make", "all"),)
    assert not admin.confirm_live(io, t, None, "a | b")
    assert io.said[-2] == "[a]llow once, [d]eny: " and io.said[-1] == "denied"
    assert [e["event"] for e in events() if e["event"] in ("approved", "denied")] == ["approved", "approved", "denied"]


@needs_sh
def test_cli(core, monkeypatch, capsys):
    write_targets(target("lab", mode="auto"))
    monkeypatch.setattr(cli, "_core", lambda: core)
    monkeypatch.setattr(cli, "_io", lambda: FakeIO(tty=False))
    assert cli.main(["run", "-t", "lab", "echo", "hi"]) == 1
    assert "--tty needs a terminal" in capsys.readouterr().out
    monkeypatch.setattr(cli, "_io", lambda: FakeIO(tty=True))
    assert cli.main(["run", "--tty", "lab", "echo", "-n", "hi"]) == 0
    assert capsys.readouterr().out == "hi"
    assert cli.main(["run", "--tty", "--shell", "lab", "exit 4"]) == 4
    assert cli.main(["run", "-t", "tag:none", "true"]) == 1
    assert "no target matches" in capsys.readouterr().out


@needs_sh
def test_ssh_live_swaps_in_a_pty_and_streams():
    conn = ssh.Connection(["sh", "-c", 'echo "$@"', "sh", "-T"], {}, [])
    got = []
    assert ssh.live(conn, "uptime", got.append) == 0
    assert b"".join(got) == b"-tt -- uptime\n"


def test_ssh_transport_live(monkeypatch):
    monkeypatch.setattr(ssh, "connect", lambda t: "conn")
    monkeypatch.setattr(ssh, "live", lambda conn, command, write: (write(b"x"), 7)[1])
    got = []
    assert SSHTransport().live(target("lab"), "c", got.append) == 7 and got == [b"x"]


def test_heredoc_delimiter_is_refused():
    with pytest.raises(ValueError):
        remote.posix_live("abc", "echo CONNING_EOF_abc", cwd=None, env={})
