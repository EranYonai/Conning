"""The CLI and the MCP server only translate arguments; these tests pin that wiring with a fake engine."""

import asyncio

import pytest

from conning import admin, cli, server


class FakeCore:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def record(*args, **kw):
            self.calls.append((name, args, kw))
            return "error: nope" if kw.get("cmd") == "fail" else f"{name} ok"

        return record


@pytest.fixture
def fake(monkeypatch):
    core = FakeCore()
    monkeypatch.setattr(cli, "_core", lambda: core)
    monkeypatch.setattr(cli, "_io", lambda: "io")
    return core


def test_agent_commands_reach_the_engine(fake, capsys):
    assert cli.main(["targets", "tag:x", "--check"]) == 0
    assert cli.main(["run", "lab", "--wait", "0", "--", "uname", "-a"]) == 0
    assert cli.main(["run", "lab", "--shell", "--", "make", "|", "tee"]) == 0
    assert cli.main(["read", "j:ab", "--wait", "5", "--signal", "TERM"]) == 0
    assert cli.main(["transfer", "local:a", "lab:/b"]) == 0
    names = [c[0] for c in fake.calls]
    assert names == ["targets", "run", "run", "read", "transfer"]
    assert fake.calls[1][2]["argv"] == ["uname", "-a"] and fake.calls[1][2]["wait"] == 0
    assert fake.calls[2][2]["cmd"] == "make | tee"
    assert fake.calls[3][1] == ("j:ab",) and fake.calls[3][2]["signal"] == "TERM"
    assert "transfer ok" in capsys.readouterr().out


def test_double_dash_is_only_for_run(fake):
    with pytest.raises(SystemExit):
        cli.main(["targets", "--", "x"])
    assert cli.main(["run", "lab", "uname", "--", "-a", "--", "b"]) == 0
    assert fake.calls[-1][2]["argv"] == ["uname", "-a", "--", "b"]


def test_errors_exit_nonzero(fake, capsys):
    assert cli.main(["run", "lab"]) == 1
    assert "give the command after the target" in capsys.readouterr().out
    assert cli.main(["run", "lab", "--shell", "--", "fail"]) == 1


def test_admin_commands_reach_admin(fake, monkeypatch):
    seen = []
    for name in ("add", "approve", "remove", "test", "lease", "import_ssh_config"):
        monkeypatch.setattr(admin, name, lambda *a, _n=name, **k: seen.append((_n, a, k)) or 0)
    assert cli.main(["add", "lab", "--host", "h", "--user", "u", "--tag", "x", "--os", "windows"]) == 0
    assert cli.main(["approve", "a:ab", "--always"]) == 0
    assert cli.main(["rm", "lab"]) == 0
    assert cli.main(["test", "lab"]) == 0
    assert cli.main(["lease", "lab", "--minutes", "5"]) == 0
    assert cli.main(["import", "--match", "lab-*"]) == 0
    assert [s[0] for s in seen] == ["add", "approve", "remove", "test", "lease", "import_ssh_config"]
    assert seen[0][2]["tags"] == ["x"] and seen[0][2]["os_name"] == "windows"
    assert seen[1][2] == {"always": True} and seen[4][1] == ("io", "lab", 5) and seen[5][1] == ("io", "lab-*")


def test_planned_and_help(capsys):
    assert cli.main(["mcp", "install", "claude"]) == 2
    assert "not implemented yet" in capsys.readouterr().err
    assert cli.main([]) == 0
    assert cli.main(["help"]) == 0
    assert "usage: conn" in capsys.readouterr().out
    assert cli.main(["help", "--markdown"]) == 0
    assert capsys.readouterr().out.startswith("```\nconn targets")


def test_help_markdown_restores_columns(monkeypatch):
    monkeypatch.setenv("COLUMNS", "42")
    cli.help_markdown()
    import os

    assert os.environ["COLUMNS"] == "42"


def test_mcp_serve(monkeypatch):
    ran = []

    class Server:
        def run(self, transport):
            ran.append(transport)

    flags = []
    monkeypatch.setattr(server, "build_server", lambda approve_in_client: flags.append(approve_in_client) or Server())
    assert cli.main(["mcp"]) == 0 and cli.main(["mcp", "serve"]) == 0
    assert cli.main(["mcp", "--no-approve-in-client"]) == 0
    assert ran == ["stdio", "stdio", "stdio"] and flags == [True, True, False]


def test_real_core_and_io_factories(home):
    from conning.admin import ConsoleIO
    from conning.core import Core

    assert isinstance(cli._core(), Core) and isinstance(cli._io(), ConsoleIO)


def test_python_dash_m(monkeypatch):
    import runpy

    monkeypatch.setattr("sys.argv", ["conning", "--version"])
    with pytest.raises(SystemExit) as e:
        runpy.run_module("conning", run_name="__main__")
    assert e.value.code == 0


def test_mcp_tools_delegate_to_the_engine():
    core = FakeCore()
    srv = server.build_server(core)

    def call(name, **args):
        result = asyncio.run(srv.call_tool(name, args))
        return result.content[0].text

    assert call("targets", filter="tag:x") == "targets ok"
    assert call("run", target="lab", argv=["uname"]) == "run ok"
    assert call("read", id="j:ab", wait=3) == "read ok"
    assert call("transfer", source="local:a", dest="lab:/b") == "transfer ok"
    assert core.calls[1][1][:3] == ("lab", None, ["uname"])


def test_everything_after_the_target_is_the_remote_command(fake):
    """From Eran's agent: `conn run <target> uname -a` must not need `--`."""
    assert cli.main(["run", "lab", "uname", "-a"]) == 0
    assert fake.calls[-1][2]["argv"] == ["uname", "-a"]
    assert cli.main(["run", "--wait", "0", "--grep", "x", "--shell", "lab", "ls", "-la", "--color"]) == 0
    assert fake.calls[-1][2]["cmd"] == "ls -la --color" and fake.calls[-1][2]["wait"] == 0
    assert cli.main(["run", "lab", "--wait", "5", "--", "make", "-j4"]) == 0  # options after the target, then --
    assert fake.calls[-1][2]["argv"] == ["make", "-j4"] and fake.calls[-1][2]["wait"] == 5
    assert cli.main(["run", "lab", "--wait=0", "--timeout", "9", "sleep", "300", "--wait", "1"]) == 0
    assert fake.calls[-1][2]["argv"] == ["sleep", "300", "--wait", "1"]  # conn's options end at the command
    assert fake.calls[-1][2]["wait"] == 0 and fake.calls[-1][2]["timeout"] == 9


def test_run_without_a_target_is_a_usage_error(fake):
    with pytest.raises(SystemExit):
        cli.main(["run", "--wait", "0"])


def test_file_problems_are_one_error_line(fake, monkeypatch, capsys):
    def denied(*a, **k):
        raise PermissionError(13, "Permission denied", "/cfg/known_hosts")

    monkeypatch.setattr(admin, "remove", denied)
    assert cli.main(["rm", "lab"]) == 1
    assert capsys.readouterr().out == "error: [Errno 13] Permission denied: '/cfg/known_hosts'\n"


def test_mcp_tools_turn_file_problems_into_errors():
    class Broken:
        def targets(self, *a):
            raise PermissionError(13, "Permission denied", "/cfg")

    srv = server.build_server(Broken())
    text = asyncio.run(srv.call_tool("targets", {})).content[0].text
    assert text == "error: [Errno 13] Permission denied: '/cfg'"
