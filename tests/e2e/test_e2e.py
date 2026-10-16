"""End to end: the real `conn` and the real MCP server against a real OpenSSH server, no mocks.

The target is the throwaway sshd that `tests/e2e/start-sshd.sh` starts (CI's e2e job runs it; see
the script for running it by hand). Every call is a fresh `conn` process, as a human or an agent
would make it. Human-only commands get a pseudo-terminal and their answers typed into it.
"""

import asyncio
import os
import re
import subprocess
import sys

import pytest

PORT = os.environ.get("CONNING_E2E_PORT")
pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(not PORT, reason="no e2e sshd: run tests/e2e/start-sshd.sh first"),
]
USER = os.environ.get("CONNING_E2E_USER", "")
KEY = os.environ.get("CONNING_E2E_KEY", "")
SSHD = ("--host", "127.0.0.1", "--port", PORT or "", "--user", USER)


class Conn:
    def __init__(self, home):
        self.env = {
            **os.environ,
            "CONNING_HOME": str(home),
            "CONNING_STATE": str(home / "state"),
            "CONNING_NOTIFY": "0",
            "CONNING_IN_CONTAINER": "0",
        }

    def __call__(self, *args: str, timeout: int = 120) -> str:
        """Like an agent: no terminal."""
        done = subprocess.run(
            [sys.executable, "-m", "conning", *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=self.env,
            timeout=timeout,
        )
        return done.stdout + done.stderr

    def human(self, *args: str, answers: str = "") -> str:
        """Like a human at a terminal, typing `answers` (one per line) when asked."""
        import pty

        main, side = pty.openpty()
        proc = subprocess.Popen(
            [sys.executable, "-m", "conning", *args], stdin=side, stdout=side, stderr=side, env=self.env
        )
        os.close(side)
        os.write(main, answers.encode())
        out = b""
        while True:
            try:
                chunk = os.read(main, 4096)
            except OSError:  # the terminal closes when the process exits
                break
            if not chunk:
                break
            out += chunk
        os.close(main)
        proc.wait(timeout=120)
        return out.decode(errors="replace").replace("\r\n", "\n")


def found(pattern: str, text: str) -> str:
    match = re.search(pattern, text)
    assert match, f"{pattern!r} not in:\n{text}"
    return match.group(1)


def add_live(conn: Conn, name: str, *extra: str) -> None:
    conn("add", name, *SSHD, *extra)
    out = conn.human("approve", name, answers="y\n")
    assert f"{name} is live: linux bash" in out, out


@pytest.fixture(scope="module")
def conn(tmp_path_factory):
    c = Conn(tmp_path_factory.mktemp("conning"))
    add_live(c, "lab", "--auth", "key", "--key", KEY)
    add_live(c, "free", "--auth", "key", "--key", KEY)
    assert "lease on free" in c.human("lease", "free", "--minutes", "30", answers="y\n")
    return c


def test_an_agent_proposes_a_target_and_a_human_approves_it(tmp_path):
    c = Conn(tmp_path)
    out = c("add", "new", *SSHD, "--auth", "key", "--key", KEY)
    assert "saved as pending" in out
    assert c("run", "new", "uname", "-s").startswith("blocked  new  (target is pending")
    assert "is live" in c.human("approve", "new", answers="y\n")
    assert re.search(r"new\s+linux\s+bash\s+user=conning-e2e .*reach=ok", c("ls", "--check"))
    assert "new: ok, linux bash, host key pinned" in c("test", "new")


def test_password_login_from_a_secret_reference(tmp_path):
    for name, password in (("pw", os.environ["CONNING_E2E_PASSWORD"]), ("bad", "wrong-password")):
        c = Conn(tmp_path / name)
        c.env["E2E_PW"] = password
        c("add", name, *SSHD, "--auth", "password", "--secret", "env:E2E_PW")
        c.human("approve", name, answers="y\n")
        out = c("run", name, "whoami")
        assert (out.startswith("exit=0") and "conning-e2e" in out) == (name == "pw"), out


def test_read_only_commands_run_and_others_wait_for_a_human(conn):
    out = conn("run", "lab", "uname", "-s")
    assert out.startswith("exit=0") and "Linux" in out
    out = conn("run", "lab", "touch", "/tmp/conning-e2e-approved")
    approval = found(r"status=pending_approval id=a:(\w+)", out)
    assert "exit=0" in conn.human("approve", f"a:{approval}", answers="a\n")
    assert "exit=0" in conn("read", f"a:{approval}")
    assert conn("run", "lab", "lab", "whoami").startswith("error: 'lab' is a target, not a command")


def test_allow_and_deny_rules(conn):
    assert "status=pending_approval" in conn("run", "lab", "date")
    conn.human("allow", "lab", "date", answers="y\n")
    assert conn("run", "lab", "date", "-u").startswith("exit=0")
    conn("deny", "lab", "date")
    assert "status=pending_approval" in conn("run", "lab", "date")


def test_long_jobs_are_polled_signalled_and_timed_out(conn):
    out = conn("run", "free", "--wait", "0", "sh", "-c", "for i in 1 2 3; do echo tick $i; sleep 1; done")
    job = found(r"job=j:(\w+)", out)
    out = conn("read", f"j:{job}", "--wait", "15")
    assert out.startswith("exit=0") and "tick 3" in out
    out = conn("run", "free", "--wait", "0", "sleep", "300")
    job = found(r"job=j:(\w+)", out)
    assert "signal=TERM sent" in conn("read", f"j:{job}", "--signal", "TERM")
    assert conn("read", f"j:{job}", "--wait", "10").startswith("exit=143")
    assert conn("run", "free", "--timeout", "2", "sleep", "30").startswith("exit=124")


def test_big_output_is_capped_and_paged(conn):
    out = conn("run", "free", "seq", "1", "100000")
    assert len(out.encode()) <= 8192 + 512
    saved = found(r"out=o:(\w+)", out)
    assert conn("read", f"o:{saved}", "--range", "500-502").splitlines()[-3:] == ["500", "501", "502"]
    assert "99999" in conn("read", f"o:{saved}", "--grep", "^9999[0-9]$")


def test_remote_files_and_transfers(conn, tmp_path):
    out = conn("read", "lab:/etc/os-release", "--range", "1-2")
    assert out.startswith("file=lab:/etc/os-release lines=1-2")
    blob = tmp_path / "blob.bin"
    blob.write_bytes(os.urandom(200_000))
    assert "sha256 verified" in conn("transfer", f"local:{blob}", "free:/tmp/conning-e2e.bin")
    back = tmp_path / "back.bin"
    assert "sha256 verified" in conn("transfer", "free:/tmp/conning-e2e.bin", f"local:{back}")
    assert back.read_bytes() == blob.read_bytes()


def test_injected_secrets_never_reach_the_output(tmp_path):
    c = Conn(tmp_path)
    add_live(c, "inj", "--auth", "key", "--key", KEY)
    c.human("lease", "inj", "--minutes", "5", answers="y\n")
    toml = tmp_path / "targets.toml"
    toml.write_text(toml.read_text() + 'inject = { DEMO_TOKEN = "env:DEMO_TOKEN" }\n')
    c.env["DEMO_TOKEN"] = "s3cret-demo-token"
    out = c("run", "inj", "sh", "-c", 'echo plain=$DEMO_TOKEN; printf %s "$DEMO_TOKEN" | base64')
    assert out.startswith("exit=0") and "plain=[REDACTED]" in out and "s3cret" not in out
    leaked = subprocess.run(["grep", "-r", "s3cret", str(tmp_path / "state")], capture_output=True)
    assert leaked.returncode == 1, leaked.stdout


def test_rename_keeps_the_pinned_key_and_rules(tmp_path):
    c = Conn(tmp_path)
    add_live(c, "old", "--auth", "key", "--key", KEY)
    c.human("allow", "old", "date", answers="y\n")
    assert "renamed old to new" in c.human("rename", "old", "new")
    assert c("run", "new", "date").startswith("exit=0")  # same pin, same rule, no prompt
    assert "renaming a target needs a human" in c("rename", "new", "agent-name")


def test_the_mcp_server_gives_the_same_answers(conn):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def session():
        server = StdioServerParameters(command=sys.executable, args=["-m", "conning", "mcp"], env=conn.env)
        async with stdio_client(server) as (r, w), ClientSession(r, w) as s:
            await s.initialize()
            tools = sorted(t.name for t in (await s.list_tools()).tools)
            ran = (await s.call_tool("run", {"target": "lab", "argv": ["uname", "-s"]})).content[0].text
            listed = (await s.call_tool("targets", {})).content[0].text
            return tools, ran, listed

    tools, ran, listed = asyncio.run(session())
    assert tools == ["read", "run", "targets", "transfer"]
    assert ran.startswith("exit=0") and "Linux" in ran
    assert "lab" in listed and "127.0.0.1" not in listed  # never the host


def test_doctor_and_rm(conn):
    out = conn("doctor")
    assert "ok   2 target(s)" in out and "FAIL" not in out, out
    add_live(conn, "gone", "--auth", "key", "--key", KEY)
    assert "removed gone" in conn("rm", "gone")
    assert "error: unknown target(s) gone" in conn("run", "gone", "true")
