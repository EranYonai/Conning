"""End to end: every command in `conn help`, and the MCP server, against a real OpenSSH server. No mocks.

The target is the throwaway sshd that `tests/e2e/start-sshd.sh` starts (CI's e2e job runs it; see
the script for running it by hand). Every call is a fresh `conn` process, as a human or an agent
would make it. Human-only commands run in a pseudo-terminal and get their answers typed when asked.
`test_every_command_in_help_is_tested_here` fails when a command is added without a test here.
"""

import asyncio
import json
import os
import re
import select
import signal
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

PORT = os.environ.get("CONNING_E2E_PORT")
pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(not PORT, reason="no e2e sshd: run tests/e2e/start-sshd.sh first"),
]
USER = os.environ.get("CONNING_E2E_USER", "")
KEY = os.environ.get("CONNING_E2E_KEY", "")
SSHD = ("--host", "127.0.0.1", "--port", PORT or "", "--user", USER)
REMOTE = f"/tmp/conning-e2e-{uuid.uuid4().hex[:8]}"  # a fresh remote dir per run
PROMPT_ENDS = (b":", b"]")  # "password for ...:", "[y/N]", "[d]eny:"


class Conn:
    def __init__(self, home: Path):
        (home / "home").mkdir(parents=True, exist_ok=True)
        self.home = home
        self.env = {
            **os.environ,
            "HOME": str(home / "home"),  # for ~/.ssh/config (import) and the agent clients' files (install)
            "CONNING_HOME": str(home),
            "CONNING_STATE": str(home / "state"),
            "CONNING_NOTIFY": "0",
            "CONNING_IN_CONTAINER": "0",
            "PYTHON_KEYRING_BACKEND": "keyrings.alt.file.PlaintextKeyring",  # a keychain CI can have
            "XDG_DATA_HOME": str(home / "keyring"),
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

    def terminal(self, *args: str) -> "Terminal":
        return Terminal(self.env, args)

    def human(self, *args: str, answers: str = "") -> str:
        """Like a human at a terminal, typing each line of `answers` when asked."""
        term = self.terminal(*args)
        for line in answers.splitlines(keepends=True):
            term.wait_for_prompt()
            term.send(line)
        return term.finish()


class Terminal:
    """`conn` in a pseudo-terminal that is its controlling terminal, so getpass and prompts work."""

    def __init__(self, env: dict, args: tuple[str, ...]):
        import fcntl
        import pty
        import termios

        def take_terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.fd, side = pty.openpty()
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "conning", *args],
            stdin=side,
            stdout=side,
            stderr=side,
            env=env,
            preexec_fn=take_terminal,
        )
        os.close(side)
        self.out = b""
        self.mark = 0

    def _read(self, wait: float) -> bool:
        """Read what is there; False when nothing came within `wait` seconds."""
        if not select.select([self.fd], [], [], wait)[0]:
            return False
        try:
            chunk = os.read(self.fd, 4096)
        except OSError:  # the terminal closed
            return False
        self.out += chunk
        return bool(chunk)

    def text(self) -> str:
        return self.out.decode(errors="replace").replace("\r\n", "\n")

    def wait_for_prompt(self, seconds: float = 60) -> None:
        for _ in range(int(seconds / 0.2)):
            if not self._read(0.2):
                if self.proc.poll() is not None:
                    return
                if len(self.out) > self.mark and self.out.rstrip(b" ").endswith(PROMPT_ENDS):
                    return
        raise AssertionError(f"no prompt from conn:\n{self.text()}")

    def expect(self, text: str, seconds: float = 60) -> None:
        for _ in range(int(seconds / 0.2)):
            if text in self.text()[self.mark :]:
                return
            self._read(0.2)
        raise AssertionError(f"{text!r} not in:\n{self.text()}")

    def send(self, line: str) -> None:
        os.write(self.fd, line.encode())
        self.mark = len(self.out)

    def finish(self, seconds: float = 120) -> str:
        """Read until conn exits. A shared ssh connection it started may keep the terminal open."""
        for _ in range(int(seconds / 0.2)):
            if not self._read(0.2) and self.proc.poll() is not None:
                break
        else:
            self.proc.kill()
            raise AssertionError(f"conn did not exit:\n{self.text()}")
        os.close(self.fd)
        return self.text()

    def stop(self) -> str:
        self.proc.send_signal(signal.SIGINT)
        return self.finish(30)


def found(pattern: str, text: str) -> str:
    match = re.search(pattern, text)
    assert match, f"{pattern!r} not in:\n{text}"
    return match.group(1)


def add_live(conn: Conn, name: str, *extra: str) -> None:
    conn("targets", "add", name, *SSHD, *extra)
    out = conn.human("approve", name, answers="y\n")
    assert f"{name} is live: linux bash" in out, out


def pending_id(out: str) -> str:
    return found(r"status=pending_approval id=a:(\w+)", out)


@pytest.fixture(scope="module")
def conn(tmp_path_factory):
    c = Conn(tmp_path_factory.mktemp("conning"))
    add_live(c, "lab", "--auth", "key", "--key", KEY)
    add_live(c, "free", "--auth", "key", "--key", KEY, "--mode", "auto")
    assert c("run", "free", "mkdir", "-p", REMOTE).startswith("exit=0")
    return c


# conn targets add / approve / targets test / targets


def test_an_agent_proposes_a_target_and_a_human_approves_it(tmp_path):
    c = Conn(tmp_path)
    assert "saved as pending" in c("targets", "add", "new", *SSHD, "--auth", "key", "--key", KEY)
    assert re.search(r"new\s+linux\s+bash\s+host=127.0.0.1:\d+\s+user=conning-e2e .*mode=pending", c("targets"))
    assert c("run", "new", "uname", "-s").startswith("blocked  new  (target is pending")
    assert "needs a human" in c("approve", "new")
    out = c.human("approve", "new", answers="y\n")
    assert "host key ssh-ed25519" in out and "new is live: linux bash mode=ask" in out
    assert re.search(r"new\s+linux\s+bash\s+host=127.0.0.1:\d+\s+user=conning-e2e .*reach=ok", c("targets", "--check"))
    assert "new: ok, linux bash, host key pinned" in c("targets", "test", "new")


def test_a_human_adds_a_target_and_is_asked_for_what_is_missing(tmp_path):
    c = Conn(tmp_path)
    answers = f"127.0.0.1\n{USER}\nkey\n{KEY}\ny\n"
    out = c.human("targets", "add", "asked", "--port", PORT, "--os", "linux", answers=answers)
    assert "host: " in out and "private key file: " in out and "asked is live: linux bash" in out
    assert c("run", "asked", "whoami").startswith("exit=0")


def test_a_typed_password_goes_to_the_keychain_and_follows_a_rename(tmp_path):
    pytest.importorskip("keyrings.alt")
    c = Conn(tmp_path)
    password = os.environ["CONNING_E2E_PASSWORD"]
    out = c.human("targets", "add", "pw", *SSHD, "--auth", "password", answers=f"{password}\ny\n")
    assert "secret=keychain:conning/pw" in out and "pw is live" in out
    assert "conning-e2e" in c("run", "pw", "whoami")
    assert "renamed pw to pw2" in c.human("targets", "rename", "pw", "pw2")
    assert 'secret = "keychain:conning/pw2"' in (tmp_path / "targets.toml").read_text()
    assert "conning-e2e" in c("run", "pw2", "whoami")
    for where in (tmp_path / "targets.toml", tmp_path / "state"):  # only the keychain holds it
        leaked = subprocess.run(["grep", "-r", password, str(where)], capture_output=True)
        assert leaked.returncode == 1, leaked.stdout


def test_password_login_from_a_secret_reference(tmp_path):
    for name, password in (("pw", os.environ["CONNING_E2E_PASSWORD"]), ("bad", "wrong-password")):
        c = Conn(tmp_path / name)
        c.env["E2E_PW"] = password
        c("targets", "add", name, *SSHD, "--auth", "password", "--secret", "env:E2E_PW")
        c.human("approve", name, answers="y\n")
        out = c("run", name, "whoami")
        assert (out.startswith("exit=0") and "conning-e2e" in out) == (name == "pw"), out


def test_key_login_through_ssh_agent(tmp_path):
    c = Conn(tmp_path)
    agent = subprocess.run(["ssh-agent", "-s"], capture_output=True, text=True, check=True).stdout
    c.env.update(re.findall(r"(SSH_AUTH_SOCK|SSH_AGENT_PID)=([^;]+);", agent))
    try:
        subprocess.run(["ssh-add", "-q", KEY], env=c.env, check=True, capture_output=True)
        add_live(c, "agent", "--auth", "ssh-agent")
        assert "conning-e2e" in c("run", "agent", "whoami")
    finally:
        subprocess.run(["ssh-agent", "-k"], env=c.env, capture_output=True)


def test_like_tags_and_fan_out(tmp_path):
    c = Conn(tmp_path)
    add_live(c, "one", "--auth", "key", "--key", KEY, "--tag", "pool")
    add_live(c, "two", "--like", "one", "--user", USER, "--auth", "key", "--key", KEY)
    assert "tags=pool" in c("targets", "two")  # --like copies the tags
    assert len(c("targets", "tag:pool").splitlines()) == 2
    assert len(c("targets", "one,two").splitlines()) == 2
    out = c("run", "one,two", "uname", "-s")
    assert out.startswith("2 targets: 2 ok, 0 failed") and "one,two  (identical output)" in out
    assert c("run", "tag:pool", "hostname").startswith("2 targets: 2 ok")


def test_retry_a_target_that_could_not_be_reached(tmp_path):
    c = Conn(tmp_path)
    c("targets", "add", "late", "--host", "127.0.0.1", "--port", "1", "--user", USER, "--auth", "key", "--key", KEY)
    assert "nothing listens on 127.0.0.1:1" in c.human("approve", "late", answers="y\n")
    toml = tmp_path / "targets.toml"
    toml.write_text(toml.read_text().replace("port = 1\n", f"port = {PORT}\n"))  # the human fixes it
    assert "already exists (probe it again with conn approve late" in c("targets", "add", "late", *SSHD)
    assert "late is live" in c.human("approve", "late", answers="y\n")


def test_the_target_file_is_fail_closed(tmp_path):
    c = Conn(tmp_path)
    (tmp_path / "targets.toml").write_text('[x]\nhost = "127.0.0.1"\nbogus = 1\n')
    assert "unknown key(s) bogus" in c("targets")


# conn targets import


def test_import_from_ssh_config(tmp_path):
    c = Conn(tmp_path)
    ssh_dir = tmp_path / "home" / ".ssh"
    ssh_dir.mkdir()
    (ssh_dir / "config").write_text(
        f"Host imp1\n  HostName 127.0.0.1\n  Port {PORT}\n  User {USER}\n  IdentityFile {KEY}\n  ForwardAgent yes\n\n"
        f"Host other\n  HostName 127.0.0.1\n"
    )
    out = c("targets", "import", "--match", "imp*")
    assert "imp1: forwardagent in your ssh config; Conning drops it" in out
    assert "imported 1 target(s) as pending: imp1" in out
    assert "imp1 is live" in c.human("approve", "imp1", answers="y\n")
    assert "conning-e2e" in c("run", "imp1", "whoami")


# jump hosts (D49): the sshd is its own bastion, reached again as "localhost" through itself


def close_shared_connection(c: Conn, name: str) -> None:
    conf = c.home / "state" / "ssh" / f"{name}.conf"
    subprocess.run(["ssh", "-F", str(conf), "-O", "exit", "conning-target"], capture_output=True)


def test_a_target_behind_a_jump_host(tmp_path):
    c = Conn(tmp_path)
    add_live(c, "gw", "--auth", "key", "--key", KEY)
    inner = ("--host", "localhost", "--port", PORT, "--user", USER, "--auth", "key", "--key", KEY)
    assert "saved as pending" in c("targets", "add", "inner", *inner, "--jump", "gw")
    out = c.human("approve", "inner", answers="y\n")
    assert f"{USER}@localhost:{PORT}  via gw" in out and "inner is live: linux bash" in out, out
    assert "conning-e2e" in c("run", "inner", "whoami")
    assert re.search(r"inner .*reach=ok", c("targets", "--check"))
    term = c.terminal("ssh", "inner")
    term.send("echo inside-$((2 + 2)); exit\n")
    assert "inside-4" in term.finish() and term.proc.returncode == 0
    blob = tmp_path / "blob.txt"
    blob.write_text("through the bastion")
    assert "sha256 verified" in c("transfer", f"local:{blob}", f"inner:{REMOTE}-jumped.txt")
    assert "inner jump through gw" in c("targets", "rm", "gw")

    known_hosts = tmp_path / "known_hosts"  # the bastion's pinned key no longer matches: no way in
    pinned = known_hosts.read_text()
    other = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp_path / "other")])
    assert other.returncode == 0
    fake = (tmp_path / "other.pub").read_text().split()[1]
    known_hosts.write_text(re.sub(r"^(conning-gw ssh-ed25519) \S+", rf"\1 {fake}", pinned, flags=re.M))
    close_shared_connection(c, "inner")
    close_shared_connection(c, "gw")
    assert "possibly at jump host gw (check it with: conn targets test gw)" in c("run", "inner", "whoami")
    assert "host key does not match" in c("targets", "test", "gw")
    known_hosts.write_text(pinned)
    assert "conning-e2e" in c("run", "inner", "whoami")


@pytest.mark.parametrize("gw_pw, inner_pw", [("right", "right"), ("right", "wrong"), ("wrong", "right")])
def test_each_hop_gets_its_own_password(tmp_path, gw_pw, inner_pw):
    c = Conn(tmp_path)
    password = os.environ["CONNING_E2E_PASSWORD"]
    c.env.update(GW_PW=password, IN_PW=password if inner_pw == "right" else "wrong-2")
    c("targets", "add", "gw", *SSHD, "--auth", "password", "--secret", "env:GW_PW")
    assert "gw is live" in c.human("approve", "gw", answers="y\n")
    c.env["GW_PW"] = password if gw_pw == "right" else "wrong-1"  # changed after gw went live
    inner = ("--host", "localhost", "--port", PORT, "--user", USER, "--jump", "gw")
    c("targets", "add", "inner", *inner, "--auth", "password", "--secret", "env:IN_PW")
    out = c.human("approve", "inner", answers="y\n")
    if gw_pw == "wrong":
        assert "no host key through gw: authentication failed" in out, out
    elif inner_pw == "wrong":
        assert "authentication failed" in out and "no host key" not in out and "inner is live" not in out, out
    else:
        assert "inner is live" in out, out
        assert "conning-e2e" in c("run", "inner", "whoami")
    for leaked in (password, "wrong-1", "wrong-2"):
        found_in = subprocess.run(["grep", "-r", leaked, str(tmp_path / "state")], capture_output=True)
        assert found_in.returncode == 1, found_in.stdout


def test_import_keeps_proxyjump(tmp_path):
    c = Conn(tmp_path)
    ssh_dir = tmp_path / "home" / ".ssh"
    ssh_dir.mkdir()
    (ssh_dir / "config").write_text(
        f"Host bastion\n  HostName 127.0.0.1\n  Port {PORT}\n  User {USER}\n  IdentityFile {KEY}\n\n"
        f"Host behind\n  HostName localhost\n  Port {PORT}\n  User {USER}\n  IdentityFile {KEY}\n"
        "  ProxyJump bastion\n"
    )
    assert "imported 2 target(s) as pending: bastion, behind" in c("targets", "import")
    assert 'jump = "bastion"' in (tmp_path / "targets.toml").read_text()
    assert "jump host bastion is pending" in c.human("approve", "behind", answers="y\n")
    assert "bastion is live" in c.human("approve", "bastion", answers="y\n")
    assert "behind is live" in c.human("approve", "behind", answers="y\n")
    assert "conning-e2e" in c("run", "behind", "whoami")


# conn run / approve / allow / deny, modes


def test_read_only_commands_run_and_others_wait_for_a_human(conn):
    out = conn("run", "lab", "uname", "-s")
    assert out.startswith("exit=0") and "Linux" in out
    approval = pending_id(conn("run", "lab", "touch", f"{REMOTE}-once"))
    assert "exit=0" in conn.human("approve", f"a:{approval}", answers="a\n")
    assert "exit=0" in conn("read", f"a:{approval}")
    assert conn("run", "lab", "lab", "whoami").startswith("error: 'lab' is a target, not a command")


def test_a_human_denies_or_always_allows(conn):
    denied = pending_id(conn("run", "lab", "rm", "-f", f"{REMOTE}-nope"))
    assert f"denied a:{denied}" in conn.human("approve", f"a:{denied}", answers="d\n")
    assert conn("read", f"a:{denied}").startswith(f"status=denied id=a:{denied}")
    always = pending_id(conn("run", "lab", "touch", f"{REMOTE}-always"))
    assert f"always allowing 'touch {REMOTE}-always' on lab" in conn.human("approve", "--always", f"a:{always}")
    assert conn("run", "lab", "touch", f"{REMOTE}-always").startswith("exit=0")  # no question this time


def test_a_human_running_a_command_is_asked_right_there(conn):
    out = conn.human("run", "lab", "touch", f"{REMOTE}-asked", answers="a\n")
    assert "needs approval on lab" in out and "exit=0" in out


def test_a_human_runs_live_in_a_pty(conn):
    script = "tty; printf 'loading\\rdone\\n'; printf 'name: '; read x; echo \"got $x\""
    out = conn.human("run", "-t", "lab", "sh", "-c", script, answers="a\nhandler\n")
    assert "needs approval on lab" in out and "/dev/pts/" in out
    assert "loading\rdone" in out and "got handler" in out
    assert "--tty needs a terminal" in conn("run", "-t", "lab", "tty")


def test_a_human_opens_a_shell(conn):
    term = conn.terminal("ssh", "lab")
    term.send("echo shell-$((6 * 7)); tty; exit 3\n")
    out = term.finish()
    assert "shell-42" in out and "/dev/pts/" in out and term.proc.returncode == 3, out
    assert "conn ssh needs a terminal" in conn("ssh", "lab")


def test_run_options(conn):
    assert conn("run", "--cwd", "/tmp", "lab", "pwd").splitlines()[1] == "/tmp"
    assert "shell syntax always asks" in conn("run", "--shell", "lab", "echo hi | tr a-z A-Z")
    out = conn("run", "--max-bytes", "300", "free", "seq", "1", "1000")
    assert len(out.encode()) <= 300 and "lines omitted" in out
    out = conn("run", "--grep", "^99[0-9]$", "free", "seq", "1", "1000")
    assert out.splitlines()[1:] == [str(n) for n in range(990, 1000)]


def test_allow_and_deny_rules(conn):
    assert "status=pending_approval" in conn("run", "lab", "date")
    conn.human("allow", "lab", "date", answers="y\n")
    assert "'date'" in conn("allow", "lab")  # listing needs no human
    assert conn("run", "lab", "date", "-u").startswith("exit=0")
    conn("deny", "lab", "date")
    assert "status=pending_approval" in conn("run", "lab", "date")
    assert "needs a human" in conn("allow", "lab", "reboot")


def test_auto_mode_runs_anything_and_old_modes_say_how_to_recreate(tmp_path):
    c = Conn(tmp_path)
    add_live(c, "box", "--auth", "key", "--key", KEY)
    assert "status=pending_approval" in c("run", "box", "sh", "-c", "echo hi; echo there")
    toml = tmp_path / "targets.toml"
    toml.write_text(toml.read_text() + 'mode = "auto"\n')
    assert c("run", "box", "sh", "-c", "echo hi; echo there").splitlines()[1:] == ["hi", "there"]
    assert "warn box has mode=auto" in c("doctor")
    toml.write_text(toml.read_text().replace('mode = "auto"', 'mode = "lease"'))
    out = c("targets")
    assert "mode 'lease' is not supported" in out and "conn targets add box --host 127.0.0.1" in out
    assert "--mode auto" in out


# conn read


def test_long_jobs_are_polled_signalled_and_timed_out(conn):
    out = conn("run", "free", "--wait", "0", "sh", "-c", "for i in 1 2 3; do echo tick $i; sleep 1; done")
    job = found(r"job=j:(\w+)", out)
    out = conn("read", f"j:{job}", "--wait", "15")
    assert out.startswith("exit=0") and "tick 3" in out
    for sig, code in (("INT", 130), ("TERM", 143), ("KILL", 137)):
        job = found(r"job=j:(\w+)", conn("run", "free", "--wait", "0", "sleep", "300"))
        assert f"signal={sig} sent" in conn("read", f"j:{job}", "--signal", sig)
        assert conn("read", f"j:{job}", "--wait", "10").startswith(f"exit={code}")
    assert conn("run", "free", "--wait", "1", "sleep", "3").startswith("status=running job=j:")
    assert conn("run", "free", "--timeout", "2", "sleep", "30").startswith("exit=124")


def test_big_output_is_capped_and_paged(conn):
    out = conn("run", "free", "seq", "1", "100000")
    assert len(out.encode()) <= 8192
    saved = found(r"out=o:(\w+)", out)
    assert conn("read", f"o:{saved}", "--range", "500-502").splitlines()[-3:] == ["500", "501", "502"]
    assert conn("read", f"o:{saved}", "--range", "-2").splitlines()[-2:] == ["99999", "100000"]
    assert "99999" in conn("read", f"o:{saved}", "--grep", "^9999[0-9]$")
    assert len(conn("read", f"o:{saved}", "--max-bytes", "200").encode()) <= 200


# conn transfer, and remote files through read


def test_remote_files_and_transfers(conn, tmp_path):
    out = conn("read", "lab:/etc/os-release", "--range", "1-2")
    assert out.startswith("file=lab:/etc/os-release lines=1-2")
    blob = tmp_path / "blob.bin"
    blob.write_bytes(os.urandom(200_000))
    assert "sha256 verified" in conn("transfer", f"local:{blob}", f"free:{REMOTE}/blob.bin")
    back = tmp_path / "back.bin"
    assert "sha256 verified" in conn("transfer", f"free:{REMOTE}/blob.bin", f"local:{back}")
    assert back.read_bytes() == blob.read_bytes()


def test_directory_transfers(conn, tmp_path):
    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "a.txt").write_text("a")
    (tree / "sub" / "b.txt").write_text("b")
    assert conn("transfer", f"local:{tree}", f"free:{REMOTE}/tree").startswith("ok directory")
    assert conn("transfer", f"free:{REMOTE}/tree", f"local:{tmp_path / 'back'}").startswith("ok directory")
    assert (tmp_path / "back" / "sub" / "b.txt").read_text() == "b"


# secrets


def test_injected_secrets_never_reach_the_output(tmp_path):
    c = Conn(tmp_path)
    add_live(c, "inj", "--auth", "key", "--key", KEY, "--mode", "auto")
    toml = tmp_path / "targets.toml"
    toml.write_text(toml.read_text() + 'inject = { DEMO_TOKEN = "env:DEMO_TOKEN" }\n')
    c.env["DEMO_TOKEN"] = "s3cret-demo-token"
    out = c("run", "inj", "sh", "-c", 'echo plain=$DEMO_TOKEN; printf %s "$DEMO_TOKEN" | base64')
    assert out.startswith("exit=0") and "plain=[REDACTED]" in out and "s3cret" not in out
    leaked = subprocess.run(["grep", "-r", "s3cret", str(tmp_path / "state")], capture_output=True)
    assert leaked.returncode == 1, leaked.stdout


# conn targets rename / rm / mode


def test_rename_keeps_the_pinned_key_and_rules(tmp_path):
    c = Conn(tmp_path)
    add_live(c, "old", "--auth", "key", "--key", KEY)
    c.human("allow", "old", "date", answers="y\n")
    assert "renamed old to new" in c.human("targets", "rename", "old", "new")
    assert c("run", "new", "date").startswith("exit=0")  # same pin, same rule, no prompt
    assert "renaming a target needs a human" in c("targets", "rename", "new", "agent-name")


def test_rm(tmp_path):
    c = Conn(tmp_path)
    add_live(c, "gone", "--auth", "key", "--key", KEY)
    assert "removed gone" in c("targets", "rm", "gone")
    assert "error: unknown target(s) gone" in c("run", "gone", "true")


def test_mode_auto_needs_a_human_and_ask_comes_back_from_anywhere(tmp_path):
    c = Conn(tmp_path)
    add_live(c, "m", "--auth", "key", "--key", KEY)
    assert "status=pending_approval" in c("run", "m", "touch", f"{REMOTE}-m")
    assert "turning on mode=auto needs a human" in c("targets", "mode", "m", "auto")
    assert "mode=auto on m" in c.human("targets", "mode", "m", "auto", answers="y\n")
    assert c("targets", "mode", "m").strip() == "m: mode=auto"
    assert c("run", "m", "touch", f"{REMOTE}-m").startswith("exit=0")
    assert "mode=ask on m" in c("targets", "mode", "m", "ask")  # taking trust away needs no terminal
    assert "mode=ask" in c("targets", "m")


# conn watch


def test_watch_shows_activity_and_asks_for_approvals(tmp_path):
    conn = Conn(tmp_path)  # no approvals left over from other tests
    add_live(conn, "lab", "--auth", "key", "--key", KEY)
    quiet = conn.terminal("watch", "--no-prompt", "--history", "0")
    quiet.expect("watching; Ctrl-C to stop")
    conn("run", "lab", "ls", "-d", "/srv")
    quiet.expect("ls -d /srv")
    quiet.expect("| /srv")
    quiet.stop()

    term = conn.terminal("watch", "--history", "0")
    term.expect("watching; Ctrl-C to stop")
    approval = pending_id(conn("run", "lab", "touch", f"{REMOTE}-watched"))
    term.expect(f"a:{approval} on lab")
    term.wait_for_prompt()
    term.send("a\n")
    assert conn("read", f"a:{approval}", "--wait", "15").count("exit=0") == 1
    term.stop()


# conn mcp


def mcp_session(env: dict, work, command=(sys.executable, "-m", "conning", "mcp"), on_elicit=None):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def go():
        server = StdioServerParameters(command=command[0], args=list(command[1:]), env=env)
        async with stdio_client(server) as (r, w), ClientSession(r, w, elicitation_callback=on_elicit) as s:
            await s.initialize()
            return await work(s)

    return asyncio.run(go())


async def call(session, tool: str, **args) -> str:
    return (await session.call_tool(tool, args)).content[0].text


def test_the_mcp_server_gives_the_same_answers(conn):
    async def work(s):
        tools = sorted(t.name for t in (await s.list_tools()).tools)
        return tools, await call(s, "run", target="lab", argv=["uname", "-s"]), await call(s, "targets")

    tools, ran, listed = mcp_session(conn.env, work)
    assert tools == ["read", "run", "targets", "transfer"]
    assert ran.startswith("exit=0") and "Linux" in ran
    assert "lab" in listed and f"host=127.0.0.1:{PORT}" in listed and "keychain" not in listed  # D59


def test_approving_in_the_agent_client(conn):
    from mcp_types import ElicitResult

    asked = []

    async def on_elicit(context, params):
        asked.append(params.message)
        return ElicitResult(action="accept", content={"decision": "once"})

    async def work(s):
        return await call(s, "run", target="lab", argv=["touch", f"{REMOTE}-client"])

    assert mcp_session(conn.env, work, on_elicit=on_elicit).count("exit=0") == 1
    assert f"touch {REMOTE}-client" in asked[0]
    command = (sys.executable, "-m", "conning", "mcp", "serve", "--no-approve-in-client")  # D61: out of band
    approval = pending_id(mcp_session(conn.env, work, command, on_elicit))
    assert len(asked) == 1
    assert "exit=0" in conn.human("approve", f"a:{approval}", answers="a\n")

    async def poll(s):
        return await call(s, "read", id=f"a:{approval}")

    assert "exit=0" in mcp_session(conn.env, poll, command, on_elicit)


def test_mcp_install_for_every_client(conn, tmp_path):
    c = Conn(tmp_path)
    c.env["PATH"] = os.pathsep.join([str(Path(sys.executable).parent), "/usr/bin", "/bin"])  # no real clients
    c.env.pop("XDG_CONFIG_HOME", None)  # CI sets it; opencode's files go under ~/.config without it
    home = tmp_path / "home"
    assert "would write" in c("mcp", "install", "claude", "--dry-run") and not (home / ".claude").exists()
    out = c("mcp", "install", "claude")
    assert "claude is not on PATH; add the server with: claude mcp add" in out
    deny = json.loads((home / ".claude" / "settings.json").read_text())["permissions"]["deny"]
    assert "Bash(ssh *)" in deny and "Bash(conn approve *)" in deny and "Bash(conn targets rename *)" in deny
    assert "Bash(conn targets mode *)" in deny
    assert "name: conning" in (home / ".claude" / "skills" / "conning" / "SKILL.md").read_text()
    assert "nothing to change" in c("mcp", "install", "claude")
    for client in ("codex", "cursor", "opencode", "pi"):
        assert "wrote" in c("mcp", "install", client), client
    assert '["conn", "targets", "rename"]' in (home / ".codex" / "rules" / "conning.rules").read_text()
    for skills in (".codex/skills", ".cursor/skills", ".config/opencode/skills", ".pi/agent/skills"):
        assert (home / skills / "conning" / "SKILL.md").exists(), skills
    entry = json.loads((home / ".cursor" / "mcp.json").read_text())["mcpServers"]["conning"]

    async def work(s):  # the server exactly as a client would start it
        return await call(s, "targets")

    assert "lab" in mcp_session(conn.env, work, (entry["command"], *entry.get("args", [])))


# conn completion


def test_tab_completes_from_the_target(conn, tmp_path):
    assert "conn __complete" in conn("completion", "bash")
    conn.env["SHELL"] = "/bin/bash"
    assert "added to" in conn("completion", "install") and "already on" in conn("completion", "install")
    assert 'eval "$(conn completion bash)"' in (conn.home / "home" / ".bashrc").read_text()
    history = tmp_path / "history"
    history.write_text("systemctl restart nginx\nmysql --password=x\n")
    assert "sha256" in conn("transfer", f"local:{history}", "free:.bash_history")
    assert conn("__complete", "run", "f").split() == ["free"]
    assert conn("__complete", "run", "free", "systemctl", "").split()[0] == "restart"
    assert "--password=x" not in conn("__complete", "run", "free", "mysql", "")
    assert f"{REMOTE}/" in conn("__complete", "run", "free", "ls", REMOTE).split()


# conn doctor / help / --version


def test_doctor(conn):
    out = conn("doctor")
    assert "ok   2 target(s)" in out and "ok   ssh found" in out and "FAIL" not in out, out


def test_help_and_version(conn):
    from conning import __version__

    assert conn("--version").strip() == f"conning {__version__}"
    out = conn("help")
    assert out.startswith("usage: conn") and "Targets (conn targets <verb>):\n  targets add " in out
    readme = (Path(__file__).parents[2] / "README.md").read_text()
    assert conn("help", "--markdown").strip() in readme


def test_every_command_in_help_is_tested_here(conn):
    commands = set(re.findall(r"^conn (targets \w+|\w+)", conn("help", "--markdown"), re.M))
    source = Path(__file__).read_text()
    untested = sorted(c for c in commands if '"' + '", "'.join(c.split()) + '"' not in source)
    assert len(commands) >= 17 and not untested, f"add an e2e test for: {untested}"
