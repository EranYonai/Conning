import base64
import hashlib
import json
import subprocess
from types import SimpleNamespace

import pytest
from conftest import target

from conning import ssh

KEY = base64.b64encode(b"fake-host-key").decode()


@pytest.fixture
def fake_ssh(monkeypatch, tmp_path):
    monkeypatch.setattr(ssh.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(ssh.tempfile, "gettempdir", lambda: str(tmp_path / "tmp"))
    monkeypatch.setattr(ssh, "SHORT_TMP", tmp_path / "tmp")
    (tmp_path / "tmp").mkdir()


def test_require_ssh(monkeypatch):
    monkeypatch.setattr(ssh.shutil, "which", lambda name: None)
    with pytest.raises(ssh.SSHError, match="not found"):
        ssh.require_ssh()
    monkeypatch.setattr(ssh.shutil, "which", lambda name: "/usr/bin/ssh")
    assert ssh.require_ssh() == "/usr/bin/ssh"


def test_config_pins_host_key_and_disables_forwarding(tmp_path):
    text = ssh.config_text(target(), tmp_path / "kh", tmp_path / "ctl")
    assert "HostKeyAlias conning-lab" in text
    assert "StrictHostKeyChecking yes" in text
    for line in ("ForwardAgent no", "ForwardX11 no", "ClearAllForwardings yes", "PermitLocalCommand no"):
        assert line in text
    assert "BatchMode yes" in text and "ControlPersist 600" in text
    assert "IdentityFile" not in text


def test_config_for_key_and_password_auth(tmp_path):
    key = ssh.config_text(target(auth="key", key="~/id_test"), tmp_path / "kh", None)
    assert "IdentitiesOnly yes" in key and "ControlMaster" not in key
    assert "~" not in key.split("IdentityFile")[1].splitlines()[0]
    pw = ssh.config_text(target(auth="password", secret="env:X"), tmp_path / "kh", None)
    assert "PubkeyAuthentication no" in pw and "BatchMode" not in pw


def test_each_target_gets_its_own_shared_connection(tmp_path):
    def socket(t, known_hosts="kh"):
        text = ssh.config_text(t, tmp_path / known_hosts, tmp_path / "ctl")
        return text.split("ControlPath ")[1].splitlines()[0]

    assert socket(target()) == socket(target())
    assert len(socket(target()).strip('"').rsplit("/", 1)[1]) == 40
    others = {socket(target(name="lab2")), socket(target(auth="key", key="~/k")), socket(target(), "kh2")}
    assert socket(target()) not in others and len(others) == 3


def test_connect_writes_config(home, fake_ssh):
    conn = ssh.connect(target())
    assert conn.argv[:2] == ["/usr/bin/ssh", "-F"] and conn.argv[-2:] == ["-T", ssh.ALIAS]
    assert (ssh.paths.state_dir() / "ssh" / "lab.conf").read_text().startswith("Host conning-target")
    assert not (home / "known_hosts").exists()  # running never writes the config dir
    assert conn.secrets == [] and "CONNING_ASKPASS_VALUES" not in conn.env


def test_connect_with_password_uses_askpass(home, fake_ssh, monkeypatch):
    monkeypatch.setenv("LAB_PW", "s3cret-pw")
    conn = ssh.connect(target(auth="password", secret="env:LAB_PW"))
    assert json.loads(conn.env["CONNING_ASKPASS_VALUES"]) == {"conning-lab": "s3cret-pw"}
    assert conn.env["SSH_ASKPASS_REQUIRE"] == "force"
    helper = conn.env["SSH_ASKPASS"]
    assert "conning.askpass" in open(helper).read()
    assert conn.secrets == ["s3cret-pw"]
    assert "s3cret-pw" not in " ".join(conn.argv)


def test_connect_password_without_secret(home, fake_ssh):
    with pytest.raises(ssh.SSHError, match="without a secret"):
        ssh.connect(target(auth="password"))


def test_windows_host_askpass_and_no_control_master(home, fake_ssh, monkeypatch):
    monkeypatch.setattr(ssh, "IS_WINDOWS_HOST", True)
    assert ssh._askpass_helper().name == "askpass.cmd"
    monkeypatch.setenv("LAB_PW", "pw-value")
    conn = ssh.connect(target(auth="password", secret="env:LAB_PW"))
    conf = (ssh.paths.state_dir() / "ssh" / "lab.conf").read_text()
    assert "ControlMaster" not in conf and "GlobalKnownHostsFile NUL" in conf
    assert conn.env["SSH_ASKPASS"].endswith("askpass.cmd")


def test_run_passes_command_after_double_dash(monkeypatch):
    seen = {}

    def fake_run(argv, **kw):
        seen.update(argv=argv, **kw)
        return SimpleNamespace(returncode=3, stdout=b"out")

    monkeypatch.setattr(ssh.subprocess, "run", fake_run)
    conn = ssh.Connection(["ssh", "-F", "c", "-T", ssh.ALIAS], {"A": "1"}, [])
    assert ssh.run(conn, "uname -a", stdin=b"in") == (3, b"out")
    assert seen["argv"][-2:] == ["--", "uname -a"] and seen["input"] == b"in" and seen["env"] == {"A": "1"}
    ssh.run(conn, "x")
    assert seen["input"] == b""


def test_run_timeout_returns_124(monkeypatch):
    def fake_run(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 1, output=b"partial")

    monkeypatch.setattr(ssh.subprocess, "run", fake_run)
    conn = ssh.Connection(["ssh"], {}, [])
    rc, out = ssh.run(conn, "sleep 9", timeout=1)
    assert rc == 124 and out.startswith(b"partial") and b"timed out" in out


@pytest.mark.parametrize(
    "text, expected",
    [
        (b"@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@", "host key does not match"),
        (b"Host key verification failed.", "host key does not match"),
        (b"tester@x: Permission denied (publickey).", "authentication failed"),
        (b"ssh: connect to host x port 22: Connection refused", "connection refused"),
        (b"ssh: connect to host x port 22: Connection timed out", "host unreachable"),
        (b"No route to host", "host unreachable"),
        (b"first\nkex_exchange_identification: read: reset\n", "kex_exchange_identification: read: reset"),
        (b"", "ssh failed"),
    ],
)
def test_explain_ssh_failure(text, expected):
    assert ssh.explain_ssh_failure(text).startswith(expected)


def test_scan_host_keys(monkeypatch):
    monkeypatch.setattr(ssh.shutil, "which", lambda name: "/usr/bin/ssh-keyscan")
    stdout = f"# 192.0.2.10:22 SSH-2.0-OpenSSH\n192.0.2.10 ssh-ed25519 {KEY}\nbad line\n"
    monkeypatch.setattr(ssh.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout=stdout))
    keys = ssh.scan_host_keys("192.0.2.10", 22)
    assert keys == [("ssh-ed25519", ssh.fingerprint(KEY), KEY)]


def test_scan_host_keys_needs_keyscan(monkeypatch):
    monkeypatch.setattr(ssh.shutil, "which", lambda name: None)
    with pytest.raises(ssh.SSHError, match="ssh-keyscan"):
        ssh.scan_host_keys("192.0.2.10", 22)


def test_fingerprint_matches_openssh_format():
    digest = hashlib.sha256(b"fake-host-key").digest()
    assert ssh.fingerprint(KEY) == "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def test_pin_host_keys_replaces_only_this_target(home):
    (home / "known_hosts").write_text("conning-other ssh-rsa AAA\nconning-lab ssh-rsa OLD\n")
    ssh.pin_host_keys("lab", [("ssh-ed25519", "fp", KEY)])
    lines = (home / "known_hosts").read_text().splitlines()
    assert lines == ["conning-other ssh-rsa AAA", f"conning-lab ssh-ed25519 {KEY}"]
    ssh.pin_host_keys("lab", [])
    assert (home / "known_hosts").read_text().splitlines() == ["conning-other ssh-rsa AAA"]


def test_port_open(monkeypatch):
    class Sock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(ssh.socket, "create_connection", lambda *a, **k: Sock())
    assert ssh.port_open("192.0.2.10", 22)

    def refuse(*a, **k):
        raise OSError("refused")

    monkeypatch.setattr(ssh.socket, "create_connection", refuse)
    assert not ssh.port_open("192.0.2.10", 22)


def test_no_ssh_hint_spots_windows(monkeypatch):
    monkeypatch.setattr(ssh, "port_open", lambda host, port, timeout=3: port in (3389, 5985))
    hint = ssh.no_ssh_hint(target())
    assert "looks like Windows" in hint and "3389, 5985" in hint and "conn add lab --retry" in hint
    monkeypatch.setattr(ssh, "port_open", lambda host, port, timeout=3: False)
    assert "nothing listens" in ssh.no_ssh_hint(target())


def test_runtime_dir_is_private(fake_ssh):
    d = ssh.runtime_dir()
    assert d.is_dir() and d.name.startswith("conning-")


def test_runtime_dir_prefers_short_tmp_over_long_temp_dir(monkeypatch, tmp_path):
    """Seen on macOS: /var/folders/... plus the socket name passed the 104-byte limit."""
    monkeypatch.setattr(ssh, "IS_WINDOWS_HOST", False)
    short = tmp_path / "t"
    short.mkdir()
    monkeypatch.setattr(ssh, "SHORT_TMP", short)
    monkeypatch.setattr(ssh.tempfile, "gettempdir", lambda: str(tmp_path / ("x" * 60)))
    assert ssh.runtime_dir().parent == short
    monkeypatch.setattr(ssh, "SHORT_TMP", tmp_path / "missing")
    (tmp_path / ("x" * 60)).mkdir()
    assert ssh.runtime_dir().parent == tmp_path / ("x" * 60)


def test_control_dir_is_dropped_when_the_socket_path_would_be_too_long(fake_ssh, monkeypatch):
    monkeypatch.setattr(ssh, "IS_WINDOWS_HOST", False)
    fits = len(str(ssh.runtime_dir())) + ssh.CONTROL_SUFFIX
    monkeypatch.setattr(ssh, "SOCKET_PATH_MAX", fits)
    assert ssh.control_dir() == ssh.runtime_dir()
    monkeypatch.setattr(ssh, "SOCKET_PATH_MAX", fits - 1)
    assert ssh.control_dir() is None
    monkeypatch.setattr(ssh, "IS_WINDOWS_HOST", True)
    assert ssh.control_dir() is None


@pytest.mark.skipif(not hasattr(ssh.os, "getuid"), reason="POSIX ownership check")
def test_runtime_dir_refuses_a_shared_dir(fake_ssh):
    d = ssh.runtime_dir()
    d.chmod(0o777)
    with pytest.raises(ssh.SSHError, match="not a private directory"):
        ssh.runtime_dir()


def test_connect_works_with_a_read_only_config_dir(home, fake_ssh):
    """An agent sandbox may mount the config dir read-only; running must not write there."""
    home.chmod(0o500)
    try:
        assert ssh.connect(target()).argv[-1] == ssh.ALIAS
    finally:
        home.chmod(0o700)
