import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import target

from conning import secrets, ssh, transport
from conning.secrets import REDACTED, SecretError


class FakeKeyring:
    def __init__(self):
        self.store = {}

    def get_password(self, service, account):
        return self.store.get((service, account))

    def set_password(self, service, account, value):
        self.store[(service, account)] = value


@pytest.fixture
def keyring(monkeypatch):
    fake = FakeKeyring()
    monkeypatch.setattr(secrets, "_keyring", lambda: fake)
    return fake


# --- secrets ---------------------------------------------------------------------------------


def test_env_reference(monkeypatch):
    monkeypatch.setenv("CONNING_T", "v1")
    assert secrets.resolve("env:CONNING_T") == "v1"
    monkeypatch.delenv("CONNING_T")
    with pytest.raises(SecretError, match="not set"):
        secrets.resolve("env:CONNING_T")


def test_keychain_roundtrip(keyring):
    ref = secrets.store_in_keychain("lab", "pw")
    assert ref == "keychain:conning/lab"
    assert secrets.resolve(ref) == "pw"
    keyring.store[("conning", "bare")] = "x"
    assert secrets.resolve("keychain:bare") == "x"  # no service: the default one
    with pytest.raises(SecretError, match="not found"):
        secrets.resolve("keychain:conning/missing")


def test_op_reference(monkeypatch):
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout="from-op", stderr="")

    monkeypatch.setattr(secrets.subprocess, "run", fake_run)
    assert secrets.resolve("op://vault/item/password") == "from-op"
    assert calls == [["op", "read", "--no-newline", "op://vault/item/password"]]

    monkeypatch.setattr(
        secrets.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="not signed in\n")
    )
    with pytest.raises(SecretError, match="not signed in"):
        secrets.resolve("op://v/i/f")

    def missing(*a, **k):
        raise FileNotFoundError("op")

    monkeypatch.setattr(secrets.subprocess, "run", missing)
    with pytest.raises(SecretError, match="not installed"):
        secrets.resolve("op://v/i/f")


def test_unknown_reference():
    with pytest.raises(SecretError, match="unknown reference"):
        secrets.resolve("plain-password")


def test_real_keyring_module_is_loaded_lazily():
    assert secrets._keyring().__name__ == "keyring"


def test_redact_all_forms():
    import base64
    import urllib.parse

    s = "p@ss/word+1"
    text = " ".join([s, base64.b64encode(s.encode()).decode(), urllib.parse.quote(s, safe=""), s.encode().hex()])
    assert secrets.redact(text, [s, "ab"]) == " ".join([REDACTED] * 4)  # "ab" is too short to redact


def test_askpass_prints_value(monkeypatch):
    env = {**os.environ, "CONNING_ASKPASS_VALUE": "pw"}
    done = subprocess.run([sys.executable, "-m", "conning.askpass"], env=env, capture_output=True, text=True)
    assert done.returncode == 0 and done.stdout == "pw\n"
    env.pop("CONNING_ASKPASS_VALUE")
    assert subprocess.run([sys.executable, "-m", "conning.askpass"], env=env).returncode == 1


def test_askpass_in_process(monkeypatch, capsys):
    import importlib

    monkeypatch.setenv("CONNING_ASKPASS_VALUE", "inproc")
    sys.modules.pop("conning.askpass", None)
    importlib.import_module("conning.askpass")
    assert capsys.readouterr().out == "inproc\n"
    monkeypatch.delenv("CONNING_ASKPASS_VALUE")
    sys.modules.pop("conning.askpass", None)
    with pytest.raises(SystemExit):
        importlib.import_module("conning.askpass")
    sys.modules.pop("conning.askpass", None)


# --- SSHTransport ------------------------------------------------------------------------------


@pytest.fixture
def connected(monkeypatch):
    made = []

    def fake_connect(t):
        made.append(t.name)
        return ssh.Connection(t, ["/usr/bin/ssh", "-F", "/cfg/lab.conf", "-T", ssh.ALIAS], {"E": "1"}, ["pw-1"])

    monkeypatch.setattr(ssh, "connect", fake_connect)
    return made


def test_exec_reuses_one_connection(connected, monkeypatch):
    monkeypatch.setattr(ssh, "run", lambda conn, cmd, stdin=None, timeout=60: (0, cmd.encode()))
    tr = transport.SSHTransport()
    assert tr.exec(target(), "uname") == (0, b"uname")
    tr.exec(target(), "id")
    assert connected == ["lab"]


def test_copy_uses_scp_with_generated_config(connected, monkeypatch):
    seen = []
    monkeypatch.setattr(transport.shutil, "which", lambda name: "/usr/bin/scp")

    def fake_run(argv, **kw):
        seen.append(argv)
        return SimpleNamespace(returncode=0, stdout=b"")

    monkeypatch.setattr(transport.subprocess, "run", fake_run)
    tr = transport.SSHTransport()
    assert tr.copy(target(), Path("/l/f"), "/r/f", upload=True) == (0, b"")
    assert seen[-1] == ["/usr/bin/scp", "-F", "/cfg/lab.conf", "-r", "-q", str(Path("/l/f")), f"{ssh.ALIAS}:/r/f"]
    tr.copy(target(), Path("/l/f"), "/r/f", upload=False)
    assert seen[-1][-2:] == [f"{ssh.ALIAS}:/r/f", str(Path("/l/f"))]


def test_copy_needs_scp(monkeypatch):
    monkeypatch.setattr(transport.shutil, "which", lambda name: None)
    with pytest.raises(ssh.SSHError, match="scp"):
        transport.SSHTransport().copy(target(), Path("a"), "b", upload=True)


def test_inject_env_and_secrets(connected, monkeypatch):
    monkeypatch.setenv("TOK", "tok-value")
    tr = transport.SSHTransport()
    t = target(inject={"TOKEN": "env:TOK"})
    assert tr.inject_env(t) == {"TOKEN": "tok-value"}
    assert tr.secrets(t) == ["tok-value"]
    assert tr.secrets(target("lab2", auth="password", secret="env:TOK")) == ["pw-1"]


def test_explain(monkeypatch):
    tr = transport.SSHTransport()
    assert tr.is_ssh_failure(255, b"") and not tr.is_ssh_failure(1, b"")
    assert tr.explain(target(), 255, b"Permission denied").startswith("authentication failed")
    monkeypatch.setattr(ssh, "no_ssh_hint", lambda t: "hint")
    assert tr.explain(target(), 255, b"Connection refused") == "hint"
    assert tr.explain(target(), 2, b"a\nlast\n") == "exit=2: last"
    assert tr.explain(target(), 2, b"") == "exit=2: no output"
