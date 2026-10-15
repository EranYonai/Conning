"""Shared fixtures. `LocalTransport` stands in for SSH: it runs the exact scripts Conning would send
to a target with the local `sh`, against a throwaway $HOME, so job handling is tested for real
without a server. PowerShell scripts run the same way with a local `pwsh` when there is one (GitHub's
Linux, macOS and Windows runners all have it); otherwise those tests are skipped.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conning.targets import Target, save_targets

needs_sh = pytest.mark.skipif(sys.platform == "win32" or not shutil.which("sh"), reason="needs a POSIX sh")
needs_pwsh = pytest.mark.skipif(not shutil.which("pwsh"), reason="needs PowerShell 7 (pwsh)")


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    """Job output and approvals never land in the real state dir."""
    monkeypatch.setenv("CONNING_STATE", str(tmp_path / "conning-state"))
    monkeypatch.setenv("CONNING_NOTIFY", "0")  # no desktop pop-ups from test runs


@pytest.fixture
def home(tmp_path, monkeypatch):
    path = tmp_path / "conning-home"
    path.mkdir()
    monkeypatch.setenv("CONNING_HOME", str(path))
    return path


def write_targets(*targets: Target) -> None:
    from conning import paths

    save_targets(paths.targets_file(), {t.name: t for t in targets})


def target(name="lab", **kw) -> Target:
    kw.setdefault("host", "192.0.2.10")
    kw.setdefault("user", "tester")
    return Target(name=name, **kw)


class LocalTransport:
    def __init__(self, remote_home: Path):
        self.remote_home = remote_home
        self.calls: list[tuple[str, str, bytes | None]] = []
        self.canned: dict[str, tuple[int, bytes]] = {}  # command prefix -> answer
        self.env: dict[str, dict[str, str]] = {}
        self.raise_on: str | None = None
        self.copy_result: tuple[int, bytes] | None = None
        self.secret_error: str | None = None  # make secrets() fail, like an unset env: reference

    def exec(self, t, command, *, stdin=None, timeout=60):
        self.calls.append((t.name, command, stdin))
        if self.raise_on and self.raise_on in command:
            from conning.ssh import SSHError

            raise SSHError("boom")
        for prefix, answer in self.canned.items():
            if command.startswith(prefix):
                return answer
        env = {**os.environ, "HOME": str(self.remote_home), "USERPROFILE": str(self.remote_home)}
        if command.startswith(("pwsh ", "powershell ")):
            argv = [shutil.which("pwsh") or "pwsh", *command.split()[1:]]
        else:
            argv = ["sh", "-s"] if command == "sh -s" else ["sh", "-c", command]
        done = subprocess.run(argv, input=stdin or b"", capture_output=True, env=env, timeout=timeout)
        return done.returncode, done.stdout + done.stderr

    def copy(self, t, local, remote_path, *, upload):
        if self.copy_result is not None:
            return self.copy_result
        src, dst = (Path(local), Path(remote_path)) if upload else (Path(remote_path), Path(local))
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            shutil.copyfile(src, dst)
        return 0, b""

    def inject_env(self, t):
        return self.env.get(t.name, {})

    def secrets(self, t):
        if self.secret_error:
            from conning.secrets import SecretError

            raise SecretError(self.secret_error)
        return list(self.inject_env(t).values())

    def explain(self, t, rc, output):
        return f"explained rc={rc}"


@pytest.fixture
def transport(tmp_path):
    remote_home = tmp_path / "remote-home"
    remote_home.mkdir()
    return LocalTransport(remote_home)


@pytest.fixture
def core(home, transport):
    from conning.core import Core

    return Core(transport=transport, poll_interval=0.05)
