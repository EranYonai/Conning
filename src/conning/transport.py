"""How the engine reaches a target. `SSHTransport` is the real one; tests swap in a fake."""

import shutil
import subprocess
import threading
from pathlib import Path
from typing import Protocol

from conning import secrets, ssh
from conning.targets import Target


class Transport(Protocol):
    def exec(
        self, t: Target, command: str, *, stdin: bytes | None = None, timeout: float = 60
    ) -> tuple[int, bytes]: ...

    def copy(self, t: Target, local: Path, remote_path: str, *, upload: bool) -> tuple[int, bytes]: ...

    def inject_env(self, t: Target) -> dict[str, str]: ...

    def secrets(self, t: Target) -> list[str]: ...

    def explain(self, t: Target, rc: int, output: bytes) -> str: ...


class SSHTransport:
    def __init__(self):
        self._conns: dict[str, ssh.Connection] = {}
        self._env: dict[str, dict[str, str]] = {}
        self._lock = threading.Lock()

    def _conn(self, t: Target) -> ssh.Connection:
        with self._lock:
            if t.name not in self._conns:
                self._conns[t.name] = ssh.connect(t)
            return self._conns[t.name]

    def exec(self, t: Target, command: str, *, stdin: bytes | None = None, timeout: float = 60) -> tuple[int, bytes]:
        return ssh.run(self._conn(t), command, stdin=stdin, timeout=timeout)

    def copy(self, t: Target, local: Path, remote_path: str, *, upload: bool) -> tuple[int, bytes]:
        scp = shutil.which("scp")
        if not scp:
            raise ssh.SSHError("scp not found on this machine")
        conn = self._conn(t)
        conf = conn.argv[conn.argv.index("-F") + 1]
        remote_spec = f"{ssh.ALIAS}:{remote_path}"
        pair = [str(local), remote_spec] if upload else [remote_spec, str(local)]
        done = subprocess.run(
            [scp, "-F", conf, "-r", "-q", *pair], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=conn.env
        )
        return done.returncode, done.stdout

    def inject_env(self, t: Target) -> dict[str, str]:
        with self._lock:
            if t.name not in self._env:
                self._env[t.name] = {k: secrets.resolve(ref) for k, ref in t.inject.items()}
            return self._env[t.name]

    def secrets(self, t: Target) -> list[str]:
        values = list(self.inject_env(t).values())
        if t.auth == "password" or t.jump:  # a jump host may log in with a password too
            values += self._conn(t).secrets
        return values

    def explain(self, t: Target, rc: int, output: bytes) -> str:
        if rc == 255:
            reason = ssh.explain_ssh_failure(output)
            if reason.startswith("connection refused"):
                return ssh.no_ssh_hint(t)
            if reason == "ssh failed" and t.jump:  # ssh hides a jump host's own errors behind a shared connection
                return f"ssh failed, possibly at jump host {t.jump} (check it with: conn targets test {t.jump})"
            return reason
        text = output.decode(errors="replace").strip()
        return f"exit={rc}: {text.splitlines()[-1] if text else 'no output'}"
