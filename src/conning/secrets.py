"""Secret references and output redaction.

A target never stores a secret, only a reference to one:

- ``keychain:<service>/<account>``  the OS keychain (macOS Keychain, Windows Credential Manager, Secret Service)
- ``op://<vault>/<item>/<field>``    1Password, through the ``op`` CLI
- ``env:<NAME>``                     an environment variable of the Conning process (CI, tests)

Values are resolved inside Conning at the moment they are needed and never returned by any tool.
"""

import base64
import os
import subprocess
import urllib.parse

KEYCHAIN_SERVICE = "conning"
REDACTED = "[REDACTED]"
NO_KEYCHAIN = (
    "the OS keychain is not reachable in a container (D46); use env: or op://, "
    "or mount your ssh-agent socket and use a key"
)


def in_container() -> bool:
    """True in Conning's own image, and in most other containers. Only changes what we say, not policy."""
    if (value := os.environ.get("CONNING_IN_CONTAINER")) is not None:
        return value not in ("", "0")
    return os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")


class SecretError(RuntimeError):
    pass


def resolve(ref: str) -> str:
    if ref.startswith("env:"):
        value = os.environ.get(ref[4:])
        if value is None:
            raise SecretError(f"secret {ref}: environment variable is not set")
        return value
    if ref.startswith("keychain:"):
        if in_container():
            raise SecretError(f"secret {ref}: {NO_KEYCHAIN}")
        service, _, account = ref[len("keychain:") :].rpartition("/")
        value = _keyring().get_password(service or KEYCHAIN_SERVICE, account)
        if value is None:
            raise SecretError(f"secret {ref}: not found in the OS keychain")
        return value
    if ref.startswith("op://"):
        try:
            done = subprocess.run(["op", "read", "--no-newline", ref], capture_output=True, text=True, timeout=60)
        except FileNotFoundError as e:
            raise SecretError(f"secret {ref}: the 1Password CLI (op) is not installed") from e
        if done.returncode != 0:
            raise SecretError(f"secret {ref}: op read failed: {done.stderr.strip()[:200]}")
        return done.stdout
    raise SecretError(f"secret {ref!r}: unknown reference type (use keychain:, op:// or env:)")


def store_in_keychain(account: str, value: str, service: str = KEYCHAIN_SERVICE) -> str:
    """Store a secret the human typed and return the reference to put in the target file."""
    _keyring().set_password(service, account, value)
    return f"keychain:{service}/{account}"


def _keyring():
    import keyring

    return keyring


def redact(text: str, secrets: list[str]) -> str:
    """Replace every secret, and its base64, URL-encoded and hex forms, with [REDACTED]."""
    for secret in secrets:
        if len(secret) < 4:
            continue
        raw = secret.encode()
        forms = {
            secret,
            base64.b64encode(raw).decode(),
            base64.b64encode(raw).decode().rstrip("="),
            urllib.parse.quote(secret, safe=""),
            raw.hex(),
        }
        for form in sorted(forms, key=len, reverse=True):
            text = text.replace(form, REDACTED)
    return text
