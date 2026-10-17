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


def move_in_keychain(ref: str, account: str) -> str:
    """Copy the secret behind a keychain reference to another account; return the new reference.
    The caller deletes the old item (`forget`) once nothing points at it."""
    value = resolve(ref)
    service = ref[len("keychain:") :].rpartition("/")[0] or KEYCHAIN_SERVICE
    return store_in_keychain(account, value, service)


def forget(ref: str) -> None:
    service, _, account = ref[len("keychain:") :].rpartition("/")
    _keyring().delete_password(service or KEYCHAIN_SERVICE, account)


def _keyring():
    import keyring

    return keyring


def _forms(secrets: list[str]) -> list[str]:
    """Every secret and its base64, URL-encoded and hex forms, longest first."""
    forms = set()
    for secret in secrets:
        if len(secret) < 4:
            continue
        raw = secret.encode()
        b64 = base64.b64encode(raw).decode()
        forms |= {secret, b64, b64.rstrip("="), urllib.parse.quote(secret, safe=""), raw.hex()}
    return sorted(forms, key=len, reverse=True)


def redact(text: str, secrets: list[str]) -> str:
    """Replace every secret, and its base64, URL-encoded and hex forms, with [REDACTED]."""
    for form in _forms(secrets):
        text = text.replace(form, REDACTED)
    return text


class Redactor:
    """`redact` for output that arrives in pieces: it holds back only a tail that could start a secret."""

    def __init__(self, secrets: list[str]):
        self.forms = _forms(secrets)
        self.held = ""

    def feed(self, text: str) -> str:
        text = self.held + text
        for form in self.forms:
            text = text.replace(form, REDACTED)
        keep = max((k for f in self.forms for k in range(1, len(f)) if text.endswith(f[:k])), default=0)
        self.held = text[len(text) - keep :]
        return text[: len(text) - keep]
