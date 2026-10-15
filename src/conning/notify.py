"""A desktop notification when a command waits for the human. Best effort, never required.

Set CONNING_NOTIFY=0 to turn it off.
"""

import os
import shutil
import subprocess
import sys

MAX_TEXT = 120


def _clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 1] + "…"


def _argv(title: str, body: str) -> list[str] | None:
    if sys.platform == "darwin" and shutil.which("osascript"):
        script = f"display notification {_applescript(body)} with title {_applescript(title)}"
        return ["osascript", "-e", script]
    if sys.platform.startswith("linux") and shutil.which("notify-send"):
        return ["notify-send", "--app-name=Conning", title, body]
    return None


def _applescript(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def approval_waiting(approval_id: str, targets: list[str], command: str) -> bool:
    """Tell the human a command is waiting. Returns whether a notification was sent."""
    if os.environ.get("CONNING_NOTIFY", "1") == "0":
        return False
    argv = _argv(
        f"Conning: approve on {', '.join(targets)}?",
        f"{_clip(command)}  (conn approve a:{approval_id})",
    )
    if argv is None:
        return False
    try:
        subprocess.run(argv, capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return True
