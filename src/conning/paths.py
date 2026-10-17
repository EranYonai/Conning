"""Where Conning keeps its files.

The config dir holds what the human decides: targets and pinned host keys. Running commands only
reads it, so it can be read-only for an agent's sandbox. The state dir holds what running creates: job
output, approval requests, generated ssh configs. CONNING_HOME and CONNING_STATE override them.
"""

import os
from pathlib import Path


def config_dir() -> Path:
    if env := os.environ.get("CONNING_HOME"):
        return Path(env)
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home())) / "conning"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "conning"


def state_dir() -> Path:
    if env := os.environ.get("CONNING_STATE"):
        return Path(env)
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / "conning" / "state"
    return Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state")) / "conning"


def targets_file() -> Path:
    return config_dir() / "targets.toml"
