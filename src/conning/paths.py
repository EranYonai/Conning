"""Where Conning keeps its files. CONNING_HOME overrides the default config dir."""

import os
from pathlib import Path


def config_dir() -> Path:
    if env := os.environ.get("CONNING_HOME"):
        return Path(env)
    if os.name == "nt":
        return Path(os.environ.get("APPDATA", Path.home())) / "conning"
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "conning"


def targets_file() -> Path:
    return config_dir() / "targets.toml"
