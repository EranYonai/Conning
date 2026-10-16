"""SSH_ASKPASS helper: ssh runs this to get a password, which Conning passed in the ssh process env.

The env maps each login's host key alias to its password. ssh names the alias in the prompt
("user@conning-lab's password: " or "(user@conning-lab) Password:"), so with jump hosts each hop
gets its own password. A prompt for a login Conning has no password for gets nothing.
"""

import json
import os
import re
import sys


def answer(prompt: str, passwords: dict[str, str]) -> str | None:
    named = re.search(r"@(conning-[A-Za-z0-9._-]+?)(?:'s |\) )", prompt)
    if named:
        return passwords.get(named.group(1))
    return next(iter(passwords.values())) if len(passwords) == 1 else None


def main() -> int:
    value = answer(sys.argv[1] if len(sys.argv) > 1 else "", json.loads(os.environ.get("CONNING_ASKPASS_VALUES", "{}")))
    if value is None:
        return 1
    sys.stdout.write(value + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - ssh runs it as a program
    sys.exit(main())
