"""SSH_ASKPASS helper: ssh runs this to get the password, which Conning passed in the ssh process env."""

import os
import sys

value = os.environ.get("CONNING_ASKPASS_VALUE")
if value is None:
    sys.exit(1)
sys.stdout.write(value + "\n")
