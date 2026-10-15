"""Start `conn` in the image as the owner of /conning (D46).

The human approves on the host against the same folder, so both sides write approvals and job output
there. Running as the folder's owner keeps those files the human's on the host, whatever their uid.
Only this script runs as root; it drops to that user before `conn` starts. ssh refuses a uid with no
passwd entry, so one is added when the owner is new to the image.
"""

import os
import sys

VOLUME = "/conning"
HOME = "/home/conning"
PASSWD = "/etc/passwd"
DEFAULT = 1000  # the image's own `conning` user


def owner(volume: str) -> tuple[int, int]:
    st = os.stat(volume)
    if st.st_uid != 0:
        return st.st_uid, st.st_gid
    # Root-owned: a folder Docker just created for a missing host path (claim it), or a file share
    # that reports root for everything and lets any uid write (Docker Desktop).
    if not os.listdir(volume):
        os.chown(volume, DEFAULT, DEFAULT)
    return DEFAULT, DEFAULT


def ensure_user(uid: int, gid: int) -> None:
    with open(PASSWD, encoding="utf-8") as f:
        if any(line.split(":")[2:3] == [str(uid)] for line in f):
            return
    with open(PASSWD, "a", encoding="utf-8") as f:
        f.write(f"conning-host:x:{uid}:{gid}::{HOME}:/usr/sbin/nologin\n")


def main(argv: list[str]) -> None:
    if os.getuid() == 0:
        uid, gid = owner(VOLUME)
        ensure_user(uid, gid)
        os.chown(HOME, uid, gid)
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        os.environ["HOME"] = HOME
    os.execvp("conn", ["conn", *argv])


if __name__ == "__main__":
    main(sys.argv[1:])
