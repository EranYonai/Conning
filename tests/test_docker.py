"""D46: the image runs the server as a non-root user with /conning as its volume, and in a container
the OS keychain is out of reach, so Conning says so instead of failing obscurely.

The build itself is checked by CI, which builds the image and runs `conn doctor` in it; here we keep
the invariants a reader of the Dockerfile would otherwise have to trust.
"""

import importlib.util
from pathlib import Path

import pytest
import test_m2
from conftest import target, write_targets
from test_admin import FakeIO

from conning import doctor, paths, secrets

tools = test_m2.tools  # fixture: the ssh tools are found and the keychain is probed

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = (ROOT / "Dockerfile").read_text()


def test_the_image_runs_unprivileged_with_the_volume_and_the_ssh_client():
    assert "USER " not in DOCKERFILE  # the entrypoint drops root itself, to the volume's owner
    assert "useradd --create-home --uid 1000 conning" in DOCKERFILE
    assert "openssh-client" in DOCKERFILE
    assert "CONNING_HOME=/conning" in DOCKERFILE and "CONNING_STATE=/conning/state" in DOCKERFILE
    assert 'VOLUME ["/conning"]' in DOCKERFILE
    assert 'ENTRYPOINT ["python", "/usr/local/lib/conning-entrypoint.py"]' in DOCKERFILE and 'CMD ["mcp"]' in DOCKERFILE
    assert "uv export --frozen" in DOCKERFILE  # the locked versions CI tested
    assert "CONNING_IN_CONTAINER=1" in DOCKERFILE


def test_in_container_follows_the_env_then_the_runtime_marker(monkeypatch):
    monkeypatch.setenv("CONNING_IN_CONTAINER", "1")
    assert secrets.in_container() is True
    monkeypatch.setenv("CONNING_IN_CONTAINER", "0")
    assert secrets.in_container() is False
    monkeypatch.delenv("CONNING_IN_CONTAINER")
    monkeypatch.setattr(secrets.os.path, "exists", lambda path: path == "/run/.containerenv")
    assert secrets.in_container() is True
    monkeypatch.setattr(secrets.os.path, "exists", lambda path: False)
    assert secrets.in_container() is False


def test_a_keychain_secret_in_a_container_says_what_to_use_instead(monkeypatch):
    monkeypatch.setenv("CONNING_IN_CONTAINER", "1")
    with pytest.raises(secrets.SecretError) as e:
        secrets.resolve("keychain:conning/lab")
    assert "not reachable in a container" in str(e.value) and "op://" in str(e.value)


def test_doctor_in_a_container_names_it_and_fails_a_keychain_secret(home, tools, monkeypatch):
    monkeypatch.setenv("CONNING_IN_CONTAINER", "1")
    write_targets(target("lab", auth="password", secret="keychain:conning/lab"))
    io = FakeIO()
    assert doctor.doctor(io) == 1
    assert "ok   running in a container" in io.text
    assert "FAIL a secret uses keychain:" in io.text
    assert str(paths.config_dir()) in io.text


def _entrypoint():
    spec = importlib.util.spec_from_file_location("conning_entrypoint", ROOT / "docker" / "entrypoint.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Root:
    """Records what the entrypoint does as root instead of doing it."""

    def __init__(self, monkeypatch, ep, tmp_path, *, uid=0, owner=(501, 20), files=()):
        self.did = []
        volume = tmp_path / "conning"
        volume.mkdir()
        for name in files:
            (volume / name).write_text("x")
        passwd = tmp_path / "passwd"
        passwd.write_text("root:x:0:0:root:/root:/bin/bash\nconning:x:1000:1000::/home/conning:/bin/sh\n")
        self.passwd = passwd
        monkeypatch.setattr(ep, "VOLUME", str(volume))
        monkeypatch.setattr(ep, "PASSWD", str(passwd))
        real_stat = ep.os.stat

        def stat(path):
            st = real_stat(path)
            if path != str(volume):
                return st
            return type("St", (), {"st_uid": owner[0], "st_gid": owner[1]})()

        monkeypatch.setattr(ep.os, "stat", stat)
        monkeypatch.setattr(ep.os, "getuid", lambda: uid, raising=False)  # none on Windows
        for name in ("chown", "setgroups", "setgid", "setuid"):
            monkeypatch.setattr(ep.os, name, lambda *a, n=name: self.did.append((n, *a)), raising=False)
        monkeypatch.setattr(ep.os, "execvp", lambda f, argv: self.did.append(("exec", *argv)))
        monkeypatch.setattr(ep.os, "environ", {})
        self.volume = str(volume)


def test_entrypoint_runs_conn_as_the_owner_of_the_volume(monkeypatch, tmp_path):
    ep = _entrypoint()
    root = Root(monkeypatch, ep, tmp_path, owner=(501, 20), files=["targets.toml"])
    ep.main(["mcp"])
    assert root.did == [
        ("chown", ep.HOME, 501, 20),
        ("setgroups", []),
        ("setgid", 20),
        ("setuid", 501),
        ("exec", "conn", "mcp"),
    ]
    assert ep.os.environ["HOME"] == ep.HOME
    assert "conning-host:x:501:20::/home/conning:" in root.passwd.read_text()  # ssh needs a passwd entry
    ep.main(["doctor"])
    assert root.passwd.read_text().count(":501:") == 1  # added once


def test_entrypoint_keeps_the_image_user_for_a_known_uid(monkeypatch, tmp_path):
    ep = _entrypoint()
    root = Root(monkeypatch, ep, tmp_path, owner=(1000, 1000), files=["targets.toml"])
    before = root.passwd.read_text()
    ep.main([])
    assert root.passwd.read_text() == before
    assert ("setuid", 1000) in root.did and root.did[-1] == ("exec", "conn")


def test_entrypoint_claims_an_empty_root_owned_volume(monkeypatch, tmp_path):
    ep = _entrypoint()
    root = Root(monkeypatch, ep, tmp_path, owner=(0, 0))
    ep.main(["mcp"])
    assert root.did[0] == ("chown", root.volume, 1000, 1000)  # Docker created it for a missing host path
    assert ("setuid", 1000) in root.did


def test_entrypoint_leaves_a_root_owned_share_with_files_alone(monkeypatch, tmp_path):
    ep = _entrypoint()
    root = Root(monkeypatch, ep, tmp_path, owner=(0, 0), files=["targets.toml"])
    ep.main(["mcp"])
    assert ("chown", root.volume, 1000, 1000) not in root.did  # Docker Desktop shows everything as root
    assert ("setuid", 1000) in root.did


def test_entrypoint_under_docker_run_user_just_runs_conn(monkeypatch, tmp_path):
    ep = _entrypoint()
    root = Root(monkeypatch, ep, tmp_path, uid=501)
    ep.main(["doctor"])
    assert root.did == [("exec", "conn", "doctor")]
