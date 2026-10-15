"""D46: the image runs the server as a non-root user with /conning as its volume, and in a container
the OS keychain is out of reach, so Conning says so instead of failing obscurely.

The build itself is checked by CI, which builds the image and runs `conn doctor` in it; here we keep
the invariants a reader of the Dockerfile would otherwise have to trust.
"""

from pathlib import Path

import pytest
import test_m2
from conftest import target, write_targets
from test_admin import FakeIO

from conning import doctor, paths, secrets

tools = test_m2.tools  # fixture: the ssh tools are found and the keychain is probed

DOCKERFILE = (Path(__file__).resolve().parent.parent / "Dockerfile").read_text()


def test_the_image_runs_unprivileged_with_the_volume_and_the_ssh_client():
    assert "USER conning" in DOCKERFILE
    assert "openssh-client" in DOCKERFILE
    assert "CONNING_HOME=/conning" in DOCKERFILE and "CONNING_STATE=/conning/state" in DOCKERFILE
    assert 'VOLUME ["/conning"]' in DOCKERFILE
    assert 'ENTRYPOINT ["conn"]' in DOCKERFILE and 'CMD ["mcp"]' in DOCKERFILE
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
