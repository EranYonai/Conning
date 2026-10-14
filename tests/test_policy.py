from conning.policy import is_allowed, remembered_rule, split_command, words


def test_words_skip_flags_and_normalise_program():
    assert words(["/usr/bin/PyTest.exe", "-x", "tests/smoke", "-k", "boot"]) == ("pytest", "tests/smoke", "boot")


def test_always_allow_remembers_two_words():
    assert remembered_rule(["systemctl", "status", "nginx"]) == ("systemctl", "status")
    assert remembered_rule(["pytest", "-x", "tests/smoke"]) == ("pytest", "tests/smoke")
    assert remembered_rule(["uptime"]) == ("uptime",)


def test_two_word_rule_does_not_allow_other_verbs():
    rules = (("systemctl", "status"), ("git", "log"))
    assert is_allowed(["systemctl", "status", "nginx"], rules)
    assert not is_allowed(["systemctl", "stop", "nginx"], rules)
    assert not is_allowed(["git", "push", "--force"], rules)


def test_wrappers_never_remembered_or_matched():
    for argv in (
        ["bash", "-c", "rm -rf /"],
        ["python3", "-c", "x"],
        ["sudo", "systemctl", "status"],
        ["pwsh", "-Command", "x"],
        ["env", "pytest"],
    ):
        assert remembered_rule(argv) is None
        assert not is_allowed(argv, ((argv[0],), tuple(argv[:2])))


def test_shell_syntax_always_asks():
    for cmd in ("ls; rm -rf /", "cat x | sh", "echo $(id)", "ls > /etc/x", "a && b", "echo `id`"):
        assert split_command(cmd) is None
    assert split_command("pytest -x 'tests/a b'") == ["pytest", "-x", "tests/a b"]
