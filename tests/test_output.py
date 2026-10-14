from conning.output import MAX_BYTES_CEILING, clamp_max_bytes, render, render_fanout


def test_small_output_is_returned_whole():
    assert render("exit=0 dur=0.1s", "ok\n") == "exit=0 dur=0.1s\nok"


def test_long_output_keeps_head_and_tail_with_handle():
    text = "\n".join(f"line {i}" for i in range(1000))
    out = render("exit=1 dur=4.2s out=o:9f2", text, head=20, tail=60, handle="o:9f2")
    lines = out.splitlines()
    assert lines[0].startswith("exit=1 dur=4.2s out=o:9f2 (1000 lines")
    assert lines[1] == "line 0" and lines[-1] == "line 999"
    assert "920 lines omitted (read o:9f2 for the rest)" in out


def test_never_exceeds_max_bytes():
    text = "\n".join("x" * 300 for _ in range(500))
    for cap in (512, 2048, 8192):
        assert len(render("exit=0", text, max_bytes=cap).encode()) <= cap
    assert len(render("exit=0", "y" * 100_000, max_bytes=1024).encode()) <= 1024


def test_max_bytes_is_clamped():
    assert clamp_max_bytes(None) == 8192
    assert clamp_max_bytes(10**9) == MAX_BYTES_CEILING


def test_fanout_collapses_identical_output():
    out = render_fanout({"a": (0, "OK"), "b": (0, "OK"), "c": (2, "No space left on device")})
    assert out.splitlines()[0] == "3 targets: 2 ok, 1 failed"
    assert "exit=0  a,b  (identical output)" in out
    assert out.index("exit=2  c") < out.index("exit=0  a,b")  # failures first
