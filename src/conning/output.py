"""Token-lean results: the fact the agent branches on comes first, the bulk stays behind a handle.

A result is a one-line header (`exit=1 dur=4.2s out=o:9f2 (812 lines, 41.0KB; showing 20+60)`)
followed by the head and tail of the output, never more than `max_bytes` in total. A short result
is just `exit=0` and the output: no duration under a second, and no handle when nothing was cut.
"""

DEFAULT_MAX_BYTES = 8192
MAX_BYTES_CEILING = 16384  # the most an agent may ask for in one call (D30)


def clamp_max_bytes(requested: int | None) -> int:
    if not requested or requested <= 0:
        return DEFAULT_MAX_BYTES
    return min(requested, MAX_BYTES_CEILING)


def _size(n: int) -> str:
    return f"{n}B" if n < 1024 else f"{n / 1024:.1f}KB"


def render(
    header: str,
    text: str,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    head: int = 20,
    tail: int = 60,
    handle: str | None = None,
    name_handle: bool = False,
) -> str:
    """Header plus as much of `text` as fits: everything if small, else head + marker + tail."""
    max_bytes = clamp_max_bytes(max_bytes)
    lines = text.splitlines()
    total_bytes = len(text.encode())
    if len(lines) <= head + tail and total_bytes + len(header) + 1 <= max_bytes:
        return f"{header}\n{text}".rstrip("\n") if text else header

    first = min(head, len(lines) - 1)  # the last line always goes to the tail
    head_part, tail_part = lines[:first], lines[max(first, len(lines) - tail) :]
    where = f"read {handle} for the rest" if handle else "output not kept"

    def compose() -> str:
        omitted = len(lines) - len(head_part) - len(tail_part)
        named = f" out={handle}" if name_handle and handle else ""
        info = f"{header}{named} ({len(lines)} lines, {_size(total_bytes)}; showing {len(head_part)}+{len(tail_part)})"
        body = head_part + ([f"… {omitted} lines omitted ({where}) …"] if omitted else []) + tail_part
        return "\n".join([info, *body])

    out = compose()
    while len(out.encode()) > max_bytes and head_part:
        head_part = head_part[:-1]
        out = compose()
    while len(out.encode()) > max_bytes and len(tail_part) > 1:
        tail_part = tail_part[1:]
        out = compose()
    if len(out.encode()) > max_bytes:  # one enormous line: keep its end
        info_len = len(out.encode()) - len(tail_part[-1].encode())
        keep = max(0, max_bytes - info_len - len("…".encode()))
        tail_part = ["…" + tail_part[-1].encode()[-keep:].decode(errors="ignore")] if keep else []
        out = compose()
        out = out.encode()[:max_bytes].decode(errors="ignore")
    return out


def render_fanout(results: dict[str, tuple[int | None, str]], *, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    """Group targets that returned the same exit code and byte-identical output into one entry."""
    groups: dict[tuple[int | None, str], list[str]] = {}
    for name, result in results.items():
        groups.setdefault(result, []).append(name)
    ok = sum(len(names) for (code, _), names in groups.items() if code == 0)
    running = sum(len(names) for (code, _), names in groups.items() if code is None)
    failed = len(results) - ok - running
    parts = [f"{len(results)} targets: {ok} ok, {failed} failed" + (f", {running} running" if running else "")]
    budget = max(256, (clamp_max_bytes(max_bytes) - 128) // max(1, len(groups)))
    for (code, text), names in sorted(groups.items(), key=lambda g: (g[0][0] == 0, g[0][0] or 0)):
        status = "status=running" if code is None else f"exit={code}"
        label = f"{status}  {','.join(names)}" + ("  (identical output)" if len(names) > 1 else "")
        parts.append(render(label, text, max_bytes=budget, head=5, tail=15))
    return "\n".join(parts)
