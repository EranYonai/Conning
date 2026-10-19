# Running Conning behind an MCP gateway

For operators who install a pinned version, launch the server themselves and approve its tools by
name (an MCP gateway, a proxy, a managed client). Decisions D60 and D61 in [design.md](design.md).

## Launch

```sh
uvx -q --from conning==0.6.4 conning mcp --no-approve-in-client serve
uvx -q --from conning==0.6.4 conning mcp serve --no-approve-in-client   # the same; either position works
```

The server speaks MCP over stdio and has no daemon, port or network listener. Pin the version, and
install the `conn` CLI the human uses at the same version (`uv tool install conning==0.6.4`).

**Behind a proxy, use `--no-approve-in-client`.** By default a command that needs approval asks the
human through MCP elicitation. A proxy may not forward elicitation, or may advertise it and drop it,
which would leave the call waiting. With the flag, every such call returns at once with
`status=pending_approval id=a:<id>`; the human answers with `conn watch` or `conn approve a:<id>` on
the machine running the server, with the same `CONNING_HOME` and `CONNING_STATE`, and the agent polls
`read a:<id>` for the result. A client that declares url-only elicitation gets the same fallback.

The operator owns the client's MCP config, so add the skill and the agent deny rules without a second
server entry: `conn mcp install <client> --skill-only` (for pi, which has no deny rules, just the skill).

## Flags

| Flag | Values | Default |
|---|---|---|
| `conn mcp [serve]` | `serve` is the default subcommand | serve |
| `--approve-in-client` / `--no-approve-in-client` | before or after `serve` | on |
| `conn mcp install <client>` | `claude`, `codex`, `cursor`, `opencode`, `pi` | |
| `--dry-run` (install) | show what would change | off |
| `--skill-only` (install) | skill and deny rules, no server entry | off |

`conning` and `conn` are the same program.

## Prerequisites

- Python 3.11 or later (uv fetches one if needed).
- An OpenSSH client on `PATH`: `ssh`, `scp` and `ssh-keyscan` (Windows ships `ssh.exe`).
- An OS keychain only for `keychain:` secrets: macOS Keychain, Windows Credential Manager or Secret
  Service on Linux. Containers can't reach one; use `env:`, `op://` or ssh-agent there.
- The 1Password CLI (`op`) only for `op://` secrets.

## Environment variables

Per-user: differs per human or machine. Server: read by `conning mcp serve`; CLI: only by `conn`.

| Variable | Used for | Per-user | Secret | Where |
|---|---|---|---|---|
| `CONNING_HOME` | config dir: targets, pinned host keys | yes | no | server, CLI |
| `CONNING_STATE` | state dir: jobs, approvals, audit log, generated ssh configs | yes | no | server, CLI |
| `XDG_CONFIG_HOME`, `XDG_STATE_HOME` | default config and state dirs (Linux, macOS) | yes | no | server, CLI |
| `APPDATA`, `LOCALAPPDATA` | default config and state dirs (Windows) | yes | no | server, CLI |
| `HOME` / `USERPROFILE`, `TMPDIR` | home folder; private dir for ssh sockets and the askpass helper | yes | no | server, CLI |
| `PATH` | finds `ssh`, `scp`, `ssh-keyscan`, `op`, `notify-send`/`osascript` | yes | no | server, CLI |
| `SSH_AUTH_SOCK`, `DISPLAY` | passed to ssh: the ssh-agent socket; askpass needs a `DISPLAY` (`:0` if unset) | yes | grants key use | server, CLI |
| `<NAME>` of an `env:<NAME>` secret reference | a target's password or injected value | yes | **yes** | server, CLI |
| `CONNING_NOTIFY` | `0` turns off the desktop notification for a pending command | fixed | no | server, CLI |
| `CONNING_IN_CONTAINER` | `1`/`0` overrides container detection (refuses `keychain:`) | fixed | no | server, CLI |
| `PYTHON_KEYRING_BACKEND` | the keyring library's own backend choice | fixed | no | server, CLI |
| `CLAUDE_CONFIG_DIR`, `CODEX_HOME` | where `conn mcp install claude` and `codex` write | yes | no | CLI (install) |
| `SHELL`, `ZDOTDIR` | which rc file `conn completion install` edits | yes | no | CLI (completion) |
| `COLUMNS` | set by `conn help --markdown` for stable wrapping | fixed | no | CLI |
| `CONNING_ASKPASS_VALUES` | internal: Conning hands ssh's askpass helper the passwords; never set it | | **yes** | internal |

## Versions

The target file is fail-closed: unknown keys and bad values are errors. A CLI and a server of
different versions report an error that names the problem rather than misread the file. Still, keep
the `conn` CLI and the pinned server on the same version.

## Tools

The toolset is fixed at four; none returns a secret, adds a live target or changes policy.

| Name | Title | readOnly | destructive | idempotent | openWorld |
|---|---|---|---|---|---|
| `targets` | List targets | true | | | true |
| `run` | Run a command | false | true | | true |
| `read` | Read a job, output, approval or file | false | false | false | true |
| `transfer` | Copy files | false | true | | true |

Only `run` can return `status=pending_approval`; `read a:<id>` reports it and, once approved, starts the
command. `read <target>:<path>` and `transfer` are not gated by command policy. See
[SECURITY.md](../SECURITY.md) for what that means.
