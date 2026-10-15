# Changelog

## 0.1.0 (unreleased)

- M1: commands run over OpenSSH with a generated per-target config (pinned host key, no forwarding,
  connection reuse) and key, ssh-agent or password auth (keychain, `op://` or `env:` references).
- `run` starts detached jobs on POSIX targets; `read j:<id>` streams new lines, long-polls and sends
  signals; `read o:<id>` pages saved output; `read <target>:<path>` reads remote files.
- `transfer` copies files and directories with scp and checks files by sha256.
- Approvals: commands outside the allowlist wait for `conn approve a:<id>`; leases with `conn lease`.
- `conn add`, `approve`, `import`, `test`, `rm` and `lease` work. Agent-added targets stay pending.
- Secrets and their base64, URL and hex forms are redacted from all output.
- Windows targets run synchronously through PowerShell for now.
- Unit tests with a fake transport; CI gates coverage at 95%.
- `conn run <target> uname -a` passes flags through without `--`; `conn approve a:<id>` prints the result.
- The `max_bytes` ceiling is now 16 KB (was 64 KB).
- Running commands never writes the config dir: job output, approvals and generated ssh configs go to a
  state dir (`XDG_STATE_HOME/conning`, or `CONNING_STATE`). Works with a read-only config, as in agent sandboxes.
- `conn targets` says where it looked when there are none, and why a pending target is pending.
- File and secret problems print one `error:` line (CLI and MCP) instead of a traceback.

## 0.0.1 (unreleased)

- Scaffold: `conn` CLI surface, MCP server with the four agent tools (`targets` works; `run`, `read`,
  `transfer` are stubs for M1), fail-closed target file, output cap with handles, two-word allowlist
  rules, CI, and a PyPI release workflow using Trusted Publishing.
