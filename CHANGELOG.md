# Changelog

## 0.2.0 (unreleased)

- Approve commands where you are: in the agent client (MCP elicitation, both protocol versions; on by
  default, `conn mcp --no-approve-in-client` turns it off), in `conn watch`, or with `conn approve`. A desktop notification
  says when a command is waiting (`CONNING_NOTIFY=0` turns it off).
- `conn watch`: every command, decision and job exit as it happens, new job output, and approval prompts.
- Audit log in the state dir (`audit.jsonl`), hash-chained; `conn doctor` reports edits.
- Built-in read-only list: `uname`, `hostname`, `df`, `ps`, `ls`, `ip addr`, `systemctl status`, `journalctl`,
  `Get-Process` and more run without asking, checked so changing forms still ask (`safe = false` opts out).
- `conn allow <target> [words]` lists or adds allow rules; `conn deny <target> <words>` removes one.
- `conn doctor` checks the config and state dirs, ssh tools, keychain, secret sources, pinned keys and leases.

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
