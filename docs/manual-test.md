# Manual end-to-end test

A clean-clone check of a branch against a real SSH server, from a Linux or macOS workstation (WSL works
too). It takes about ten minutes. Every step lists what you should see. Your real Conning config is
never touched: everything lives in a throwaway `CONNING_HOME` (config) and `CONNING_STATE` (job output).

You need `git`, [`uv`](https://docs.astral.sh/uv/) and the OpenSSH client (`ssh`, `scp`, `ssh-keygen`,
`ssh-keyscan`).

## 1. Clone, install, unit tests

```sh
git clone -b claude/m1-ssh https://github.com/EranYonai/Conning.git conning-m1 && cd conning-m1
uv sync
uv run pytest --cov=conning -q     # expect: all passed, TOTAL ... 100% (Linux/macOS)
uv run ruff check                  # expect: All checks passed!
export CONNING_HOME=$(mktemp -d)   # throwaway config for this test
export CONNING_STATE=$CONNING_HOME/state
alias conn='uv run -q conn'
```

## 2. A target

**Option A, a lab VM you already have** (Linux, reachable over SSH):

```sh
export T_HOST=<vm address> T_PORT=22 T_USER=<user> T_KEY=~/.ssh/id_ed25519   # key auth
```

For password auth, skip `T_KEY`, and in step 3 use `--auth password` and run `conn approve` at a terminal:
it asks for the password once and stores it in your OS keychain.

**Option B, a throwaway sshd on this machine** (no root needed, port 2222, your own user):

```sh
S=$(mktemp -d)
ssh-keygen -q -t ed25519 -N '' -f $S/hostkey
ssh-keygen -q -t ed25519 -N '' -f $S/userkey
cp $S/userkey.pub $S/authorized_keys
cat > $S/sshd_config <<EOF
Port 2222
ListenAddress 127.0.0.1
HostKey $S/hostkey
AuthorizedKeysFile $S/authorized_keys
PidFile $S/sshd.pid
StrictModes no
UsePAM no
PasswordAuthentication no
Subsystem sftp internal-sftp
EOF
$(command -v sshd || echo /usr/sbin/sshd) -f $S/sshd_config -E $S/log
export T_HOST=127.0.0.1 T_PORT=2222 T_USER=$(whoami) T_KEY=$S/userkey
```

## 3. The agent proposes a target; you approve it

```sh
conn add lab --host $T_HOST --port $T_PORT --user $T_USER --auth key --key $T_KEY --tag demo < /dev/null
```
Expect: `lab saved as pending. It does nothing until a human runs: conn approve lab`. (`< /dev/null`
makes it behave like an agent with no terminal.)

```sh
conn run lab uname -a        # expect: blocked  lab  (target is pending; ...)
conn approve lab             # shows the host key fingerprint; type y
conn ls --check              # expect: lab  linux  bash  tags=demo  mode=ask  reach=ok
```
If approving fails, the target stays pending and `conn ls` says why, e.g. `mode=pending (login check failed: ...)`.

## 4. Approvals and "always allow"

```sh
conn run lab uname -a
```
Expect: `status=pending_approval id=a:<id> ...`. Then:

```sh
conn approve a:<id>          # type e (always allow 'uname'); it then prints exit=0 and the uname line
conn read a:<id>             # what the agent sees: the same result
conn run lab uname -r        # expect: exit=0 right away, no approval (the rule matched)
```

## 5. Lease, long jobs, signals, timeouts

```sh
conn lease lab --minutes 10  # type y; the agent may now run anything on lab for 10 minutes
conn run lab --wait 0 sh -c 'for i in 1 2 3 4 5 6; do echo tick $i; sleep 1; done'
```
Expect: `status=running job=j:<job> ...`. Then:

```sh
conn read j:<job> --wait 1   # expect: status=running with only the new tick lines
conn read j:<job> --wait 15  # expect: exit=0 with the remaining ticks, none repeated
conn run lab --wait 0 sleep 300
conn read j:<job2> --signal TERM     # expect: signal=TERM sent to j:<job2>
conn read j:<job2> --wait 5          # expect: exit=143
conn run lab --timeout 2 sleep 30 # expect: exit=124 ... (timed out)
```

## 6. Output cap and paging

```sh
conn run lab seq 1 100000         # expect: header (100000 lines, ...; showing 20+60), head, marker, tail
conn read o:<out> --range 500-503    # expect: 500 to 503
conn read o:<out> --grep '^9999[0-9]$'
conn read lab:/etc/os-release --range 1-2   # expect: file=lab:/etc/os-release lines=1-2 untrusted
```

## 7. Transfers

```sh
head -c 200000 /dev/urandom > /tmp/conning-blob.bin
conn transfer local:/tmp/conning-blob.bin lab:/tmp/conning-blob.bin       # expect: sha256 verified
conn transfer lab:/tmp/conning-blob.bin local:/tmp/conning-blob.back
cmp /tmp/conning-blob.bin /tmp/conning-blob.back && echo identical
```

## 8. Secrets never reach the agent

```sh
printf 'inject = { DEMO_TOKEN = "env:DEMO_TOKEN" }\n' >> $CONNING_HOME/targets.toml
export DEMO_TOKEN=s3cret-demo-token
conn run lab sh -c 'echo plain=$DEMO_TOKEN; printf %s "$DEMO_TOKEN" | base64'
```
Expect: `plain=[REDACTED]` and `[REDACTED]`. Then `grep -r s3cret $CONNING_HOME` finds nothing (that covers the state dir too).

```sh
unset DEMO_TOKEN
conn read lab:/etc/hostname          # expect: error: secret env:DEMO_TOKEN: environment variable is not set
```

## 9. A changed host key is a hard fail (option B only)

```sh
ssh -O exit -F $CONNING_STATE/ssh/lab.conf conning-target 2>/dev/null   # close the reused connection
kill $(cat $S/sshd.pid); rm $S/hostkey*; ssh-keygen -q -t ed25519 -N '' -f $S/hostkey
$(command -v sshd || echo /usr/sbin/sshd) -f $S/sshd_config -E $S/log
conn run lab uname -s     # expect: error: lab: host key does not match the pinned key ...
conn approve lab             # re-pin: shows the new fingerprint; type y
conn run lab uname -s     # expect: exit=0
```

## 10. The MCP server

```sh
export DEMO_TOKEN=s3cret-demo-token
uv run -q python - <<'EOF'
import asyncio, os
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    server = StdioServerParameters(command="uv", args=["run", "-q", "conn", "mcp"], env=dict(os.environ))
    async with stdio_client(server) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        print("tools:", sorted(t.name for t in (await s.list_tools()).tools))
        for name, args in [("targets", {"check": True}), ("run", {"target": "lab", "argv": ["uname", "-s"]}),
                           ("read", {"id": "lab:/etc/hostname"})]:
            print(f"--- {name}\n" + (await s.call_tool(name, args)).content[0].text)

asyncio.run(main())
EOF
```
Expect: the four tools, then the same text the CLI printed.

To try it from a real agent: `claude mcp add conning-dev -e CONNING_HOME=$CONNING_HOME -e CONNING_STATE=$CONNING_STATE -- uv run --directory $PWD -q conn mcp`.

## Clean up

```sh
[ -n "$S" ] && kill $(cat $S/sshd.pid)
rm -rf "$CONNING_HOME" /tmp/conning-blob.*
```
On the target, Conning's job files are under `~/.conning/jobs`.
