#!/bin/sh
# A throwaway OpenSSH server on 127.0.0.1 for the end-to-end tests: a real target with key and
# password login. Run it as root (sudo), because password login checks a real account; it creates
# the account `conning-e2e` with a random password. It prints the settings the tests read, one
# NAME=value per line (the format of $GITHUB_ENV):
#
#   sudo sh tests/e2e/start-sshd.sh /tmp/conning-sshd >> "$GITHUB_ENV"         # in CI
#   eval "$(sudo sh tests/e2e/start-sshd.sh /tmp/conning-sshd | sed 's/^/export /')"   # by hand
#   uv run pytest -m e2e
set -eu
dir=${1:?usage: start-sshd.sh <empty dir> [port]}
port=${2:-2222}
user=conning-e2e
owner=${SUDO_USER:-$(id -un)}  # who runs the tests and must read the key

mkdir -p "$dir" /run/sshd
id "$user" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$user"
password=$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
echo "$user:$password" | chpasswd
home=$(getent passwd "$user" | cut -d: -f6)

ssh-keygen -q -t ed25519 -N '' -f "$dir/hostkey"
ssh-keygen -q -t ed25519 -N '' -f "$dir/userkey"
install -d -m 700 -o "$user" "$home/.ssh"
install -m 600 -o "$user" "$dir/userkey.pub" "$home/.ssh/authorized_keys"
chown "$owner" "$dir/userkey" "$dir/userkey.pub"

cat > "$dir/sshd_config" <<CONF
Port $port
ListenAddress 127.0.0.1
HostKey $dir/hostkey
PidFile $dir/sshd.pid
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM no
AllowUsers $user
Subsystem sftp internal-sftp
CONF
"$(command -v sshd || echo /usr/sbin/sshd)" -f "$dir/sshd_config" -E "$dir/sshd.log"

echo "CONNING_E2E_PORT=$port"
echo "CONNING_E2E_USER=$user"
echo "CONNING_E2E_KEY=$dir/userkey"
echo "CONNING_E2E_PASSWORD=$password"
