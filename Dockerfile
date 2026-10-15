# The MCP server in a container, for clients that install servers with `docker run` (D46).
#
# The image carries only what running commands needs: Python, the OpenSSH client and Conning. The
# human-only commands (`add`, `approve`, `lease`, `allow`) stay on the host, sharing the same
# CONNING_HOME volume, so nothing inside the container can grant trust to itself. `conn` runs as the
# volume's owner (docker/entrypoint.py), so what it writes there stays the human's on the host.
#
#   docker run -i --rm --network host \
#     -v ~/.config/conning:/conning \
#     -v "$SSH_AUTH_SOCK":/ssh-agent -e SSH_AUTH_SOCK=/ssh-agent \
#     ghcr.io/eranyonai/conning:latest
#
# On Docker Desktop for Mac the agent socket is /run/host-services/ssh-auth.sock.
#
# The OS keychain is not reachable from a container: use `env:` or `op://` secret references, or an
# ssh-agent socket. `conn doctor` in the container says so.

FROM python:3.13-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
COPY --from=ghcr.io/astral-sh/uv:0.11.32 /uv /usr/local/bin/uv
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
# The versions CI tested, from uv.lock, not whatever is newest on the day of the build.
RUN uv export --frozen --no-dev --no-emit-project --no-hashes -o requirements.txt \
    && pip install --prefix=/install -r requirements.txt .

FROM python:3.13-slim

LABEL org.opencontainers.image.title="Conning" \
      org.opencontainers.image.description="A control room for your agent's test machines: run commands on remote targets without the agent seeing a secret." \
      org.opencontainers.image.source="https://github.com/EranYonai/Conning" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /install /usr/local
COPY docker/entrypoint.py /usr/local/lib/conning-entrypoint.py

# The jobs the server starts are remote; nothing here needs root. The entrypoint starts as root only
# to switch to the owner of /conning; `docker run --user` skips that.
RUN useradd --create-home --uid 1000 conning && mkdir -p /conning && chown conning:conning /conning

ENV CONNING_HOME=/conning \
    CONNING_STATE=/conning/state \
    CONNING_IN_CONTAINER=1 \
    PYTHONUNBUFFERED=1
VOLUME ["/conning"]

ENTRYPOINT ["python", "/usr/local/lib/conning-entrypoint.py"]
CMD ["mcp"]
