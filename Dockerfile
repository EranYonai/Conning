# The MCP server in a container, for clients that install servers with `docker run` (D46).
#
# The image carries only what running commands needs: Python, the OpenSSH client and Conning. The
# human-only commands (`add`, `approve`, `lease`, `allow`) stay on the host, sharing the same
# CONNING_HOME volume, so nothing inside the container can grant trust to itself.
#
#   docker run -i --rm --network host \
#     -v ~/.config/conning:/conning \
#     -v "$SSH_AUTH_SOCK":/ssh-agent -e SSH_AUTH_SOCK=/ssh-agent \
#     ghcr.io/eranyonai/conning:latest
#
# The OS keychain is not reachable from a container: use `env:` or `op://` secret references, or an
# ssh-agent socket. `conn doctor` in the container says so.

FROM python:3.13-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --prefix=/install .

FROM python:3.13-slim

LABEL org.opencontainers.image.title="Conning" \
      org.opencontainers.image.description="A control room for your agent's test machines: run commands on remote targets without the agent seeing a secret." \
      org.opencontainers.image.source="https://github.com/EranYonai/Conning" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /install /usr/local

# The jobs the server starts are remote; nothing here needs root, and /conning is the human's volume.
RUN useradd --create-home --uid 1000 conning && mkdir -p /conning && chown conning /conning
USER conning

ENV CONNING_HOME=/conning \
    CONNING_STATE=/conning/state \
    CONNING_IN_CONTAINER=1 \
    PYTHONUNBUFFERED=1
VOLUME ["/conning"]

ENTRYPOINT ["conn"]
CMD ["mcp"]
