#!/usr/bin/env bash
# Provision a Linux host to run SayDo's container sandbox.
#
# Target: a free-tier VM (Oracle Always-Free, GCP e2-micro) or any Ubuntu/
# Debian box. Installs Docker, then gVisor, then creates the isolated network
# the runner uses. Run once, as a user with sudo.
#
#     bash provision.sh
#
# It is deliberately verbose about what it changes: this host will execute
# untrusted MCP servers, so the operator should be able to read every step.
# It installs nothing beyond Docker, gVisor, and one Docker network.
set -euo pipefail

say() { printf '\n=== %s\n' "$*"; }

say "1/4  Docker"
if command -v docker >/dev/null 2>&1; then
  echo "docker already installed: $(docker --version)"
else
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"
  echo "NOTE: log out and back in for the docker group to take effect."
fi

say "2/4  gVisor (runsc)"
# gVisor runs as a Docker runtime, so the same run command works with or
# without it. It needs an x86_64 or arm64 Linux kernel; if this step fails the
# Docker path still works and the runner simply omits --runtime.
if command -v runsc >/dev/null 2>&1; then
  echo "runsc already installed: $(runsc --version | head -1)"
else
  ARCH=$(uname -m)
  URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"
  TMP=$(mktemp -d)
  if curl -fsSL "${URL}/runsc" -o "$TMP/runsc" \
     && curl -fsSL "${URL}/containerd-shim-runsc-v1" -o "$TMP/containerd-shim-runsc-v1"; then
    chmod +x "$TMP/runsc" "$TMP/containerd-shim-runsc-v1"
    sudo mv "$TMP/runsc" "$TMP/containerd-shim-runsc-v1" /usr/local/bin/
    sudo /usr/local/bin/runsc install
    sudo systemctl restart docker
    echo "gVisor installed and registered with docker."
  else
    echo "WARNING: could not fetch gVisor for ${ARCH}."
    echo "The locked-down Docker path still works; run SayDo without --runtime."
  fi
fi

say "3/4  isolated network"
# A bridge network with no gateway to the internet: containers on it reach
# only what is attached to the network -- which will be the SayDo proxy. This
# is what makes 'the only route out is the proxy' true rather than hoped for.
if docker network inspect saydo-none >/dev/null 2>&1; then
  echo "network saydo-none already exists"
else
  docker network create --internal saydo-none
  echo "created internal network saydo-none (no route off-host)"
fi

say "4/4  verify"
docker info --format 'runtimes: {{json .Runtimes}}' || true
echo
echo "Provisioned. Next: build a server image, e.g."
echo "  docker build -f container/Dockerfile.python \\"
echo "    --build-arg SERVER_SPEC='mcp-server-fetch==2026.8.18' \\"
echo "    -t saydo/mcp-server-fetch:2026.8.18 container/"
echo
echo "Then run the harness with the container runner. If gVisor installed,"
echo "add the runsc runtime for the stronger sandbox."
