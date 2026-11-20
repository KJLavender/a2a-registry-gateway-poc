#!/usr/bin/env bash
# Download the Linux agentgateway binary into bin/ and check its sha256.
set -euo pipefail
asset=agentgateway-linux-amd64
gh release download "${AGENTGATEWAY_VERSION:-v1.7.0}" -R agentgateway/agentgateway -D bin \
  -p "$asset" -p "$asset.sha256"
cd bin
echo "$(cut -d' ' -f1 "$asset.sha256")  $asset" | sha256sum -c -
chmod +x "$asset"
