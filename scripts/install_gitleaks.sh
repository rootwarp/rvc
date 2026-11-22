#!/usr/bin/env bash
# Install the pinned gitleaks release into /usr/local/bin on a Linux x64
# runner. Both secret-scan workflows call this script, so they use one pin.
# scripts/gitleaks_strict_config.py pins the default config of this version.
set -euo pipefail

GITLEAKS_VERSION=8.21.2
GITLEAKS_SHA256=5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" -o "$tmp/gitleaks.tar.gz"
echo "${GITLEAKS_SHA256}  $tmp/gitleaks.tar.gz" | sha256sum -c -
sudo tar -xz -C /usr/local/bin -f "$tmp/gitleaks.tar.gz" gitleaks
gitleaks version
