#!/usr/bin/env bash

# This script searches the wolfssl repository for any defined
# WOLFSSL_PR*_PATCH_APPLIED macros and lists them in sorted order.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

matches="$(grep -R -h -o -E 'WOLFSSL_PR[0-9]+_PATCH_APPLIED' \
  --exclude-dir=.git \
  --exclude-dir=build \
  "$repo_root" || true)"
if [ -z "$matches" ]; then
  exit 0
fi

printf "%s\n" "$matches" | sort -u
