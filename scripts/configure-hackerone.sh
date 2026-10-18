#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/node-runtime.sh"
exec python3 "$ROOT/scripts/configure-hackerone.py"
