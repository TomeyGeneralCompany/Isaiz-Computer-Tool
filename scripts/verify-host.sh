#!/usr/bin/env bash
# Collect host/model/account evidence without launching hunts or submitting.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source "$ROOT/scripts/node-runtime.sh"
exec python3 scripts/acceptance.py --provider --report data/host-acceptance.json
