#!/usr/bin/env bash
# Rerun only the real local model checks after infrastructure has already passed.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source "$ROOT/scripts/node-runtime.sh"
exec python3 scripts/acceptance.py --model-only --report data/model-acceptance.json
