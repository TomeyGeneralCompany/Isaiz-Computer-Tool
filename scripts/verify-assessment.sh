#!/usr/bin/env bash
# Exercise production program assessment with fictional data and local inference.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source "$ROOT/scripts/node-runtime.sh"
exec node --import tsx scripts/test-local-assessment.ts
