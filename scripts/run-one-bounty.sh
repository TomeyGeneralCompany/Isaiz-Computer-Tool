#!/usr/bin/env bash
# One existing eligible bounty program: inspect -> local verification -> review.
# This is NOT the recurring supervisor and never enables automatic submission.
set -Eeuo pipefail
umask 077
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
source "$ROOT/scripts/node-runtime.sh"
for exe in flock timeout tee node; do
  command -v "$exe" >/dev/null 2>&1 || { echo "Missing dependency: $exe" >&2; exit 127; }
done
[[ -d node_modules && -f .env ]] || {
  echo "Install/configure this checkout first: bash setup-and-run.sh --verify-only" >&2
  exit 2
}
# Never compete with an installed service or with the running orchestrator.
mkdir -p data data/one-bounty
exec 8>data/supervisor.lock
flock -n 8 || { echo "AutoHack supervisor is running. Stop it before one-bounty mode." >&2; exit 2; }
exec 9>data/orchestrator.lock
flock -n 9 || { echo "AutoHack orchestrator is running. Stop it before one-bounty mode." >&2; exit 2; }
export PROJECT_ROOT="$ROOT"
# A single cap bounds discovery, inference, review and cleanup.
minutes=35
args=("$@")
for ((i=0;i<${#args[@]};i++)); do
  if [[ "${args[i]}" == "--timeout-min" ]]; then
    ((i+=1))
    [[ $i -lt ${#args[@]} && ${args[i]} =~ ^[0-9]+$ ]] || { echo "Invalid --timeout-min" >&2; exit 2; }
    minutes="${args[i]}"
  fi
done
[[ "$minutes" =~ ^[0-9]+$ ]] && ((10#$minutes >= 5 && 10#$minutes <= 120)) || {
  echo "Timeout must be 5 through 120 minutes." >&2; exit 2;
}
if [[ " ${args[*]} " == *" --list "* || " ${args[*]} " == *" --help "* ]]; then
  exec node --import tsx scripts/one-bounty.ts "$@"
fi
LOG="data/one-bounty/terminal-$(date -u +%Y%m%dT%H%M%SZ).log"
echo "One-bounty terminal log: $ROOT/$LOG"
set +e
timeout --signal=TERM --kill-after=30s "$((10#$minutes*60+45))" node --import tsx scripts/one-bounty.ts "$@" 2>&1 | tee "$LOG"
code=${PIPESTATUS[0]}
set -e
if (( code==124 || code==137 )); then
  echo "Time cap hit; inspect the saved log and per-run JSON summary." >&2
fi
exit "$code"
