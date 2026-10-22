#!/usr/bin/env bash
# Start the main AutoHack app and the bounded offline worker pipeline together.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
export AUTOHACK_ROOT="$ROOT"
source "$ROOT/scripts/node-runtime.sh"
# A kernel-held lock is released after exit/crash; no stale PID cleanup needed.
command -v flock >/dev/null 2>&1 || { echo "flock (util-linux) is required." >&2; exit 127; }
mkdir -p data
exec 9>data/supervisor.lock
flock -n 9 || { echo "AutoHack supervisor is already running in this checkout." >&2; exit 2; }
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 127
fi
# Sequential mode owns discovery, analysis, reproduction and review in Node.
# Do not start the independent scan/research worker farm alongside it.
if [[ "${AUTOHACK_SEQUENTIAL_PIPELINE:-true}" != "false" ]]; then
  echo "Sequential pipeline enabled; independent offline workers are parked."
  exec bash "$ROOT/run-local-autohack.sh"
fi
mkdir -p data/worker-logs
python3 -u scripts/run-offline-workers.py >data/worker-logs/supervisor.log 2>&1 &
WORKER_PID=$!
MAIN_PID=""
shutdown() {
  trap - INT TERM EXIT
  if [[ -n "$MAIN_PID" ]]; then
    kill "$MAIN_PID" 2>/dev/null || true
  fi
  kill "$WORKER_PID" 2>/dev/null || true
  wait "$WORKER_PID" 2>/dev/null || true
  if [[ -n "$MAIN_PID" ]]; then
    wait "$MAIN_PID" 2>/dev/null || true
  fi
}
trap shutdown INT TERM EXIT
bash "$ROOT/run-local-autohack.sh" &
MAIN_PID=$!
echo "AutoHack launched. Worker logs: $ROOT/data/worker-logs/"
echo "Dashboard (when available): http://localhost:3456"
set +e
wait -n "$MAIN_PID" "$WORKER_PID"
STATUS=$?
set -e
exit "$STATUS"
