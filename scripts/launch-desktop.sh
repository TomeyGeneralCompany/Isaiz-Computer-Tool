#!/usr/bin/env bash
# Desktop entry point for the installed local service and dashboard.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
fail() {
  printf '%s\n' "$1" >&2
  if command -v zenity >/dev/null 2>&1; then
    zenity --error --title="Tomey Gun" --text="$1" || true
  elif command -v notify-send >/dev/null 2>&1; then
    notify-send "Tomey Gun" "$1" || true
  fi
  exit 1
}
source "$ROOT/scripts/node-runtime.sh" || fail "Node 22 is unavailable. Open the terminal and run setup-and-run.sh --verify-only."
export PROJECT_ROOT="$ROOT"
PORT="$(node --import tsx --input-type=module -e 'import "dotenv/config"; import {getConfig} from "./packages/core/src/config.ts"; console.log(getConfig().DASHBOARD_PORT)')" || fail "Could not read the local configuration."
[[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT >= 1 && PORT <= 65535)) || fail "The configured dashboard port is invalid."
URL="http://127.0.0.1:$PORT/security"
STATE="${XDG_DATA_HOME:-$HOME/.local/share}/tomey-gun"
mkdir -p "$STATE"
chmod 700 "$STATE"
systemctl --user start autohack.service || fail "Could not start Tomey Gun. Check: journalctl --user -u autohack.service -n 80"
DEADLINE=$((SECONDS + 60))
READY=false
while ((SECONDS < DEADLINE)); do
  if curl --fail --silent --location --max-time 2 --output /dev/null "$URL"; then
    READY=true
    break
  fi
  sleep 1
done
[[ "$READY" == true ]] || fail "The dashboard did not become ready within 60 seconds. Check the AutoHack service logs."
for BROWSER in google-chrome google-chrome-stable chromium chromium-browser; do
  if command -v "$BROWSER" >/dev/null 2>&1; then
    exec "$BROWSER" "--app=$URL" --class=TomeyGun "--user-data-dir=$STATE/browser-profile" >>"$STATE/launcher.log" 2>&1
  fi
done
# Firefox and other desktop defaults remain usable if Chromium is unavailable.
command -v xdg-open >/dev/null 2>&1 || fail "No supported browser or desktop URL opener was found."
exec xdg-open "$URL"
