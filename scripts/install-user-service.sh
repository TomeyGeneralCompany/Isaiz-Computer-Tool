#!/usr/bin/env bash
# Install a per-user systemd unit for the existing AutoHack supervisor.
# Run after local dependencies and runtime configuration are validated.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "$BASH_SOURCE")/.." && pwd)"
if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd is required for this user-service installer." >&2
  exit 127
fi
if [[ ! -d "$ROOT/node_modules" || ! -f "$ROOT/.env" ]]; then
  echo "AutoHack is not configured. Run setup-and-run.sh first." >&2
  exit 2
fi
# Conservative pathname policy for embedding absolute paths in unit directives.
if [[ "$ROOT" =~ [[:space:]%] ]]; then
  echo "Move the checkout to a path without whitespace or '%'." >&2
  exit 2
fi
source "$ROOT/scripts/node-runtime.sh"
if [[ "$AUTOHACK_NODE_BIN" =~ [[:space:]%\"] ]]; then
  echo "Node executable path must not contain whitespace, quotes, or percent signs." >&2
  exit 2
fi
TARGET="$HOME/.config/systemd/user/autohack.service"
mkdir -p "$(dirname "$TARGET")"
cat > "$TARGET" <<UNIT
[Unit]
Description=AutoHack authorized offline and bounty research supervisor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$ROOT
ExecStart=/usr/bin/env bash $ROOT/run-complete-autohack.sh
Restart=always
RestartSec=20
TimeoutStopSec=30
KillMode=control-group
NoNewPrivileges=true
UMask=0077
Environment=PROJECT_ROOT=$ROOT
Environment=AUTOHACK_NODE_BIN=$AUTOHACK_NODE_BIN
Environment=PATH=$(dirname -- "$AUTOHACK_NODE_BIN"):$HOME/.local/bin:$HOME/.npm-global/bin:/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=default.target
UNIT
chmod 0644 "$TARGET"
systemctl --user daemon-reload
# enable --now leaves an already-running process in its previous checkout.
systemctl --user enable autohack.service
systemctl --user restart autohack.service
systemctl --user is-active --quiet autohack.service || {
  echo "AutoHack service is not active. See: journalctl --user -u autohack -n 60" >&2
  exit 1
}
printf '%s\n' "AutoHack user service installed and running." \
  "Control: systemctl --user stop|start|restart|status autohack.service" \
  "Logs: journalctl --user -u autohack.service -f" \
  "Service can run while the computer remains powered on." \
  "Logout persistence depends on user lingering and local system policy."
