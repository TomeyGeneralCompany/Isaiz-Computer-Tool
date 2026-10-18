#!/usr/bin/env bash
# Safe human-facing service controls. No automatic bounty submission toggles.
set -Eeuo pipefail
command -v systemctl >/dev/null 2>&1 || { echo "systemctl unavailable" >&2; exit 127; }
case "$1" in
  start|stop|restart|status)
    exec systemctl --user "$1" autohack.service
    ;;
  enable)
    exec systemctl --user enable --now autohack.service
    ;;
  disable)
    exec systemctl --user disable --now autohack.service
    ;;
  logs)
    exec journalctl --user -u autohack.service -n 80 --no-pager
    ;;
  *)
    echo "Usage: bash scripts/control-user-service.sh {start|stop|restart|status|enable|disable|logs}" >&2
    exit 2
    ;;
esac
