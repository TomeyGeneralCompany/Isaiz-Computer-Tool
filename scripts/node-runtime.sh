#!/usr/bin/env bash
# Source from launch/setup scripts. Pin the same Node ABI for npm and services.
if [[ -n "${AUTOHACK_NODE_BIN:-}" ]]; then
  [[ -x "$AUTOHACK_NODE_BIN" ]] || { echo "Configured AutoHack Node executable is missing." >&2; return 2; }
  export PATH="$(dirname -- "$AUTOHACK_NODE_BIN"):$PATH"
elif [[ -s "$HOME/.nvm/nvm.sh" ]]; then
  source "$HOME/.nvm/nvm.sh"
  nvm use --silent 22 >/dev/null 2>&1 || { echo "Install Node 22 with: nvm install 22" >&2; return 2; }
fi
command -v node >/dev/null 2>&1 || { echo "Node 22 is required." >&2; return 127; }
[[ "$(node -p 'process.versions.node.split(".")[0]')" == 22 ]] || {
  echo "AutoHack requires Node 22 for its locked native SQLite dependency. Select Node 22 and run npm ci." >&2
  return 2
}
export AUTOHACK_NODE_BIN="$(command -v node)"
