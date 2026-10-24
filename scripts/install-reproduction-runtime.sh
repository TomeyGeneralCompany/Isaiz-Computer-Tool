#!/usr/bin/env bash
# Install the local Python, JavaScript, Java and Solidity test toolchains; never executes target project scripts.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/node-runtime.sh"
packages=()
command -v bwrap >/dev/null 2>&1 || packages+=(bubblewrap)
command -v python3 >/dev/null 2>&1 || packages+=(python3)
if ! command -v javac >/dev/null 2>&1 || ! command -v java >/dev/null 2>&1; then
  packages+=(default-jdk-headless)
fi
if (( ${#packages[@]} )); then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Install bubblewrap, Python 3 and a JDK with your package manager, then rerun setup." >&2
    exit 2
  fi
  if [[ "$(id -u)" == 0 ]]; then
    apt-get update
    apt-get install -y "${packages[@]}"
  else
    sudo apt-get update
    sudo apt-get install -y "${packages[@]}"
  fi
fi
npm install --prefix "$ROOT/scripts/reproduction-runtime" --ignore-scripts --no-audit --no-fund
node -e 'const r=process.argv[1]; for (const name of ["solc","ethers","ganache"]) require(require.resolve(name,{paths:[r]}));' "$ROOT/scripts/reproduction-runtime"
if ! bwrap --unshare-all --die-with-parent --ro-bind / / -- /usr/bin/true; then
  echo "Bubblewrap is installed but this host denies the required namespaces. Resolve the host's user-namespace/AppArmor policy before running hunts, then rerun setup." >&2
  exit 2
fi

python3 --version
node --version
javac -version
