#!/usr/bin/env python3
"""Local prerequisite check; never contacts bounty targets or submits reports."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".autohack-next-stage"
checks = {}

def executable(name):
    checks[name] = shutil.which(name) or "missing"

for tool in ("node", "npm", "python3", "git", "ollama", "bwrap", "podman", "docker"):
    executable(tool)

checks["node_modules"] = (ROOT / "node_modules").is_dir()
checks["runtime_env"] = (ROOT / ".env").is_file()
checks["database_directory"] = (ROOT / "data").is_dir()
checks["workers"] = {
    name: (STAGE / relative).is_file()
    for name, relative in {
        "scope": "immunefi/sync.py",
        "monitor": "worker.py",
        "investigator": "investigator/engine.py",
        "triage": "investigator/triage/worker.py",
        "verification": "investigator/verification/verifier.py",
        "reproduction": "investigator/reproduction/worker.py",
        "research": "research-engine/worker.py",
        "evidence": "autonomous/worker.py",
    }.items()
}
try:
    request = urllib.request.Request("http://127.0.0.1:11434/api/tags")
    with urllib.request.urlopen(request, timeout=3) as response:
        models = json.load(response).get("models", [])
    checks["ollama_models"] = [m.get("name") for m in models if isinstance(m, dict)]
except Exception as exc:
    checks["ollama_models"] = f"unavailable: {type(exc).__name__}"
try:
    cfg = json.loads((STAGE / "research-engine/config.json").read_text())
    checks["research_model"] = cfg.get("model")
    checks["foundry_image"] = cfg.get("foundry_image")
except (OSError, ValueError) as exc:
    checks["research_config"] = f"invalid: {exc}"

print(json.dumps(checks, indent=2))
required = ["node", "npm", "python3", "git"]
missing = [name for name in required if checks[name] == "missing"]
missing += [name for name, present in checks["workers"].items() if not present]
if not checks["node_modules"]:
    missing.append("node_modules (run npm ci)")
if missing:
    print("Required prerequisites missing: " + ", ".join(missing), file=sys.stderr)
    sys.exit(1)
print("Core prerequisites present. This does not verify bounty scope or end-to-end operation.")
