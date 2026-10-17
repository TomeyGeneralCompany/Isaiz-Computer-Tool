#!/usr/bin/env python3
"""Local, read-only AutoHack acceptance checks.

Never probes bounty targets, runs target code, or submits reports.
Produces machine-readable pass/fail evidence for local deployment.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RESULTS: dict[str, dict] = {}

def record(name: str, ok: bool, detail: str) -> None:
    RESULTS[name] = {"passed": ok, "detail": detail}

def run(name: str, args: list[str], timeout: int = 120) -> None:
    try:
        proc = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        record(name, proc.returncode == 0, (proc.stdout + proc.stderr)[-1200:])
    except (OSError, subprocess.TimeoutExpired) as exc:
        record(name, False, str(exc))

def main() -> int:
    run("python_integration_tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"])
    run("launcher_syntax", ["bash", "-n", "run-local-autohack.sh", "run-complete-autohack.sh", "setup-and-run.sh"])
    if shutil.which("npm") and (ROOT / "node_modules").is_dir():
        run("typescript", ["npx", "--no-install", "tsc", "--noEmit", "--project", "tsconfig.json"], 180)
    else:
        record("typescript", False, "Local Node dependencies not installed")
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=4) as response:
            models = json.load(response).get("models", [])
        names = [m.get("name") for m in models]
        record("local_model", "qwen3:4b" in names, "Available models: " + ", ".join(str(n) for n in names))
    except Exception as exc:
        record("local_model", False, type(exc).__name__ + ": " + str(exc))
    if RESULTS.get("local_model", {}).get("passed"):
        try:
            payload = json.dumps({"model": "qwen3:4b", "stream": False, "think": False,
                                  "messages": [{"role": "user", "content": "Reply with the single word READY."}],
                                  "options": {"num_predict": 24, "temperature": 0}}).encode()
            request = urllib.request.Request("http://127.0.0.1:11434/api/chat", data=payload,
                                             headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=120) as response:
                answer = json.load(response).get("message", {}).get("content", "")
            record("local_inference", isinstance(answer, str) and "READY" in answer.upper(),
                   "Ollama produced a response" if answer else "Ollama returned no response")
        except Exception as exc:
            record("local_inference", False, str(exc))
    else:
        record("local_inference", False, "Local model unavailable")
    claude = shutil.which(os.getenv("CLAUDE_PATH", "claude"))
    if not claude:
        record("agent_backend", False, "Claude Code CLI not found; security-solver still depends on it")
    elif RESULTS["local_inference"]["passed"]:
        try:
            env = dict(os.environ)
            env.update({"ANTHROPIC_BASE_URL": "http://127.0.0.1:11434",
                        "ANTHROPIC_AUTH_TOKEN": "ollama", "ANTHROPIC_API_KEY": "ollama",
                        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"})
            proc = subprocess.run([claude, "--print", "--model", "qwen3:4b",
                                   "--max-turns", "1", "--tools", ""],
                                  input="Reply with the single word READY.",
                                  capture_output=True, text=True, timeout=120,
                                  cwd=ROOT, env=env)
            record("agent_backend", proc.returncode == 0 and "READY" in proc.stdout.upper(),
                   ("Agent backend responded" if proc.returncode == 0 else proc.stderr[-500:]))
        except (OSError, subprocess.TimeoutExpired) as exc:
            record("agent_backend", False, str(exc))
    else:
        record("agent_backend", False, "Cannot test agent backend without local inference")
    path = Path(os.getenv("DB_PATH", "data/bounty.db")).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    if path.is_file():
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=3)
            try:
                tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                record("database_schema", {"security_findings", "security_programs"} <= tables,
                       "Tables: " + ", ".join(sorted(tables & {"security_findings", "security_programs"})))
            finally:
                conn.close()
        except sqlite3.Error as exc:
            record("database_schema", False, str(exc))
    else:
        record("database_schema", False, "Database not initialized")
    record("runtime_config", (ROOT / ".env").is_file(), "Local .env present" if (ROOT / ".env").is_file() else "Local .env absent")
    print(json.dumps(RESULTS, indent=2))
    return 0 if all(result["passed"] for result in RESULTS.values()) else 1

if __name__ == "__main__":
    raise SystemExit(main())
