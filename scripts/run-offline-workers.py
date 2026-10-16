#!/usr/bin/env python3
"""Manage the offline AutoHack workers with restart, logs and graceful shutdown.

The separate Node orchestrator is started by run-local-autohack.sh.
This launcher does not enable live probing or automatic bounty submission.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".autohack-next-stage"
WORKERS = {
    "scope": STAGE / "immunefi/sync.py",
    "monitor": STAGE / "worker.py",
    "investigator": STAGE / "investigator/engine.py",
    "triage": STAGE / "investigator/triage/worker.py",
    "verification": STAGE / "investigator/verification/verifier.py",
    "reproduction": STAGE / "investigator/reproduction/worker.py",
    "research": STAGE / "research-engine/worker.py",
    "evidence": STAGE / "autonomous/worker.py",
}
STOP = False


def shutdown(*_args: object) -> None:
    global STOP
    STOP = True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", nargs="+", choices=sorted(WORKERS))
    parser.add_argument("--restart-delay", type=int, default=15)
    args = parser.parse_args()
    names = args.only or list(WORKERS)
    missing = [name for name in names if not WORKERS[name].is_file()]
    if missing:
        print("Missing workers: " + ", ".join(missing), file=sys.stderr)
        return 2
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    env = os.environ.copy()
    env["AUTOHACK_ROOT"] = str(ROOT)
    env.setdefault("AUTOHACK_TRIAGE_MODEL", "qwen3:4b")
    logs = ROOT / "data" / "worker-logs"
    logs.mkdir(parents=True, exist_ok=True)
    children: dict[str, subprocess.Popen[bytes]] = {}
    streams = {}
    retry_at = {name: 0.0 for name in names}
    delay = max(5, args.restart_delay)
    try:
        while not STOP:
            for name in names:
                child = children.get(name)
                if child is not None and child.poll() is None:
                    continue
                if child is not None:
                    print(f"{name} exited with code {child.returncode}", flush=True)
                    children.pop(name, None)
                    streams.pop(name).close()
                    retry_at[name] = time.monotonic() + delay
                if time.monotonic() < retry_at[name]:
                    continue
                stream = open(logs / f"{name}.log", "ab", buffering=0)
                try:
                    child = subprocess.Popen(
                        [sys.executable, "-u", str(WORKERS[name])],
                        cwd=str(ROOT), env=env, stdout=stream,
                        stderr=subprocess.STDOUT, start_new_session=True,
                    )
                except OSError as exc:
                    print(f"Cannot start {name}: {exc}", file=sys.stderr, flush=True)
                    stream.close()
                    retry_at[name] = time.monotonic() + delay
                    continue
                children[name] = child
                streams[name] = stream
                print(f"Started {name} (pid {child.pid})", flush=True)
            time.sleep(1)
    finally:
        for child in children.values():
            if child.poll() is None:
                child.terminate()
        for child in children.values():
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for stream in streams.values():
            stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
