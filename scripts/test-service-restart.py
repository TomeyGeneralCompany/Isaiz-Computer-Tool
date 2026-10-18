#!/usr/bin/env python3
"""CI-only end-to-end service bootstrap/restart smoke, offline by default.

Uses a temporary SQLite schema created by Drizzle. Network destinations are
limited to the local dashboard; provider discovery and hunts are explicitly
disabled. This validates process startup/restart, not live bounty operations.
"""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PORT = 3456
URL = "http://127.0.0.1:3456/api/trpc/securityEarnings"

def check_url():
    try:
        with urllib.request.urlopen(URL, timeout=3) as r:
            if r.status != 200:
                return False
            data = json.load(r)
        result = data.get("result", {}).get("data", {})
        # superjson transformer returns {json: { ... }}.
        obj = result.get("json", result)
        return (obj.get("monthlyTargetCents") == 400000
                and isinstance(obj.get("verifiedPaidCents"), int)
                and isinstance(obj.get("pendingReports"), int))
    except (OSError, ValueError, TypeError, KeyError):
        return False

def wait_for_shutdown():
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        with socket.socket() as s:
            s.settimeout(1)
            if s.connect_ex(("127.0.0.1",PORT)) != 0:
                return True
        time.sleep(0.3)
    return False

def smoke(iteration):
    env = os.environ.copy()
    env.update({
        "GITHUB_TOKEN":"ci-mock-never-real",
        "HACKERONE_ENABLED":"false",
        "IMMUNEFI_ENABLED":"false",
        "HUNTR_ENABLED":"false",
        "AGGREGATOR_ENABLED":"false",
        "SECURITY_AUTO_HUNT_ENABLED":"false",
        "SECURITY_AUTO_SUBMIT":"false",
        "LOCAL_OLLAMA_MODEL":"",
        "DASHBOARD_PORT":str(PORT),
    })
    with tempfile.TemporaryFile(mode="w+t") as output:
        runner = subprocess.Popen(["npx","tsx","orchestrator.ts"],
            cwd=ROOT,env=env,start_new_session=True,
            stdout=output,stderr=subprocess.STDOUT)
        try:
            deadline=time.monotonic()+100
            while time.monotonic()<deadline:
                if runner.poll() is not None:
                    break
                if check_url():
                    print(f"Launch {iteration}: dashboard API and real SQLite answered", flush=True)
                    return
                time.sleep(0.8)
            output.seek(0)
            logs=output.read()[-4500:]
            raise AssertionError(f"Dashboard did not become healthy on iteration {iteration}:\n{logs}")
        finally:
            try:
                os.killpg(runner.pid,signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                runner.wait(timeout=12)
            except subprocess.TimeoutExpired:
                try: os.killpg(runner.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                runner.wait(timeout=5)
            if not wait_for_shutdown():
                raise AssertionError("Service left dashboard listening after shutdown")

def main():
    if os.environ.get("CI_DASHBOARD_SMOKE") != "1":
        raise SystemExit("CI_DASHBOARD_SMOKE=1 required")
    if not Path(os.environ.get("DB_PATH","")).is_file():
        raise SystemExit("Missing isolated initialized CI SQLite database")
    smoke(1)
    smoke(2)
    print("Real orchestrator/dashboard startup, shutdown and restart: PASSED")

if __name__=="__main__":
    main()
