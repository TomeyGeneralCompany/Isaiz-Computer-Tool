#!/usr/bin/env python3
"""Import offline investigation leads into the main AutoHack SQLite findings queue.

Imports are always UNVERIFIED, never report_ready, validated or submitted.
No external requests or execution of target code. Idempotent by draft hash.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / ".autohack-next-stage"
DRAFTS = STAGE / "investigator/triage/drafts"
SCOPE = STAGE / "immunefi/scope.json"
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA_RE = re.compile(r"^[a-f0-9]{40}$")


def scope_repositories() -> set[str]:
    try:
        data = json.loads(SCOPE.read_text())
        if data.get("permission") != "passive_github_metadata_only":
            return set()
        expires = datetime.fromisoformat(data["valid_until"].replace("Z", "+00:00"))
        if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
            return set()
        repos = data.get("repositories")
        if not isinstance(repos, dict):
            return set()
        return {repo for repo in repos if REPO_RE.fullmatch(repo)}
    except (OSError, ValueError, TypeError, KeyError):
        return set()


def database_path() -> Path:
    configured = os.environ.get("DB_PATH", "data/autohack.db")
    path = Path(configured).expanduser()
    return path if path.is_absolute() else ROOT / path


def import_leads(db: sqlite3.Connection) -> dict:
    stats = {"seen": 0, "imported": 0, "existing": 0, "skipped": 0}
    allowed = scope_repositories()
    if not allowed:
        stats["warning"] = "No fresh passive GitHub scope; import paused"
        return stats
    required = {"security_programs", "security_findings"}
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not required.issubset(tables):
        stats["warning"] = "Main database schema not initialized"
        return stats
    programs = list(db.execute("SELECT id, provider, name, scope_summary FROM security_programs WHERE status='active'"))
    for path in sorted(DRAFTS.glob("*.json")):
        stats["seen"] += 1
        try:
            raw = path.read_bytes()
            if len(raw) > 300_000:
                raise ValueError("Oversized draft")
            draft = json.loads(raw)
            repo = draft.get("repository")
            sha = draft.get("commit")
            lead = draft.get("lead")
            if not isinstance(repo, str) or repo not in allowed or not REPO_RE.fullmatch(repo):
                raise ValueError("Not currently in passive scope")
            if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
                raise ValueError("Invalid commit")
            if not isinstance(lead, dict) or not isinstance(lead.get("file"), str):
                raise ValueError("Missing source location")
            if draft.get("verified_vulnerability") is not False or draft.get("status") != "unverified_draft":
                raise ValueError("Unexpected verification status")
            # Program association must be unambiguous and sourced from the
            # same exact GitHub asset; never guess from a display name.
            matches = []
            for program_id, provider, _name, scope_summary in programs:
                if provider != "immunefi" or not scope_summary:
                    continue
                try:
                    scope_data = json.loads(scope_summary)
                except (ValueError, TypeError):
                    continue
                if isinstance(scope_data, list) and any(
                    (isinstance(item, str) and item.rstrip("/") == "https://github.com/" + repo)
                    or (isinstance(item, dict) and any(
                        isinstance(item.get(key), str) and
                        item[key].rstrip("/") == "https://github.com/" + repo
                        for key in ("asset_url", "url", "target")
                    ))
                    for item in scope_data
                ):
                    matches.append(program_id)
            if len(matches) != 1:
                raise ValueError("No unique exact-asset program mapping")
            fingerprint = hashlib.sha256(
                json.dumps([repo, sha, lead.get("file"), lead.get("line"), lead.get("rule")],
                           sort_keys=True).encode()
            ).hexdigest()
            finding_id = "offline-" + fingerprint[:24]
            if db.execute("SELECT 1 FROM security_findings WHERE id=?", (finding_id,)).fetchone():
                stats["existing"] += 1
                continue
            now = int(datetime.now(timezone.utc).timestamp())
            title = f"Unverified static lead: {str(lead.get('rule', 'review'))[:70]}"
            notes = json.dumps({
                "source": "offline_static_triage", "repository": repo, "commit": sha,
                "lead": lead, "triage": draft.get("triage"),
                "verification": "NOT VERIFIED", "submission_eligible": False,
            }, ensure_ascii=False)[:16000]
            # discovered is the earliest state, not an assertion of security impact.
            db.execute(
                """INSERT INTO security_findings
                   (id, program_id, title, description, target_asset, status,
                    analysis_notes, confidence_score, retry_count, discovered_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, 'discovered', ?, NULL, 0, ?, ?)""",
                (finding_id, matches[0], title, "Offline static heuristic candidate; requires independent reproduction.",
                 "https://github.com/" + repo, notes, now, now),
            )
            db.commit()
            stats["imported"] += 1
        except (OSError, ValueError, TypeError, sqlite3.Error, KeyError) as exc:
            stats["skipped"] += 1
            if stats["skipped"] <= 10:
                print(f"Skipped {path.name}: {exc}")
    return stats


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Run one bounded import cycle")
    args = parser.parse_args()
    path = database_path()
    if not path.is_file():
        print(json.dumps({"warning": f"Database does not exist: {path}"}))
        return
    # Never create a database or schema as a side effect of importing.
    db = sqlite3.connect(str(path), timeout=10)
    try:
        print(json.dumps(import_leads(db), sort_keys=True))
    finally:
        db.close()


if __name__ == "__main__":
    main()
