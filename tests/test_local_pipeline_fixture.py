#!/usr/bin/env python3
"""Isolated acceptance fixture: known vulnerable local code, no target access.

This is a deterministic test of evidence -> triage -> database -> report
handoff, not proof that a live bounty finding was verified.
"""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("offline_import", ROOT / "scripts/import-offline-leads.py")
importer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(importer)


class LocalFixture(unittest.TestCase):
    def test_source_to_draft_to_findings_and_report(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            code = base / "example.py"
            code.write_text("def unsafe_eval(user_input):\n    return eval(user_input)\n")
            evidence = {"file": code.name, "line": 2, "rule": "PY_EVAL"}
            self.assertIn("eval(user_input)", code.read_text().splitlines()[1])

            previous = importer.DRAFTS, importer.SCOPE
            try:
                importer.DRAFTS = base / "drafts"
                importer.DRAFTS.mkdir()
                importer.SCOPE = base / "scope.json"
                importer.SCOPE.write_text(json.dumps({
                    "permission": "passive_github_metadata_only",
                    "valid_until": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                    "repositories": {"fixture/unsafe": []},
                }))
                (importer.DRAFTS / "candidate.json").write_text(json.dumps({
                    "repository": "fixture/unsafe",
                    "commit": "a" * 40,
                    "lead": evidence,
                    "triage": {"classification": "needs_review", "rationale": "Manual validation required"},
                    "verified_vulnerability": False,
                    "status": "unverified_draft",
                }))
                db = sqlite3.connect(":memory:")
                try:
                    db.executescript("""
                        CREATE TABLE security_programs (
                            id TEXT, provider TEXT, name TEXT, scope_summary TEXT, status TEXT);
                        CREATE TABLE security_findings (
                            id TEXT PRIMARY KEY, program_id TEXT, title TEXT, description TEXT,
                            target_asset TEXT, status TEXT, analysis_notes TEXT,
                            confidence_score REAL, retry_count INTEGER,
                            discovered_at INTEGER, updated_at INTEGER);
                    """)
                    db.execute("INSERT INTO security_programs VALUES (?,?,?,?,?)", (
                        "fixture", "immunefi", "Local fixture",
                        json.dumps({"scopes": [{"assetIdentifier": "https://github.com/fixture/unsafe",
                                                "eligibleForBounty": True}]}), "active",
                    ))
                    self.assertEqual(importer.import_leads(db)["imported"], 1)
                    row = db.execute("SELECT id, status, analysis_notes FROM security_findings").fetchone()
                    self.assertEqual(row[1], "discovered")
                    notes = json.loads(row[2])
                    self.assertEqual(notes["verification"], "NOT VERIFIED")
                    self.assertFalse(notes["submission_eligible"])
                    report = {
                        "fixture": True,
                        "finding_id": row[0],
                        "evidence": evidence,
                        "reproduction": "Static fixture source contains eval(user_input)",
                        "status": "test_only_not_submittable",
                    }
                    output = base / "fixture-report.json"
                    output.write_text(json.dumps(report))
                    self.assertEqual(json.loads(output.read_text())["status"], "test_only_not_submittable")
                    self.assertEqual(importer.import_leads(db)["existing"], 1)
                finally:
                    db.close()
            finally:
                importer.DRAFTS, importer.SCOPE = previous


if __name__ == "__main__":
    unittest.main()
