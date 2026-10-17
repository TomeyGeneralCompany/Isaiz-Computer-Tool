"""Offline lead importer integration tests; no network, model, or target execution."""
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/import-offline-leads.py"
spec = importlib.util.spec_from_file_location("offline_import", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ImporterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.old = (module.DRAFTS, module.SCOPE)
        self.addCleanup(self.restore)
        module.DRAFTS = root / "drafts"
        module.DRAFTS.mkdir()
        module.SCOPE = root / "scope.json"
        module.SCOPE.write_text(json.dumps({
            "permission": "passive_github_metadata_only",
            "valid_until": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "repositories": {"example/repo": []},
        }))
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE security_programs (
              id TEXT, provider TEXT, name TEXT, scope_summary TEXT, status TEXT);
            CREATE TABLE security_findings (
              id TEXT PRIMARY KEY, program_id TEXT, title TEXT, description TEXT,
              target_asset TEXT, status TEXT, analysis_notes TEXT,
              confidence_score REAL, retry_count INTEGER,
              discovered_at INTEGER, updated_at INTEGER);
        """)
        self.db.execute(
            "INSERT INTO security_programs VALUES (?,?,?,?,?)",
            ("p1", "immunefi", "Example", json.dumps(["https://github.com/example/repo"]), "active"),
        )
        self.draft = {
            "repository": "example/repo", "commit": "a" * 40,
            "lead": {"file": "src/main.py", "line": 4, "rule": "PY_EVAL"},
            "verified_vulnerability": False, "status": "unverified_draft",
            "triage": {"classification": "needs_review"},
        }
        (module.DRAFTS / "lead.json").write_text(json.dumps(self.draft))

    def restore(self):
        module.DRAFTS, module.SCOPE = self.old

    def test_import_is_idempotent_and_unverified(self):
        self.assertEqual(module.import_leads(self.db)["imported"], 1)
        self.assertEqual(module.import_leads(self.db)["existing"], 1)
        row = self.db.execute("SELECT status, confidence_score, analysis_notes FROM security_findings").fetchone()
        self.assertEqual(row[0], "discovered")
        self.assertIsNone(row[1])
        self.assertFalse(json.loads(row[2])["submission_eligible"])

    def test_expired_scope_blocks_import(self):
        scope = json.loads(module.SCOPE.read_text())
        scope["valid_until"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        module.SCOPE.write_text(json.dumps(scope))
        self.assertEqual(module.import_leads(self.db)["imported"], 0)

    def test_no_program_match_blocks_import(self):
        self.db.execute("DELETE FROM security_programs")
        self.assertEqual(module.import_leads(self.db)["imported"], 0)

    def test_unverified_only(self):
        self.draft["verified_vulnerability"] = True
        (module.DRAFTS / "lead.json").write_text(json.dumps(self.draft))
        self.assertEqual(module.import_leads(self.db)["imported"], 0)


if __name__ == "__main__":
    unittest.main()
