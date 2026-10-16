"""Fail-closed, expiry-checked passive repo scope input."""
import datetime as dt
import json
from pathlib import Path

SCOPE = Path(__file__).resolve().parent / 'scope.json'

def scoped_repositories():
    try:
        doc = json.loads(SCOPE.read_text())
        if doc.get('permission') != 'passive_github_metadata_only':
            return []
        expiry = dt.datetime.fromisoformat(doc['valid_until'])
        if expiry <= dt.datetime.now(dt.timezone.utc):
            return []
        repos = doc.get('repositories', {})
        if not isinstance(repos, dict):
            return []
        return sorted(repos)
    except (OSError, ValueError, TypeError, KeyError):
        return []
