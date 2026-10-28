#!/usr/bin/env python3
"""Check exact upstream provenance, without executing any upstream fixture."""
import hashlib
import json
from pathlib import Path
root = Path(__file__).parent / 'vendor' / 'semgrep-rules'
manifest = json.loads((root / 'manifest.json').read_text())
for entry in manifest['files']:
    path = root / entry['path']
    assert path.resolve().is_relative_to(root.resolve()), entry['path']
    assert hashlib.sha256(path.read_bytes()).hexdigest() == entry['sha256'], entry['path']
assert len(list(root.rglob('*.yaml'))) == 24
print(f"Verified {len(manifest['files'])} upstream files at {manifest['commit']}")
