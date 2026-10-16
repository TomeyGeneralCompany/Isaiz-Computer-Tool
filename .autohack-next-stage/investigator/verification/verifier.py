#!/usr/bin/env python3
"""Continuous offline evidence checker for AutoHack triage drafts.
Never executes repository code, connects to targets, or asserts a vulnerability.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
from datetime import datetime, timezone

ROOT = Path(os.environ.get('AUTOHACK_ROOT', str(Path.home() / 'isaiz-bugbounty/autohack')))
BASE = ROOT / '.autohack-next-stage/investigator'
DRAFTS = BASE / 'triage/drafts'
OUT = BASE / 'verification/results'
OUT.mkdir(parents=True, exist_ok=True)
STOP = False

def stop(*_):
    global STOP
    STOP = True

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)

def now():
    return datetime.now(timezone.utc).isoformat()

def jsonwrite(path, data):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n')
    temp.replace(path)

def locate_path(lead):
    if not isinstance(lead, dict):
        return None
    for key in ('file', 'path', 'file_path', 'filename', 'source_file'):
        val = lead.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None

def locate_line(lead):
    if not isinstance(lead, dict):
        return None
    for key in ('line', 'line_number', 'start_line'):
        try:
            val = int(lead.get(key))
            if val > 0:
                return val
        except (ValueError, TypeError):
            pass
    return None

def excerpt_text(value):
    if isinstance(value, str):
        return value[:24000]
    if isinstance(value, dict):
        for key in ('text', 'content', 'snippet', 'excerpt'):
            if isinstance(value.get(key), str):
                return value[key][:24000]
    return ''

def check(draft_path):
    raw = draft_path.read_bytes()
    fingerprint = hashlib.sha256(raw + b'|verifier-v1').hexdigest()
    destination = OUT / (draft_path.stem + '.json')
    if destination.exists():
        try:
            if json.loads(destination.read_text()).get('input_fingerprint') == fingerprint:
                return False
        except (ValueError, OSError):
            pass
    result = {
        'source_draft': str(draft_path), 'input_fingerprint': fingerprint,
        'checked_at': now(), 'status': 'needs_manual_or_test_verification',
        'verified_vulnerability': False, 'tests_executed': 0,
        'checks': [], 'limitations': [
            'This is offline evidence validation, not exploit reproduction.',
            'No project code or generated test cases are executed.',
            'A valid excerpt or parseable code does not prove vulnerability.'
        ]
    }
    try:
        d = json.loads(raw)
        if not isinstance(d, dict):
            raise ValueError('Draft is not a JSON object')
        result['repository'] = d.get('repository')
        result['commit'] = d.get('commit')
        result['scope_sources'] = d.get('scope_sources', [])
        lead = d.get('lead')
        text = excerpt_text(d.get('source_excerpt'))
        path = locate_path(lead)
        line = locate_line(lead)
        result['lead_location'] = {'path': path, 'line': line}
        result['checks'].append({'name': 'has_repository_and_commit', 'passed': bool(d.get('repository') and d.get('commit'))})
        result['checks'].append({'name': 'has_program_scope_reference', 'passed': bool(d.get('scope_sources'))})
        result['checks'].append({'name': 'has_code_excerpt', 'passed': bool(text.strip())})
        result['checks'].append({'name': 'has_source_location', 'passed': bool(path and line)})
        if path and text:
            suffix = Path(path).suffix.lower()
            if suffix == '.py':
                try:
                    ast.parse(text)
                    result['checks'].append({'name': 'python_excerpt_syntax', 'passed': True, 'note': 'Excerpt parses as standalone Python'})
                except SyntaxError:
                    result['checks'].append({'name': 'python_excerpt_syntax', 'passed': None, 'note': 'Partial excerpt cannot be assessed as a standalone module'})
            elif suffix in ('.js', '.cjs', '.mjs'):
                result['checks'].append({'name': 'javascript_excerpt_syntax', 'passed': None, 'note': 'Partial snippet: no execution or syntax claim'})
        triage = d.get('triage')
        result['triage_present'] = bool(triage)
        result['checks'].append({'name': 'has_ai_triage', 'passed': bool(triage)})
        failed = [c['name'] for c in result['checks'] if c['passed'] is False]
        result['status'] = 'insufficient_evidence' if failed else 'ready_for_isolated_reproduction'
        result['missing_evidence'] = failed
        result['next_step'] = 'Create a non-destructive, isolated regression test tailored to the alleged flaw and run it in a sandbox; do not label verified until a reproducible security impact is demonstrated.'
    except Exception as e:
        result['status'] = 'invalid_draft'
        result['error'] = str(e)[:500]
    jsonwrite(destination, result)
    print(f"[{now()}] {draft_path.name}: {result['status']}", flush=True)
    return True

def main():
    print(f"[{now()}] Offline verifier started; watching {DRAFTS}", flush=True)
    while not STOP:
        try:
            for p in sorted(DRAFTS.glob('*.json')):
                if STOP:
                    break
                if p.is_file():
                    check(p)
        except Exception as e:
            print(f"[{now()}] Worker error: {e}", flush=True)
        for _ in range(30):
            if STOP:
                break
            time.sleep(1)
    print(f"[{now()}] Verifier stopped", flush=True)

if __name__ == '__main__':
    main()
