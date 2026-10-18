#!/usr/bin/env python3
"""Prompt locally, verify read-only API access, then save credentials privately."""
import getpass
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def save_credentials(path, username, token):
    text = path.read_text() if path.is_file() else ''
    for key, value in [('HACKERONE_USERNAME', username), ('HACKERONE_API_TOKEN', token)]:
        if not value or any(char in value for char in '\r\n'):
            raise ValueError('Credentials must be nonempty single-line values')
        line = key + '=' + json.dumps(value)
        pattern = re.compile(r'^[ \t]*(?:export\s+)?' + key + r'\s*=.*$', re.MULTILINE)
        text = pattern.sub(lambda _: line, text) if pattern.search(text) else text.rstrip('\n') + '\n' + line + '\n'
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix='.env-credentials-', delete=False) as output:
            temporary = Path(output.name)
            os.fchmod(output.fileno(), 0o600)
            output.write(text)
        os.replace(temporary, path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def main():
    username = input('HackerOne username (not email): ').strip()
    token = getpass.getpass('HackerOne API token (hidden): ').strip()
    if not username or not token:
        print('No credentials saved: username and token are required.')
        return 1
    env = dict(os.environ, HACKERONE_USERNAME=username, HACKERONE_API_TOKEN=token)
    try:
        result = subprocess.run([os.environ.get('AUTOHACK_NODE_BIN', 'node'), '--import', 'tsx', 'scripts/provider-preflight.ts'],
                                cwd=ROOT, env=env, capture_output=True, text=True, timeout=25)
    except (OSError, subprocess.TimeoutExpired):
        print('Credential verification connection failed. No credentials saved.')
        return 1
    try:
        checked = json.loads(result.stdout)
    except ValueError:
        print('Credential verification could not complete. No credentials saved.')
        return 1
    if result.returncode != 0 or checked.get('passed') is not True:
        print(checked.get('detail', 'Credential verification failed.'))
        print('No credentials saved.')
        return 1
    save_credentials(ROOT / '.env', username, token)
    print('HackerOne authenticated read access verified. Credentials saved privately in .env.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
