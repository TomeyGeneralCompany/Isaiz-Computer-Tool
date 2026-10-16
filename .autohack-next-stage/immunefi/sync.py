#!/usr/bin/env python3
"""Conservative Immunefi scope-to-passive-GitHub-monitor connector.

Only explicitly listed GitHub repository assets on active public programs are
eligible. The generated list permits GitHub metadata polling ONLY; it does not
confer permission for scanning, exploitation, or submission.
"""
import datetime as dt
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import urllib.parse
import urllib.request

BASE = Path(__file__).resolve().parent
API = 'https://immunefi.com/public-api/bounties.json'
REPO = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
NOW = dt.datetime.now(dt.timezone.utc)

def parse_date(value):
    if not value or not isinstance(value, str):
        return None
    try:
        return dt.datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(dt.timezone.utc)
    except ValueError:
        return None

def github_repo(url):
    if not isinstance(url, str):
        return None
    p = urllib.parse.urlparse(url.strip())
    if p.scheme != 'https' or p.hostname not in ('github.com', 'www.github.com') or p.username or p.password or p.port:
        return None
    parts = [urllib.parse.unquote(x) for x in p.path.strip('/').split('/')]
    if len(parts) != 2 or not all(parts) or p.query or p.fragment:
        return None
    repo = '/'.join(parts)
    if not REPO.fullmatch(repo) or parts[1].endswith('.git'):
        return None
    return repo

def active(program):
    if program.get('inviteOnly') is not False:
        return False
    if program.get('endDate') and (not parse_date(program['endDate']) or parse_date(program['endDate']) <= NOW):
        return False
    if program.get('launchDate') and (not parse_date(program['launchDate']) or parse_date(program['launchDate']) > NOW):
        return False
    status = str(program.get('status', 'active')).lower()
    if status not in ('active', 'live', 'ongoing'):
        return False
    return bool(program.get('slug'))

def extract(programs):
    found = {}
    for p in programs:
        if not isinstance(p, dict) or not active(p):
            continue
        assets = p.get('assets')
        if not isinstance(assets, list):
            continue
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            # Only the explicit scope target, never codebase/resource links.
            repo = github_repo(asset.get('url'))
            if not repo:
                continue
            # Do not accept an asset explicitly marked excluded/inactive.
            if asset.get('inScope') is False or asset.get('outOfScope') is True or asset.get('isActive') is False:
                continue
            found.setdefault(repo, []).append({'program': str(p['slug']), 'scope_url': 'https://immunefi.com/bug-bounty/' + str(p['slug']) + '/scope/', 'asset_url': asset['url'], 'asset_type': asset.get('type', '')})
    return found

def atomic_json(path, obj):
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.tmp-')
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(obj, out, indent=2, sort_keys=True)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def main():
    request = urllib.request.Request(API, headers={'User-Agent': 'AutoHack-Immunefi-scope-connector/1.0', 'Accept': 'application/json'})
    with urllib.request.urlopen(request, timeout=45) as response:
        if 'json' not in response.headers.get('Content-Type', '').lower():
            raise ValueError('Unexpected API content type')
        raw = response.read(16_000_001)
        if len(raw) > 16_000_000:
            raise ValueError('API response exceeds size limit')
    programs = json.loads(raw)
    if not isinstance(programs, list) or len(programs) < 10:
        raise ValueError('Unexpected Immunefi catalog shape; retaining previous cache')
    repos = extract(programs)
    if not repos:
        raise ValueError('No exact GitHub repository assets found; retaining previous cache')
    atomic_json(BASE / 'scope.json', {'source': API, 'updated_at': NOW.isoformat(), 'valid_until': (NOW + dt.timedelta(hours=12)).isoformat(), 'permission': 'passive_github_metadata_only', 'repositories': repos})
    print(f'Immunefi: {len(programs)} programs read; {len(repos)} explicit GitHub repository assets eligible for passive monitoring.')
    print('Program rules and exclusions remain authoritative; no active testing enabled.')

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print('Immunefi sync failed (previous valid cache retained):', e, file=sys.stderr)
        sys.exit(1)
