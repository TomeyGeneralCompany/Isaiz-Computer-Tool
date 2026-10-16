#!/usr/bin/env python3
"""Bounded, persistent, passive GitHub repository change monitor for authorized targets.

This is a verified, low-impact stage for an autonomous workflow, not an exploit runner.
"""
import datetime as dt
import hashlib
import json
import os
import pathlib
import signal
import sqlite3
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = pathlib.Path(__file__).resolve().parent
DB = BASE / 'jobs.sqlite3'
TARGETS = BASE / 'authorized-repositories.txt'
REPORTS = BASE / 'reports'
REPORTS.mkdir(exist_ok=True)
STOP = False

def shutdown(*_):
    global STOP
    STOP = True

signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)

conn = sqlite3.connect(DB)
conn.execute('PRAGMA journal_mode=WAL')
conn.execute('CREATE TABLE IF NOT EXISTS targets (repo TEXT PRIMARY KEY, last_sha TEXT, last_checked TEXT, last_error TEXT, change_count INTEGER DEFAULT 0)')
conn.execute('CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, repo TEXT, old_sha TEXT, new_sha TEXT, discovered TEXT, report_path TEXT)')
conn.commit()

INTERVAL = max(300, int(os.getenv('AUTOHACK_MONITOR_INTERVAL', '900')))
TOKEN = os.getenv('GITHUB_TOKEN', '')

def log(message):
    print(dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'), message, flush=True)

def manual_authorized_repos():
    if not TARGETS.exists():
        TARGETS.write_text('# One explicitly authorized public GitHub repository per line: owner/repo\n# Do not add repositories without checking the program scope and rules.\n')
    repos = []
    for raw in TARGETS.read_text().splitlines():
        value = raw.strip()
        if not value or value.startswith('#'):
            continue
        parts = value.split('/')
        if len(parts) != 2 or any(not p or not all(c.isalnum() or c in '-_.' for c in p) for p in parts):
            log(f'Ignoring malformed repository entry: {value!r}')
            continue
        repos.append(value)
    return list(dict.fromkeys(repos))

def immunefi_scoped_repos():
    import importlib.util
    path = BASE / 'immunefi' / 'allowlist.py'
    if not path.exists():
        return []
    spec = importlib.util.spec_from_file_location('immunefi_allowlist', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.scoped_repositories()

def authorized_repos():
    # Manual explicit approvals and automatically discovered, fresh, exact
    # Immunefi scope assets are separate sources for passive monitoring only.
    return list(dict.fromkeys(manual_authorized_repos() + immunefi_scoped_repos()))

def fetch(repo):
    url = 'https://api.github.com/repos/' + '/'.join(urllib.parse.quote(p, safe='') for p in repo.split('/'))
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'AutoHack-authorized-monitor/1.0', 'X-GitHub-Api-Version': '2022-11-28'}
    if TOKEN:
        headers['Authorization'] = 'Bearer ' + TOKEN
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=20) as response:
        obj = json.load(response)
    branch = obj.get('default_branch')
    if not branch:
        raise ValueError('No default branch returned')
    url = 'https://api.github.com/repos/' + '/'.join(urllib.parse.quote(p, safe='') for p in repo.split('/')) + '/commits/' + urllib.parse.quote(branch, safe='')
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as response:
        commit = json.load(response)
    sha = commit.get('sha')
    if not sha or len(sha) < 12:
        raise ValueError('Invalid commit SHA')
    return sha, branch, commit.get('html_url', '')

def inspect(repo):
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
    old = conn.execute('SELECT last_sha FROM targets WHERE repo=?', (repo,)).fetchone()
    try:
        sha, branch, link = fetch(repo)
        old_sha = old[0] if old else None
        if old_sha and old_sha != sha:
            event_id = hashlib.sha256(f'{repo}\0{old_sha}\0{sha}'.encode()).hexdigest()[:24]
            report = REPORTS / (event_id + '.json')
            payload = {'repository': repo, 'branch': branch, 'previous_commit': old_sha, 'current_commit': sha, 'commit_url': link, 'observed_at': now, 'status': 'change_detected', 'note': 'Passive change signal only. No vulnerability has been established.'}
            report.write_text(json.dumps(payload, indent=2) + '\n')
            conn.execute('INSERT OR IGNORE INTO events (id,repo,old_sha,new_sha,discovered,report_path) VALUES (?,?,?,?,?,?)', (event_id, repo, old_sha, sha, now, str(report)))
            log(f'Change detected: {repo} {old_sha[:10]} -> {sha[:10]}')
        conn.execute('INSERT INTO targets(repo,last_sha,last_checked,last_error,change_count) VALUES(?,?,?,?,?) ON CONFLICT(repo) DO UPDATE SET last_sha=excluded.last_sha,last_checked=excluded.last_checked,last_error=NULL,change_count=targets.change_count+?', (repo, sha, now, None, 1 if old and old[0] != sha else 0, 1 if old and old[0] != sha else 0))
        conn.commit()
        log(f'Checked {repo}: {sha[:12]}')
    except (urllib.error.URLError, ValueError, TimeoutError, OSError) as exc:
        conn.execute('INSERT INTO targets(repo,last_checked,last_error) VALUES(?,?,?) ON CONFLICT(repo) DO UPDATE SET last_checked=excluded.last_checked,last_error=excluded.last_error', (repo, now, str(exc)))
        conn.commit()
        log(f'Check failed {repo}: {exc}')

def main():
    log('Started. Passive authorized repository monitoring; no exploitation or submission.')
    while not STOP:
        repos = authorized_repos()
        if not repos:
            log(f'No authorized repositories configured in {TARGETS}; waiting.')
        for repo in repos:
            if STOP:
                break
            inspect(repo)
            for _ in range(5):
                if STOP:
                    break
                time.sleep(1)
        deadline = time.monotonic() + INTERVAL
        while not STOP and time.monotonic() < deadline:
            time.sleep(min(1, max(0.01, deadline - time.monotonic())))
    log('Stopped cleanly.')

if __name__ == '__main__':
    try:
        main()
    finally:
        conn.close()
