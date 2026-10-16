#!/usr/bin/env python3
"""Autonomous bounded local source-code triage for fresh, explicitly listed Immunefi GitHub assets.

Fetches public source only. No remote probing, payload delivery, exploitation, or submissions.
Findings are *leads*, not established vulnerabilities. Requires program-policy review
before any active testing. Runs until stopped, persists progress, fails closed on stale scope.
"""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import time

BASE = Path(__file__).resolve().parent
STAGE = BASE.parent
SCOPE = STAGE / 'immunefi' / 'scope.json'
REPOS = BASE / 'repos'
REPORTS = BASE / 'reports'
DB = BASE / 'investigations.sqlite3'
for d in (REPOS, REPORTS): d.mkdir(exist_ok=True)
STOP = False
signal.signal(signal.SIGTERM, lambda *_: globals().__setitem__('STOP', True))
signal.signal(signal.SIGINT, lambda *_: globals().__setitem__('STOP', True))
REPO_PATTERN = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
INTERVAL = max(600, int(os.environ.get('AUTOHACK_INVESTIGATE_INTERVAL', '1800')))
MAX_REPOS = max(1, min(100, int(os.environ.get('AUTOHACK_INVESTIGATE_MAX_REPOS', '25'))))
MAX_FILES = 1500
MAX_FILE_BYTES = 350_000
MAX_TOTAL_BYTES = 35_000_000
MAX_FINDINGS = 100
SKIP_DIRS = {'.git','node_modules','vendor','dist','build','target','.next','.venv','venv','coverage','__pycache__','testdata','fixtures'}
EXTS = {'.py','.js','.jsx','.ts','.tsx','.sol','.go','.rs','.java','.sh','.yaml','.yml','.json','.toml'}
# High-signal heuristic leads. Never claim these prove exploitability.
RULES = [
 ('PY_SHELL_TRUE', re.compile(r'\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^\n]{0,240}\bshell\s*=\s*True'), '.py', 'Review shell invocation and whether any input is untrusted'),
 ('PY_EVAL', re.compile(r'(?<![\w.])(?:eval|exec)\s*\('), '.py', 'Review dynamic execution and input provenance'),
 ('JS_CHILD_EXEC', re.compile(r'\b(?:child_process\.)?exec(?:Sync)?\s*\('), '.js,.jsx,.ts,.tsx', 'Review command construction and input provenance'),
 ('JS_EVAL', re.compile(r'\beval\s*\('), '.js,.jsx,.ts,.tsx', 'Review dynamic JavaScript execution'),
 ('SOL_TX_ORIGIN', re.compile(r'\btx\.origin\b'), '.sol', 'Review authorization based on tx.origin'),
 ('SOL_DELEGATECALL', re.compile(r'\.delegatecall\s*\('), '.sol', 'Review delegatecall target and access control'),
 ('GO_INSECURE_TLS', re.compile(r'InsecureSkipVerify\s*:\s*true'), '.go', 'Review TLS certificate verification configuration'),
 ('PY_INSECURE_TLS', re.compile(r'\bverify\s*=\s*False\b'), '.py', 'Review TLS certificate verification configuration'),
]

def log(*msg): print(dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'), *msg, flush=True)

def scope_repos():
    try:
        doc = json.loads(SCOPE.read_text())
        if doc.get('permission') != 'passive_github_metadata_only': return {}
        expiry = dt.datetime.fromisoformat(doc['valid_until'].replace('Z','+00:00'))
        if expiry.tzinfo is None or expiry <= dt.datetime.now(dt.timezone.utc): return {}
        repos = doc.get('repositories')
        if not isinstance(repos, dict): return {}
        return {r: entries for r, entries in repos.items() if REPO_PATTERN.fullmatch(r) and isinstance(entries,list) and any(isinstance(e,dict) and e.get('scope_url','').startswith('https://immunefi.com/bug-bounty/') and e.get('asset_url','').rstrip('/') == 'https://github.com/'+r for e in entries)}
    except (OSError, KeyError, ValueError, TypeError, OverflowError): return {}

def git(*args, cwd=None, timeout=120):
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1')
    # Disable user/system git hooks and global URL rewrites; no local repo scripts run.
    env['GIT_CONFIG_GLOBAL'] = '/dev/null'
    proc = subprocess.run(['git','-c','core.hooksPath=/dev/null','-c','protocol.file.allow=never',*args],cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout,check=False)
    if proc.returncode: raise RuntimeError('git operation failed: '+proc.stderr[-250:])
    return proc.stdout.strip()

def get_source(repo, path):
    url = 'https://github.com/'+repo+'.git'
    fresh = not (path/'.git').is_dir()
    if fresh:
        if path.exists(): shutil.rmtree(path)
        git('clone','--quiet','--depth=1','--single-branch','--filter=blob:none','--no-checkout',url,str(path),timeout=150)
    else:
        origin = git('remote','get-url','origin',cwd=path)
        if origin != url: raise RuntimeError('repository remote does not match authorized source')
        git('fetch','--quiet','--depth=1','origin',timeout=150,cwd=path)
    # Read-only source snapshot; no build scripts or dependencies executed.
    head = git('rev-parse','HEAD' if fresh else 'FETCH_HEAD',cwd=path)
    git('checkout','--quiet','--force',head,cwd=path,timeout=150)
    return head

def scan(path):
    findings=[]; files=0; size=0; truncated=False
    for root, dirs, names in os.walk(path,followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not (Path(root)/d).is_symlink())
        for name in sorted(names):
            p=Path(root)/name
            if p.suffix.lower() not in EXTS or p.is_symlink() or not p.is_file(): continue
            stat=p.stat()
            if stat.st_size>MAX_FILE_BYTES: continue
            if files>=MAX_FILES or size+stat.st_size>MAX_TOTAL_BYTES:
                truncated=True; break
            files+=1; size+=stat.st_size
            try: content=p.read_text(encoding='utf-8',errors='replace')
            except OSError: continue
            for number,line in enumerate(content.splitlines(),1):
                if len(line)>5000: continue
                for rule,pattern,extensions,explanation in RULES:
                    if p.suffix.lower() not in extensions.split(','): continue
                    if pattern.search(line):
                        findings.append({'rule':rule,'file':str(p.relative_to(path)),'line':number,'guidance':explanation,'fingerprint':hashlib.sha256((rule+'\0'+str(p.relative_to(path))+'\0'+line.strip()).encode()).hexdigest()[:20]})
                        if len(findings)>=MAX_FINDINGS: return findings,files,size,True
        if truncated: break
    return findings,files,size,truncated

def main():
    conn=sqlite3.connect(DB)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('CREATE TABLE IF NOT EXISTS status (repo TEXT PRIMARY KEY, sha TEXT, last_attempt TEXT, last_error TEXT, report TEXT)')
    conn.commit()
    log('Investigator started; local public-source static triage only; no active target testing')
    try:
        while not STOP:
            scopes=scope_repos()
            if not scopes: log('No fresh, explicitly scoped Immunefi repositories; waiting')
            for repo in sorted(scopes)[:MAX_REPOS]:
                if STOP: break
                if repo not in scope_repos(): log('Scope expired; stopping cycle'); break
                local=REPOS / repo.replace('/','__')
                now=dt.datetime.now(dt.timezone.utc).isoformat()
                try:
                    sha=get_source(repo,local)
                    prior=conn.execute('SELECT sha FROM status WHERE repo=?',(repo,)).fetchone()
                    if prior and prior[0]==sha: continue
                    findings,files,total,truncated=scan(local)
                    payload={'repository':repo,'commit':sha,'checked_at':now,'scope_sources':scopes[repo],'inspection':'local_static_heuristics','files_examined':files,'bytes_examined':total,'truncated':truncated,'potential_review_leads':findings,'verified_vulnerabilities':0,'note':'Heuristic leads require contextual review; no vulnerability or bounty eligibility is established.'}
                    output=REPORTS / (repo.replace('/','__')+'-'+sha[:12]+'.json')
                    tmp=output.with_suffix('.tmp')
                    tmp.write_text(json.dumps(payload,indent=2)+'\n'); os.replace(tmp,output)
                    conn.execute('INSERT INTO status(repo,sha,last_attempt,last_error,report) VALUES(?,?,?,?,?) ON CONFLICT(repo) DO UPDATE SET sha=excluded.sha,last_attempt=excluded.last_attempt,last_error=NULL,report=excluded.report',(repo,sha,now,None,str(output)))
                    conn.commit()
                    log('Scanned',repo,sha[:12],f'{files} files, {len(findings)} review leads', '(truncated)' if truncated else '')
                except (RuntimeError, subprocess.TimeoutExpired, OSError, ValueError) as exc:
                    conn.execute('INSERT INTO status(repo,last_attempt,last_error) VALUES(?,?,?) ON CONFLICT(repo) DO UPDATE SET last_attempt=excluded.last_attempt,last_error=excluded.last_error',(repo,now,str(exc)[:500]))
                    conn.commit(); log('Skipped',repo,str(exc)[:180])
                for _ in range(2):
                    if STOP: break
                    time.sleep(1)
            end=time.monotonic()+INTERVAL
            while not STOP and time.monotonic()<end: time.sleep(min(1,end-time.monotonic()))
    finally:
        conn.close(); log('Investigator stopped')

if __name__=='__main__': main()
