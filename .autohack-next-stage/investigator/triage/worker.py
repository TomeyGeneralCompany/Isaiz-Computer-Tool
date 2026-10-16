#!/usr/bin/env python3
"""Persistent, bounded contextual review of AutoHack static leads.
No target interaction, execution of repository code, vulnerability confirmation or submissions.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sqlite3
import time
import urllib.request

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
REPORTS = BASE/'reports'
REPOS = BASE/'repos'
SCOPE = BASE.parent/'immunefi'/'scope.json'
OUT = HERE/'drafts'
OUT.mkdir(exist_ok=True)
DB = HERE/'triage.sqlite3'
STOP = False
signal.signal(signal.SIGTERM, lambda *_: globals().__setitem__('STOP', True))
signal.signal(signal.SIGINT, lambda *_: globals().__setitem__('STOP', True))
MODEL = os.getenv('AUTOHACK_TRIAGE_MODEL','qwen3:4b')
OLLAMA = 'http://127.0.0.1:11434/api/chat'
INTERVAL = max(60,int(os.getenv('AUTOHACK_TRIAGE_INTERVAL','120')))
MAX_PER_CYCLE = max(1,min(20,int(os.getenv('AUTOHACK_TRIAGE_PER_CYCLE','6'))))
MAX_SOURCE = 5000
REPO_RE = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')

def log(*args): print(dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'),*args,flush=True)

def fresh_scope():
    try:
        obj=json.loads(SCOPE.read_text())
        if obj.get('permission')!='passive_github_metadata_only': return {}
        exp=dt.datetime.fromisoformat(obj['valid_until'].replace('Z','+00:00'))
        if exp.tzinfo is None or exp<=dt.datetime.now(dt.timezone.utc): return {}
        return obj.get('repositories',{}) if isinstance(obj.get('repositories'),dict) else {}
    except (OSError,ValueError,KeyError,TypeError): return {}

def valid_report(p, scope):
    try:
        data=json.loads(p.read_text())
        repo=data.get('repository')
        if not isinstance(repo,str) or not REPO_RE.fullmatch(repo) or repo not in scope: return None
        if data.get('inspection')!='local_static_heuristics': return None
        if not isinstance(data.get('potential_review_leads'),list): return None
        if not isinstance(data.get('commit'),str) or not re.fullmatch('[a-f0-9]{40}',data['commit']): return None
        return data
    except (OSError,ValueError,TypeError): return None

def context_for(repo,sha,lead):
    if not isinstance(lead,dict): return None
    rel=lead.get('file'); line=lead.get('line')
    if not isinstance(rel,str) or not isinstance(line,int) or line<1: return None
    root=REPOS/repo.replace('/','__')
    path=(root/rel).resolve()
    if not path.is_relative_to(root.resolve()) or path.is_symlink() or not path.is_file(): return None
    if path.stat().st_size>350000: return None
    # Match the exact reported commit; the checkout may change between cycles.
    try:
        head=subprocess.run(['git','-c','core.hooksPath=/dev/null','rev-parse','HEAD'],
            cwd=root,capture_output=True,text=True,timeout=6,check=False)
        if head.returncode != 0 or head.stdout.strip() != sha: return None
    except (OSError,subprocess.TimeoutExpired): return None
    # Repo can still update during reading; this is triage, not verified evidence.
    lines=path.read_text(errors='replace').splitlines()
    lo=max(0,line-9); hi=min(len(lines),line+8)
    return '\n'.join(f'{i+1}: {lines[i][:400]}' for i in range(lo,hi))[:MAX_SOURCE]

def review(repo,lead,context):
    payload={'model':MODEL,'stream':False,'think':False,'format':'json','options':{'num_ctx':3072,'num_predict':380,'temperature':0},
      'messages':[{'role':'system','content':'You review static-analysis leads in publicly listed bug-bounty source code. Respond with one JSON object with keys classification, rationale, evidence, follow_up. classification must be one of needs_review, likely_false_positive, insufficient_context. Be skeptical. Never claim exploitability or verified vulnerabilities. Do not provide exploitation steps. Rationale and evidence must be short.'},
                  {'role':'user','content':json.dumps({'repository':repo,'rule':lead.get('rule'),'guidance':lead.get('guidance'),'file':lead.get('file'),'line':lead.get('line'),'source_excerpt':context})}]}
    request=urllib.request.Request(OLLAMA,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=180) as response:
        raw=json.load(response)
    output=json.loads(raw['message']['content'])
    if not isinstance(output,dict): raise ValueError('AI output not object')
    classification=output.get('classification','insufficient_context')
    if classification not in ('needs_review','likely_false_positive','insufficient_context'): classification='insufficient_context'
    return {'classification':classification,'rationale':str(output.get('rationale',''))[:900],'evidence':str(output.get('evidence',''))[:900],'follow_up':str(output.get('follow_up',''))[:900]}

def main():
    conn=sqlite3.connect(DB)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('CREATE TABLE IF NOT EXISTS processed (id TEXT PRIMARY KEY, status TEXT, attempts INTEGER, retry_after REAL, result_path TEXT, last_error TEXT)')
    conn.commit()
    log('Triage worker started; source-only review; no verification or submissions')
    try:
        while not STOP:
            scope=fresh_scope()
            done=0
            if not scope: log('Scope cache absent/expired; waiting')
            for report in sorted(REPORTS.glob('*.json')):
                if STOP or done>=MAX_PER_CYCLE or not scope: break
                data=valid_report(report,scope)
                if not data: continue
                repo=data['repository']; sha=data['commit']
                for lead in data['potential_review_leads'][:100]:
                    if STOP or done>=MAX_PER_CYCLE: break
                    if not isinstance(lead,dict): continue
                    key=hashlib.sha256(json.dumps([repo,sha,lead],sort_keys=True).encode()).hexdigest()
                    row=conn.execute('SELECT status,attempts,retry_after FROM processed WHERE id=?',(key,)).fetchone()
                    if row and (row[0]=='done' or (row[2] or 0)>time.time()): continue
                    if repo not in fresh_scope(): break
                    context=context_for(repo,sha,lead)
                    if not context:
                        result={'classification':'insufficient_context','rationale':'Source excerpt unavailable; requires review','evidence':'','follow_up':'Check local repository snapshot'}
                    else:
                        try: result=review(repo,lead,context)
                        except Exception as exc:
                            attempts=(row[1] if row else 0)+1
                            delay=min(21600,60*(2**min(attempts,8)))
                            conn.execute('INSERT INTO processed(id,status,attempts,retry_after,last_error) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,attempts=excluded.attempts,retry_after=excluded.retry_after,last_error=excluded.last_error',(key,'retry',attempts,time.time()+delay,str(exc)[:300])); conn.commit()
                            log('AI unavailable; retry scheduled:',str(exc)[:150]); done+=1; continue
                    draft={'repository':repo,'commit':sha,'scope_sources':data['scope_sources'],'original_report':report.name,'lead':lead,'source_excerpt':context,'triage':result,'status':'unverified_draft','verified_vulnerability':False,'generated_at':dt.datetime.now(dt.timezone.utc).isoformat(),'note':'Automated static triage only. No exploitability, eligibility, or bounty award established.'}
                    target=OUT/(key+'.json'); temp=OUT/(key+'.tmp')
                    temp.write_text(json.dumps(draft,indent=2)+'\n'); os.replace(temp,target)
                    conn.execute('INSERT INTO processed(id,status,attempts,retry_after,result_path,last_error) VALUES(?,?,?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET status=excluded.status,retry_after=0,result_path=excluded.result_path,last_error=NULL',(key,'done',1,0,str(target)))
                    conn.commit(); done+=1
                    log('Draft',repo,lead.get('rule','unknown'),result['classification'])
            for _ in range(INTERVAL):
                if STOP: break
                time.sleep(1)
    finally:
        conn.close(); log('Triage stopped')

if __name__=='__main__': main()
