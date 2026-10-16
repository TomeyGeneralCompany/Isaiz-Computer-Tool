#!/usr/bin/env python3
"""Autonomous offline evidence compiler for existing AutoHack workers.
Never executes repository code, generated commands, exploits, or remote tests.
Never claims a security defect is verified without an independent reproduction.
"""
import ast, datetime as dt, hashlib, json, os, pathlib, re, signal, subprocess, time, traceback
ROOT=pathlib.Path(__file__).resolve().parents[1]
INV=ROOT/'investigator'
BASE=ROOT/'autonomous'
SCOPE=ROOT/'immunefi/scope.json'
DRAFTS=INV/'triage/drafts'
VER=INV/'verification/results'
REPRO=INV/'reproduction/results'
REPOS=INV/'repos'
OUT=BASE/'evidence'
REPORTS=BASE/'reports'
STATE=BASE/'state'
for p in (OUT,REPORTS,STATE): p.mkdir(parents=True,exist_ok=True)
STOP=False
signal.signal(signal.SIGTERM,lambda *_: globals().__setitem__('STOP',True))
signal.signal(signal.SIGINT,lambda *_: globals().__setitem__('STOP',True))
REPO_RE=re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
SHA_RE=re.compile(r'^[a-f0-9]{40}$')

def now(): return dt.datetime.now(dt.timezone.utc).isoformat()
def read(path):
    try: return json.loads(path.read_text())
    except (OSError,ValueError): return None

def atomic(path,data):
    tmp=path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data,indent=2,ensure_ascii=False,sort_keys=True)+'\n')
    os.replace(tmp,path)

def atomic_text(path,text):
    tmp=path.with_suffix('.tmp')
    tmp.write_text(text)
    os.replace(tmp,path)

def scope():
    data=read(SCOPE)
    if not isinstance(data,dict) or data.get('permission')!='passive_github_metadata_only': return {}
    try:
        expiry=dt.datetime.fromisoformat(data['valid_until'].replace('Z','+00:00'))
        if expiry.tzinfo is None or expiry<=dt.datetime.now(dt.timezone.utc): return {}
    except (ValueError,TypeError,KeyError): return {}
    return data.get('repositories',{}) if isinstance(data.get('repositories'),dict) else {}

def git_head(root):
    try:
        p=subprocess.run(['git','-c','core.hooksPath=/dev/null','rev-parse','HEAD'],cwd=root,capture_output=True,text=True,timeout=6,check=False)
        return p.stdout.strip() if p.returncode==0 else None
    except (OSError,subprocess.TimeoutExpired): return None

def file_evidence(draft):
    repo=draft.get('repository'); sha=draft.get('commit'); lead=draft.get('lead')
    if not isinstance(lead,dict) or not isinstance(repo,str) or not REPO_RE.fullmatch(repo) or not isinstance(sha,str) or not SHA_RE.fullmatch(sha):
        return {'status':'invalid_location'}
    rel=lead.get('file'); line=lead.get('line')
    if not isinstance(rel,str) or not isinstance(line,int) or line<1: return {'status':'invalid_location'}
    root=(REPOS/repo.replace('/','__')).resolve()
    file=(root/rel).resolve()
    if not file.is_relative_to(root) or file.is_symlink() or not file.is_file(): return {'status':'source_unavailable'}
    if file.stat().st_size>500_000: return {'status':'source_too_large'}
    head=git_head(root)
    if head!=sha: return {'status':'commit_mismatch','expected':sha,'actual':head}
    lines=file.read_text(errors='replace').splitlines()
    if line>len(lines): return {'status':'line_out_of_range'}
    start=max(0,line-12); end=min(len(lines),line+12)
    snippet='\n'.join(f'{i+1:>5}: {lines[i][:350]}' for i in range(start,end))
    result={'status':'source_matched','file':rel,'line':line,'file_sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'excerpt':snippet,'commit':head}
    if file.suffix=='.py':
        try: ast.parse(file.read_text(errors='replace')); result['python_syntax']='valid'
        except SyntaxError as exc: result['python_syntax']='invalid: '+str(exc)[:150]
    return result

def classification(draft):
    tri=draft.get('triage')
    return tri.get('classification','insufficient_context') if isinstance(tri,dict) else 'insufficient_context'

def write_package(path, data, current_scope, verification):
    repo=data.get('repository'); sha=data.get('commit'); lead=data.get('lead')
    if not isinstance(repo,str) or repo not in current_scope or not REPO_RE.fullmatch(repo): return 'skipped_out_of_scope'
    if not isinstance(sha,str) or not SHA_RE.fullmatch(sha): return 'skipped_invalid_commit'
    if not isinstance(lead,dict): return 'skipped_invalid_lead'
    fingerprint=hashlib.sha256(path.read_bytes()).hexdigest()
    dest=OUT/(path.stem+'.json')
    existing=read(dest)
    if isinstance(existing,dict) and existing.get('source_fingerprint')==fingerprint and existing.get('source_check',{}).get('status')=='source_matched':
        return 'unchanged'
    evidence=file_evidence(data)
    cls=classification(data)
    scope_urls=sorted(set(x.get('scope_url','') for x in current_scope[repo] if isinstance(x,dict) and isinstance(x.get('scope_url'),str)))
    checks={'in_scope_at_processing':True,'source_commit_matches':evidence.get('status')=='source_matched',
            'triage_requires_review':cls=='needs_review','has_reproduction_test':False}
    result={'source_fingerprint':fingerprint,'repository':repo,'commit':sha,'lead':lead,
            'triage':data.get('triage'),'scope_urls':scope_urls,'source_check':evidence,
            'checks':checks,'status':'needs_project_specific_reproduction' if evidence.get('status')=='source_matched' else 'blocked_missing_exact_source',
            'verified_vulnerability':False,'processed_at':now(),
            'note':'Automated offline evidence preparation only. No project-specific reproduction or verified security impact.'}
    atomic(dest,result)
    if cls=='needs_review' and evidence.get('status')=='source_matched':
        md=['# Investigation candidate (unverified)','',f'**Repository:** `{repo}`',f'**Commit:** `{sha}`',
            f'**Rule:** `{lead.get("rule","unknown")}`',f'**Location:** `{lead.get("file","?")}:{lead.get("line","?")}`',
            '**Status:** Requires a project-specific regression test and security-impact demonstration.','',
            '## Scope references',*(f'- {url}' for url in scope_urls),'',
            '## Source evidence','```',evidence['excerpt'],'```','',
            '## Automated triage',str((data.get('triage') or {}).get('rationale',''))[:1200],'',
            '## Remaining proof obligations','- Establish an actual violated security property.',
            '- Build an isolated project-specific regression test.',
            '- Demonstrate reproducible security impact on the exact in-scope version.',
            '- Recheck current program eligibility and reporting requirements.','']
        atomic_text(REPORTS/(path.stem+'.md'),'\n'.join(md))
    return result['status']

def main():
    print(now(),'Autonomous evidence compiler running; no remote testing or submissions',flush=True)
    while not STOP:
        try:
            valid=scope()
            stats={'scope_repositories':len(valid),'drafts_seen':0,'evidence_ready':0,'blocked':0,'unverified':0,
                   'verification_records':len(list(VER.glob('*.json'))),'reproduction_records':len(list(REPRO.glob('*.json'))),
                   'generated_at':now(),'service':'active','verified_vulnerabilities':0}
            if valid:
                for draft_path in sorted(DRAFTS.glob('*.json')):
                    if STOP: break
                    draft=read(draft_path)
                    if not isinstance(draft,dict): continue
                    stats['drafts_seen']+=1
                    outcome=write_package(draft_path,draft,valid,stats)
                    if outcome in ('needs_project_specific_reproduction','unchanged'): stats['evidence_ready']+=1
                    else: stats['blocked']+=1
                    stats['unverified']+=1
            else:
                stats['warning']='Scope missing or expired; evidence processing paused'
            atomic(STATE/'status.json',stats)
            print(now(),json.dumps(stats,sort_keys=True),flush=True)
        except Exception as exc:
            print(now(),'Cycle failed:',repr(exc),traceback.format_exc(limit=2),flush=True)
        for _ in range(90):
            if STOP: break
            time.sleep(1)
    print(now(),'Stopped',flush=True)
if __name__=='__main__': main()
