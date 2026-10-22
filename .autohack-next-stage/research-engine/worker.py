#!/usr/bin/env python3
"""Continuous, local, isolated security regression research. No production target access.
LLM output is untrusted. Running tests is permitted ONLY inside a locked-down local
container with a preinstalled image, no network, no host secrets, and bounded resources.
A generated test passing is NOT by itself proof of a vulnerability.
"""
import fcntl
import datetime, hashlib, json, os, pathlib, re, shutil, signal, subprocess, tempfile, time, urllib.request
ROOT=pathlib.Path(os.environ.get('AUTOHACK_ROOT',str(pathlib.Path(__file__).resolve().parents[2])))
STAGE=ROOT/'.autohack-next-stage'; INV=STAGE/'investigator'; BASE=STAGE/'research-engine'
DRAFTS=INV/'triage/drafts'; REPOS=INV/'repos'; SCOPE=STAGE/'immunefi/scope.json'
OUT=BASE/'results'; REPORTS=BASE/'reports'; CASES=BASE/'cases'; STATE=BASE/'state'
for d in (OUT,REPORTS,CASES,STATE): d.mkdir(parents=True,exist_ok=True)
STOP=False
signal.signal(signal.SIGTERM,lambda *_: globals().__setitem__('STOP',True))
signal.signal(signal.SIGINT,lambda *_: globals().__setitem__('STOP',True))
REPO_RE=re.compile(r'^[\w.-]+/[\w.-]+$'); SHA_RE=re.compile(r'^[0-9a-f]{40}$')
CONFIG=BASE/'config.json'
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def read(p):
    try: return json.loads(p.read_text())
    except (OSError,ValueError): return None
def write(p,obj):
    t=p.with_suffix('.tmp'); t.write_text(json.dumps(obj,indent=2,sort_keys=True,ensure_ascii=False)+'\n'); os.replace(t,p)
def config():
    d=read(CONFIG) or {}; return d if isinstance(d,dict) else {}
def scoped():
    s=read(SCOPE)
    if not isinstance(s,dict) or s.get('permission')!='passive_github_metadata_only': return {}
    try:
        exp=datetime.datetime.fromisoformat(s['valid_until'].replace('Z','+00:00'))
        if exp<=datetime.datetime.now(datetime.timezone.utc): return {}
    except (KeyError,ValueError,TypeError): return {}
    r=s.get('repositories',{})
    return r if isinstance(r,dict) else {}
def location(lead):
    if not isinstance(lead,dict): return None,None
    path=next((lead[k] for k in ('file','path','file_path','filename','source_file') if isinstance(lead.get(k),str)),None)
    line=next((lead[k] for k in ('line','line_number','start_line') if lead.get(k) is not None),None)
    try: line=int(line)
    except (ValueError,TypeError): line=None
    return path,line
def repo_path(repo):
    for p in (REPOS/repo.replace('/','__'), REPOS/repo.split('/')[1], REPOS/repo):
        if p.is_dir() and (p/'.git').exists(): return p.resolve()
    return None
def git_commit(p):
    try:
        r=subprocess.run(['git','-c','core.hooksPath=/dev/null','rev-parse','HEAD'],cwd=p,capture_output=True,text=True,timeout=6)
        return r.stdout.strip() if r.returncode==0 else None
    except (OSError,subprocess.TimeoutExpired): return None
def ollama(prompt,model):
    payload=json.dumps({'model':model,'stream':False,'format':'json','options':{'temperature':0,'num_predict':1100},'prompt':prompt}).encode()
    req=urllib.request.Request('http://127.0.0.1:11434/api/generate',payload,{'Content-Type':'application/json'})
    # Shared with TypeScript assessment/hunt/review requests, across processes.
    lock_path=ROOT/'data/ollama-inference.lock'
    lock_path.parent.mkdir(parents=True,exist_ok=True)
    with lock_path.open('a') as lock:
        deadline=time.monotonic()+600
        while True:
            if STOP: raise RuntimeError('Research worker stopping while queued for inference')
            try:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic()>=deadline: raise TimeoutError('Ollama inference queue timed out')
                time.sleep(0.1)
        with urllib.request.urlopen(req,timeout=100) as r: raw=json.load(r)
    return json.loads(raw.get('response','{}'))
def docker_engine():
    for exe in ('podman','docker'):
        if shutil.which(exe):
            try:
                r=subprocess.run([exe,'info'],capture_output=True,timeout=8)
                if r.returncode==0: return exe
            except (OSError,subprocess.TimeoutExpired): pass
    return None
def image_available(engine,image):
    try: return subprocess.run([engine,'image','inspect',image],capture_output=True,timeout=10).returncode==0
    except (OSError,subprocess.TimeoutExpired): return False
def isolated_run(engine,image,repo,case_name,test_source):
    # No shell execution on the host. Never mount host home, credentials or docker socket.
    # Existing local container image only; no pull, no network, read-only rootfs, no capabilities.
    with tempfile.TemporaryDirectory(prefix='autohack-case-') as td:
        case=pathlib.Path(td); (case/'GeneratedSecurityTest.t.sol').write_text(test_source)
        cmd=[engine,'run','--rm','--pull=never','--network=none','--read-only',
             '--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=96',
             '--memory=700m','--cpus=1','--user=65534:65534',
             '--tmpfs','/tmp:rw,nosuid,nodev,size=512m',
             '--mount',f'type=bind,src={repo},dst=/src,readonly',
             '--mount',f'type=bind,src={case},dst=/cases,readonly',
             '--workdir','/src','--entrypoint','forge',image,
             'test','--offline','--no-match-contract','^$', '--match-path','/cases/GeneratedSecurityTest.t.sol','-vv']
        # Foundry expects tests inside the project. We therefore copy a bounded snapshot into
        # a writable tmpfs inside the container, never modifying the host repository.
        # Use a fixed, reviewed entrypoint script, not an LLM-supplied command.
        script='set -eu; cp -a /src/. /tmp/work/; mkdir -p /tmp/work/test; cp /cases/GeneratedSecurityTest.t.sol /tmp/work/test/AutoHackGenerated.t.sol; cd /tmp/work; forge test --offline --match-path test/AutoHackGenerated.t.sol -vv'
        cmd=cmd[:cmd.index('--entrypoint')]+['--entrypoint','/bin/sh',image,'-c','mkdir -p /tmp/work; '+script]
        try:
            p=subprocess.run(cmd,capture_output=True,text=True,timeout=110)
            return {'exit_code':p.returncode,'stdout_tail':p.stdout[-7000:],'stderr_tail':p.stderr[-5000:]}
        except subprocess.TimeoutExpired: return {'status':'timeout'}
        except OSError as e: return {'status':'execution_error','reason':str(e)[:250]}
def generate_test(draft,source,model):
    lead=draft.get('lead',{}); tri=draft.get('triage',{})
    prompt=('You are writing a defensive OFFLINE Solidity Foundry regression test for an authorized open-source repository. '
            'Return ONLY a JSON object with keys test_source (Solidity source) and security_property (one sentence). '
            'The test must be self-contained, must not use ffi, RPC, forks, HTTP, shell, cheatcodes that access external systems, or external dependencies. '
            'Use Solidity >=0.8.0; import and exercise the ACTUAL target contract from the repository; test contract named AutoHackSecurityTest and a function testSecurityProperty(). '
            'Do not claim a vulnerability is proven. If context is insufficient return {"test_source":"","security_property":"insufficient context"}. '
            'Repository lead: '+json.dumps(lead,ensure_ascii=False)[:1800]+'\nTriage: '+json.dumps(tri,ensure_ascii=False)[:1500]+'\nSource:\n'+source[:11000])
    result=ollama(prompt,model)
    return result if isinstance(result,dict) else {}
def report(draft,status,detail,source_file):
    lead=draft.get('lead',{})
    return ('# AutoHack research report (UNVERIFIED)\n\n'
            f"Repository: {draft.get('repository')}\n\nCommit: {draft.get('commit')}\n\n"
            f"Source: {source_file}\n\nOutcome: **{status}**\n\n"
            '## Hypothesis\n\n'+json.dumps(lead,indent=2,ensure_ascii=False)[:4500]+'\n\n'
            '## Reproduction result\n\n'+json.dumps(detail,indent=2,ensure_ascii=False)[:6000]+'\n\n'
            '## Disclosure\n\nNot submission-ready. Generated tests and their outcomes require '
            'independent validation of the security property, exploitability, impact and program scope.\n')
def process(path,cfg,scope,engine):
    raw=path.read_bytes(); digest=hashlib.sha256(raw+b'|research-engine-v1').hexdigest()
    result_path=OUT/(path.stem+'.json')
    old=read(result_path)
    if isinstance(old,dict) and old.get('input_hash')==digest and old.get('status') not in ('blocked_missing_container','blocked_missing_image','model_unavailable','source_unavailable'):
        return old.get('status','unknown')
    draft=read(path); status='inconclusive'; detail={}; source_file=''
    repo=draft.get('repository') if isinstance(draft,dict) else None
    sha=draft.get('commit') if isinstance(draft,dict) else None
    if not isinstance(repo,str) or not REPO_RE.fullmatch(repo) or repo not in scope:
        status='out_of_scope'
    elif not isinstance(sha,str) or not SHA_RE.fullmatch(sha): status='invalid_commit'
    else:
        root=repo_path(repo)
        if root is None: status='source_unavailable'; detail={'reason':'No local Git clone; no automatic remote fetch'}
        elif git_commit(root)!=sha: status='commit_mismatch'; detail={'actual':git_commit(root),'expected':sha}
        else:
            rel,line=location(draft.get('lead'))
            file=(root/rel).resolve() if isinstance(rel,str) else None
            if file is None or not file.is_relative_to(root) or not file.is_file() or file.is_symlink() or file.stat().st_size>500000:
                status='source_unavailable'; detail={'reason':'No valid bounded local source file'}
            else:
                source_file=rel; lines=file.read_text(errors='replace').splitlines(); start=max(0,(line or 1)-90); end=min(len(lines),(line or 1)+90)
                source='\n'.join(f'{i+1}: {lines[i]}' for i in range(start,end))
                if file.suffix!='.sol': status='adapter_not_available'; detail={'language':file.suffix,'note':'Solidity Foundry adapter only in this release'}
                elif not engine: status='blocked_missing_container'
                elif not image_available(engine,cfg['foundry_image']): status='blocked_missing_image'; detail={'required_preloaded_image':cfg['foundry_image']}
                else:
                    try: generated=generate_test(draft,source,cfg['model'])
                    except Exception as e: generated={}; status='model_unavailable'; detail={'error':str(e)[:250]}
                    if status!='model_unavailable':
                        test=generated.get('test_source','')
                        if not isinstance(test,str) or not (100<=len(test)<=18000) or 'contract AutoHackSecurityTest' not in test or 'function testSecurityProperty' not in test:
                            status='insufficient_test_context'
                        elif 'import ' not in test or pathlib.Path(source_file).stem not in test:
                            status='test_not_targeting_source'
                        elif re.search(r'(?i)\b(ffi|vm\.fork|createFork|rpcUrl|http[s]?://|stdCheats|process\.run)\b',test):
                            status='unsafe_test_rejected'
                        else:
                            case=CASES/(path.stem+'.sol'); case.write_text(test)
                            run=isolated_run(engine,cfg['foundry_image'],root,path.stem,test)
                            detail={'test_case':str(case),'security_property':generated.get('security_property',''), 'execution':run}
                            status='test_executed_needs_security_review' if 'exit_code' in run else 'test_execution_inconclusive'
    record={'source_draft':str(path),'input_hash':digest,'repository':repo,'commit':sha,'status':status,
            'verified_vulnerability':False,'submitted':False,'detail':detail,'processed_at':now()}
    write(result_path,record)
    (REPORTS/(path.stem+'.md')).write_text(report(draft or {},status,detail,source_file))
    print(f'{path.name}: {status}',flush=True)
    return status
def main():
    print('AutoHack offline research engine started. No automatic submission or live tests.',flush=True)
    while not STOP:
        cfg=config(); cfg.setdefault('model','qwen3:0.6b'); cfg.setdefault('foundry_image','ghcr.io/foundry-rs/foundry:stable')
        scope=scoped(); engine=docker_engine()
        counts={}
        try:
            for p in sorted(DRAFTS.glob('*.json')):
                if STOP: break
                try: status=process(p,cfg,scope,engine)
                except Exception as e:
                    status='worker_exception'; print(p.name,repr(e),flush=True)
                counts[status]=counts.get(status,0)+1
            write(STATE/'status.json',{'checked_at':now(),'scope_repositories':len(scope),'container_engine':engine,
                                       'foundry_image_available':bool(engine and image_available(engine,cfg['foundry_image'])),
                                       'counts':counts,'submission_enabled':False})
        except Exception as e: print('Cycle error:',repr(e),flush=True)
        for _ in range(60):
            if STOP: break
            time.sleep(1)
if __name__=='__main__': main()
