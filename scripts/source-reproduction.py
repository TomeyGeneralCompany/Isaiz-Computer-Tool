#!/usr/bin/env python3
"""Bounded offline probes of Python, JavaScript and Solidity source functions in bubblewrap.

A probe confirms only its named behavior, never complete exploitability.
No model-generated commands or scripts are executed. Source code runs only
inside a fresh, network-isolated namespace with resource limits.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import tempfile

PROBE = r'''
import contextlib, importlib.util, io, json, os, pathlib, sys, resource
resource.setrlimit(resource.RLIMIT_NPROC,(0,0))
specification=json.loads(pathlib.Path('/spec.json').read_text())
file=pathlib.Path('/repo',specification['file']).resolve()
if not file.is_relative_to('/repo'): raise ValueError('Source outside repository')
sys.path[:0]=['/repo',str(file.parent)]
control='TOMEY_CONTROL_'+specification['nonce']
attack=('<em data-tomey="'+specification['nonce']+'">TOMEY_PROBE</em>'
        if specification['kind']=='html_reflection' else '../../TOMEY_ESCAPE_'+specification['nonce'])
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    module_spec=importlib.util.spec_from_file_location('autohack_probe_target',str(file))
    module=importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    function=getattr(module,specification['function'])
    normal=function(control)
    observed=function(attack)
if not isinstance(normal,str) or not isinstance(observed,str): raise ValueError('Probe requires string return values')
if len(normal)>16000 or len(observed)>16000: raise ValueError('Probe output too large')
print(json.dumps({'control_input':control,'control_output':normal,'attack_input':attack,'attack_output':observed}))
'''

def limits(node=False):
    resource.setrlimit(resource.RLIMIT_CPU,(15,15))
    resource.setrlimit(resource.RLIMIT_AS,((32 if node else 1)*1024**3,)*2)
    resource.setrlimit(resource.RLIMIT_FSIZE,(1024**2,1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))


def run_probe(repository: Path, specification: dict) -> dict:
    repository=repository.resolve(strict=True)
    if not repository.is_dir(): raise ValueError('Repository directory required')
    file=specification.get('file','')
    function=specification.get('function','')
    kind=specification.get('kind','')
    nonce=specification.get('nonce','')
    if not isinstance(file,str) or len(file)>4096 or Path(file).suffix not in ('.py','.js','.mjs','.cjs','.sol'): raise ValueError('Python, JavaScript or Solidity source path required')
    target=(repository/file).resolve(strict=True)
    if not target.is_relative_to(repository) or not target.is_file() or target.stat().st_size>256000: raise ValueError('Source outside repository or too large')
    if not isinstance(function,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,79}(?:\.[A-Za-z][A-Za-z0-9_]{0,79})?',function): raise ValueError('Public top-level function name required')
    if kind not in ('html_reflection','path_construction'): raise ValueError('Unsupported probe kind')
    if not isinstance(nonce,str) or not re.fullmatch(r'[a-f0-9]{32}',nonce): raise ValueError('Invalid probe nonce')
    language = 'python' if file.endswith('.py') else 'solidity' if file.endswith('.sol') else 'javascript'
    if language != 'solidity' and '.' in function: raise ValueError('Top-level function name required')
    runtime = Path(__file__).resolve().parent / 'reproduction-runtime'
    node = shutil.which('node') if language != 'python' else None
    if language != 'python' and not node:
        return {'status':'blocked_no_runtime','behavior_observed':False,'detail':'Node.js is required'}
    if language == 'solidity' and not all((runtime/'node_modules'/name).is_dir() for name in ('solc','ethers','ganache')):
        return {'status':'blocked_no_runtime','behavior_observed':False,'detail':'Run npm install --prefix scripts/reproduction-runtime'}
    sandbox=shutil.which('bwrap')
    if not sandbox: return {'status':'blocked_no_sandbox','behavior_observed':False}
    source_hash=hashlib.sha256(target.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='autohack-reproduction-') as temporary:
        work=Path(temporary)
        (work/'probe.py').write_text(PROBE)
        (work/'spec.json').write_text(json.dumps(specification))
        runtime_binds = [] if language == 'python' else [
            '--ro-bind',str(Path(node).resolve()),'/probe-node',
            '--ro-bind',str(runtime),'/runtime']
        invocation = ['/usr/bin/python3','-I','/probe.py'] if language == 'python' else [
            '/probe-node','--disable-wasm-trap-handler','--max-old-space-size=256','/runtime/probe.cjs']
        command=[sandbox,'--unshare-all','--die-with-parent','--new-session','--cap-drop','ALL','--clearenv',
                 '--ro-bind','/usr','/usr','--ro-bind','/lib','/lib','--ro-bind-try','/lib64','/lib64',
                 '--proc','/proc','--dev','/dev','--tmpfs','/tmp','--ro-bind',str(repository),'/repo',
                 '--ro-bind',str(work/'probe.py'),'/probe.py','--ro-bind',str(work/'spec.json'),'/spec.json',
                 '--chdir','/repo','--setenv','PATH','/usr/bin:/bin','--setenv','HOME','/tmp',
                 '--setenv','PYTHONNOUSERSITE','1','--setenv','PYTHONDONTWRITEBYTECODE','1',
                 *runtime_binds,'--',*invocation]
        with (work/'stdout').open('wb') as output,(work/'stderr').open('wb') as error:
            process=subprocess.Popen(command,stdout=output,stderr=error,env={'PATH':'/usr/bin:/bin'},
                                     start_new_session=True,preexec_fn=lambda: limits(language != 'python'))
            try: code=process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait()
                return {'status':'timeout','behavior_observed':False}
            finally:
                try: os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError: pass
        if code:
            return {'status':'probe_failed','behavior_observed':False,'exit_code':code,
                    'detail':(work/'stderr').read_text(errors='replace')[-1200:]}
        if hashlib.sha256(target.read_bytes()).hexdigest()!=source_hash: raise ValueError('Source changed during probe')
        data=json.loads((work/'stdout').read_text())
        normal,observed=data['control_output'],data['attack_output']
        if kind=='html_reflection':
            matches=data['control_input'] in normal and data['attack_input'] in observed
        else:
            # Path construction alone is not proof of an exploitable file operation.
            base=Path(os.path.normpath(normal)).parent
            attack_path=Path(os.path.normpath(observed))
            matches=normal.endswith(data['control_input']) and attack_path.name=='TOMEY_ESCAPE_'+nonce and not attack_path.is_relative_to(base)
        return {'status':'behavior_observed' if matches else 'behavior_not_observed',
                'behavior_observed':matches,'source_sha256':source_hash,'kind':kind,'observations':data,
                'limitation':'A local function behavior is not sufficient to establish a reportable vulnerability; call-site reachability, mitigations, policy and impact require independent review.'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository',required=True)
    parser.add_argument('--spec',required=True)
    args=parser.parse_args()
    try: result=run_probe(Path(args.repository),json.loads(Path(args.spec).read_text()))
    except (OSError,ValueError,TypeError,KeyError) as error:
        result={'status':'invalid_probe','behavior_observed':False,'detail':str(error)[:500]}
    print(json.dumps(result))
    return 0 if result['behavior_observed'] else 1

if __name__=='__main__': raise SystemExit(main())
