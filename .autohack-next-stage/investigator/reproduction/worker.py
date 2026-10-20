#!/usr/bin/env python3
"""Offline evidence queue. Executes only explicitly defined local test cases in a sandbox.
No remote testing, generated exploits, or automatic vulnerability assertions.
"""
import hashlib, json, os, pathlib, shutil, subprocess, tempfile, time, datetime
ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = ROOT / 'reproduction'
INPUT = ROOT / 'verification/results'
RESULTS = BASE / 'results'
CASES = BASE / 'cases'
for p in (RESULTS, CASES): p.mkdir(parents=True, exist_ok=True)

def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def atomic(path, obj):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n')
    os.replace(tmp, path)
def fingerprint(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def run_case(spec):
    # A case must be explicitly configured with a local fixture and an expected assertion.
    # The worker never executes AI-generated commands or downloads target code.
    fixture = pathlib.Path(str(spec.get('fixture_dir', ''))).expanduser().resolve()
    if 'source_probe' in spec:
        if not fixture.is_dir() or not fixture.is_relative_to(CASES.resolve()):
            return {'status':'inconclusive', 'reason':'Fixture must be a local directory under reproduction/cases'}
        driver = pathlib.Path(__file__).resolve().parents[4] / 'scripts/source-reproduction.py'
        with tempfile.TemporaryDirectory(prefix='tomey-case-') as temporary:
            manifest = pathlib.Path(temporary) / 'spec.json'
            manifest.write_text(json.dumps(spec['source_probe']))
            try:
                result = subprocess.run(['/usr/bin/python3', str(driver), '--repository', str(fixture),
                                         '--spec', str(manifest)], capture_output=True, text=True, timeout=35)
                return json.loads(result.stdout)
            except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
                return {'status':'inconclusive', 'reason':str(exc)[:500]}
    args = spec.get('argv')
    if not isinstance(args, list) or not args or any(not isinstance(x, str) for x in args):
        return {'status':'inconclusive', 'reason':'Invalid argv in case manifest'}
    if not fixture.is_dir() or not fixture.is_relative_to(CASES.resolve()):
        return {'status':'inconclusive', 'reason':'Fixture must be a local directory under reproduction/cases'}
    if not shutil.which('bwrap'):
        return {'status':'blocked_no_sandbox', 'reason':'bubblewrap (bwrap) is required to execute local tests'}
    # Restrict executables to python3 in the isolated fixture; no shell.
    if args[0] not in ('python3', '/usr/bin/python3'):
        return {'status':'inconclusive', 'reason':'Only Python regression test commands are supported'}
    if len(args) > 8 or any(len(x)>256 for x in args):
        return {'status':'inconclusive', 'reason':'Arguments exceed safety limits'}
    cmd = ['bwrap','--unshare-all','--die-with-parent','--new-session',
           '--ro-bind','/usr','/usr','--ro-bind','/lib','/lib',
           '--ro-bind-try','/lib64','/lib64', '--proc','/proc','--dev','/dev',
           '--tmpfs','/tmp','--ro-bind',str(fixture),'/case','--chdir','/case',
           '--setenv','HOME','/tmp','--setenv','PYTHONDONTWRITEBYTECODE','1',
           '--setenv','PYTHONNOUSERSITE','1','--', '/usr/bin/python3'] + args[1:]
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=45, check=False)
    except subprocess.TimeoutExpired:
        return {'status':'inconclusive', 'reason':'Local test timed out (45s)'}
    except OSError as exc:
        return {'status':'inconclusive', 'reason':str(exc)}
    expected = spec.get('expected_exit_code', 0)
    return {'status':'test_passed' if p.returncode == expected else 'test_failed',
            'exit_code':p.returncode, 'expected_exit_code':expected,
            'stdout_tail':p.stdout[-3000:], 'stderr_tail':p.stderr[-3000:],
            'note':'A test result alone does not establish a vulnerability'}

def process(path):
    digest = fingerprint(path)
    out = RESULTS / (path.stem + '-' + digest[:12] + '.json')
    if out.exists(): return
    try: record = json.loads(path.read_text())
    except (ValueError, OSError) as exc:
        atomic(out, {'status':'inconclusive','reason':'Invalid verification JSON: '+str(exc), 'processed_at':now()}); return
    if record.get('status') != 'ready_for_isolated_reproduction':
        status, detail = 'not_ready', {'reason':'Verification record not marked ready'}
    else:
        case = CASES / (path.stem + '.json')
        if not case.exists():
            status, detail = 'awaiting_reproduction_case', {'reason':'No explicit local regression case supplied', 'case_manifest':str(case)}
        else:
            try: detail = run_case(json.loads(case.read_text()))
            except (ValueError, OSError) as exc: detail = {'status':'inconclusive','reason':str(exc)}
            status = detail['status']
    atomic(out, {'source_record':str(path), 'source_sha256':digest,
                 'repository':record.get('repository'), 'commit':record.get('commit'),
                 'status':status, 'test_result':detail, 'verified_vulnerability':False,
                 'processed_at':now()})
    print(f'{path.name}: {status}', flush=True)

def main():
    print('Offline reproduction queue started; only explicit sandboxed local cases can execute.', flush=True)
    while True:
        try:
            for path in sorted(INPUT.glob('*.json')):
                process(path)
        except Exception as exc:
            print('Worker error:', repr(exc), flush=True)
        time.sleep(60)
if __name__ == '__main__': main()
