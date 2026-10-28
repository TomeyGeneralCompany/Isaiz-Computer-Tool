#!/usr/bin/env python3
"""Offline, bounded navigation leads. Detectors never create report evidence."""
import argparse
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent

def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024**2, 8 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

def analyze(repository, engine, target=None):
    repository = Path(repository).resolve()
    runtime = ROOT / '.venv-static'
    binary = runtime / 'bin' / ('semgrep' if engine == 'semgrep' else 'slither')
    if not binary.is_file():
        return {'status': 'unavailable', 'reason': 'Run scripts/install-static-analysis.sh', 'leads': []}
    if not shutil.which('bwrap'):
        return {'status': 'blocked_no_sandbox', 'leads': []}
    paths = subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', 'ls-files', '-z'], cwd=repository, timeout=10).decode().split('\0')
    with tempfile.TemporaryDirectory(prefix='static-leads-') as temporary:
        source = Path(temporary) / 'source'
        source.mkdir()
        size = 0
        copied = 0
        skipped = 0
        for name in paths[:10000]:
            path = repository / name
            if path.suffix not in ('.py', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.java', '.sol'):
                continue
            if path.is_symlink() or not path.resolve().is_relative_to(repository) or not path.is_file():
                continue
            count = path.stat().st_size
            if count > 256000 or size + count > 30 * 1024**2:
                skipped += 1
                continue
            size += count
            copied += 1
            dest = source / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, dest)
        command = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--cap-drop', 'ALL', '--clearenv']
        for folder in ('/usr', '/bin', '/lib', '/lib64'):
            if Path(folder).exists():
                command += ['--ro-bind', folder, folder]
        command += ['--ro-bind', str(runtime), str(runtime), '--ro-bind', str(source), '/repo',
                    '--ro-bind', str(ROOT / 'scripts/static-leads.yaml'), '/rules.yaml',
                    '--ro-bind', str(ROOT / 'scripts/vendor/semgrep-rules'), '/vendor-rules',
                    '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/home',
                    '--setenv', 'HOME', '/home', '--setenv', 'PATH', str(runtime / 'bin') + ':/usr/bin:/bin',
                    '--setenv', 'SEMGREP_SEND_METRICS', 'off', '--setenv', 'SEMGREP_ENABLE_VERSION_CHECK', '0',
                    '--setenv', 'PYTHONNOUSERSITE', '1', '--chdir', '/repo', str(binary)]
        if engine == 'semgrep':
            command += ['scan', '--config', '/rules.yaml', '--config', '/vendor-rules', '--json', '--metrics=off', '--disable-version-check', '--jobs=1', '--max-memory=512', '--timeout=5', '/repo']
        else:
            if not target or not (source / target).resolve().is_relative_to(source) or not (source / target).is_file() or not target.endswith('.sol'):
                return {'status': 'unsupported_target', 'leads': []}
            compiler = runtime / 'solc-0.8.30'
            if not compiler.is_file():
                return {'status': 'unavailable_compiler', 'leads': []}
            command += ['/repo/' + target, '--compile-force-framework', 'solc', '--solc', str(compiler), '--json', '-', '--disable-color']
        try:
            # Files cap output without buffering arbitrary scanner output in memory.
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                run = subprocess.run(command, stdout=out, stderr=err, timeout=90, preexec_fn=limits)
                out.seek(0)
                raw = out.read(8 * 1024**2)
                err.seek(0)
                diagnostic = err.read(1000).decode('utf-8', errors='replace')
                try:
                    data = json.loads(raw)
                except ValueError:
                    return {'status': 'failed', 'reason': 'Scanner returned no valid JSON',
                            'exitCode': run.returncode, 'diagnostic': diagnostic, 'leads': []}
        except (subprocess.TimeoutExpired, ValueError, OSError) as error:
            return {'status': 'failed', 'reason': type(error).__name__, 'leads': []}
        leads = []
        if engine == 'semgrep':
            for item in data.get('results', []):
                leads.append({'path': item.get('path', '').removeprefix('/repo/'), 'line': item.get('start', {}).get('line'), 'rule': item.get('check_id'), 'message': str(item.get('extra', {}).get('message', ''))[:300], 'severity': item.get('extra', {}).get('severity', 'INFO')})
        else:
            for item in data.get('results', {}).get('detectors', [])[:32]:
                for element in item.get('elements', [])[:2]:
                    mapping = element.get('source_mapping', {})
                    leads.append({'path': str(mapping.get('filename_absolute', '')).removeprefix('/repo/'), 'line': (mapping.get('lines') or [0])[0], 'rule': item.get('check'), 'message': str(item.get('description', ''))[:300]})
        leads = [lead for lead in leads if isinstance(lead['path'], str) and not Path(lead['path']).is_absolute() and '..' not in Path(lead['path']).parts and isinstance(lead['line'], int) and lead['line'] > 0]
        leads.sort(key=lambda lead: ({'ERROR': 0, 'WARNING': 1}.get(lead.get('severity'), 2), lead['path'], lead['line']))
        complete = run.returncode == 0 and not data.get('errors') and data.get('success', True)
        return {'status': 'completed' if complete else 'partial', 'complete': False, 'coverage': {'copiedFiles': copied, 'skippedSizeFiles': skipped, 'filesBeyondLimit': max(0, len(paths) - 10000), 'scannerErrors': len(data.get('errors', [])), 'detectedLeads': len(leads)}, 'leads': leads[:64], 'limitation': 'Bounded navigation leads only; scanner output is not a verified finding. Source/size limits and tool coverage apply.'}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--repository', required=True)
    parser.add_argument('--engine', choices=['semgrep', 'slither'], required=True)
    parser.add_argument('--target')
    args = parser.parse_args()
    print(json.dumps(analyze(args.repository, args.engine, args.target)))
