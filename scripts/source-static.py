#!/usr/bin/env python3
"""Offline bounded static lead collection inside bubblewrap."""
import argparse
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
STATIC_LIMITATION = (
    'Detectors produce advisory candidates, not verified findings. '
    'Inspect and independently reproduce before reporting.'
)


def user_thread_count(proc=Path('/proc'), uid=None):
    """Linux RLIMIT_NPROC counts *all* threads of the real UID, not sandbox children."""
    uid = os.getuid() if uid is None else uid
    total = 0
    try:
        for entry in proc.iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                status = (entry / 'status').read_text()
                fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
                real_uid = int(fields['Uid'].split()[0])
                if real_uid == uid:
                    total += max(1, int(fields['Threads'].strip()))
            except (OSError, ValueError, KeyError):
                continue
    except OSError:
        return None
    return total or None


def scanner_nproc_limit():
    """Allow 64 scanner tasks beyond the current UID load, respecting host limits."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    existing = user_thread_count()
    desired = max(64, existing + 64 if existing is not None else 512)
    for inherited in (soft, hard):
        if inherited != resource.RLIM_INFINITY:
            desired = min(desired, inherited)
    return desired


def scanner_as_limit(slither=False):
    """Node.js + WASM solc reserves >2 GiB virtual address space; bound safely."""
    desired = (32 if slither else 2) * 1024**3
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    for inherited in (soft, hard):
        if inherited != resource.RLIM_INFINITY:
            desired = min(desired, inherited)
    return desired


def limits(slither=False):
    cpu_seconds = 90 if slither else 45
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    as_limit = scanner_as_limit(slither=slither) if slither else 2 * 1024**3
    resource.setrlimit(resource.RLIMIT_AS, (as_limit, as_limit))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024**2, 8 * 1024**2))
    nproc = scanner_nproc_limit()
    resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _prepare_slither_locked_imports(repository, source, sol_targets):
    """Materialize locked npm Solidity imports needed by Slither targets."""
    lock_path = repository / 'package-lock.json'
    if not lock_path.is_file() or lock_path.is_symlink():
        return
    try:
        if lock_path.stat().st_size > 4 * 1024 * 1024:
            return
        lock = json.loads(lock_path.read_bytes())
    except (OSError, ValueError):
        return
    packages = lock.get('packages')
    if lock.get('lockfileVersion') not in (2, 3) or not isinstance(packages, dict):
        return
    locked_pkgs = [k[13:] for k in packages if isinstance(k, str) and k.startswith('node_modules/') and k[13:]]
    if not locked_pkgs:
        return
    visited = set()
    queue = list(sol_targets[:24])
    raw_imports = set()
    import_re = re.compile(r'^\s*import\s+(?:[^"\';]*?\s+from\s+)?["\']([^"\']+)["\']\s*;', re.M)
    while queue and len(visited) < 256:
        rel = queue.pop(0)
        if rel in visited:
            continue
        visited.add(rel)
        f = source / rel
        if not f.is_file():
            continue
        try:
            text = f.read_text(errors='replace')[:256000]
        except OSError:
            continue
        for imp in import_re.findall(text):
            if imp.startswith('.'):
                try:
                    resolved = (f.parent / imp).resolve()
                    if resolved.is_relative_to(source) and resolved.is_file():
                        sub_rel = resolved.relative_to(source).as_posix()
                        if sub_rel not in visited:
                            queue.append(sub_rel)
                except OSError:
                    continue
            else:
                raw_imports.add(imp)
    missing = []
    for imp in sorted(raw_imports):
        if (repository / 'node_modules' / imp).is_file():
            continue
        if any(imp == pkg or imp.startswith(pkg + '/') for pkg in locked_pkgs):
            missing.append(imp)
    if not missing:
        return
    try:
        sys.path.insert(0, str(ROOT / 'scripts'))
        from source_dependencies import prepare_dependencies
        prepare_dependencies(repository, missing[:64])
    except Exception:
        return


def detect_solc_pkg(source_text):
    """Return pinned reproduction-runtime solc package matching pragma."""
    match = re.search(r'\bpragma\s+solidity\s+([^;]+);', source_text)
    pragma = match.group(1).strip() if match else ''
    if re.search(r'\b0\.5\.', pragma) or (re.search(r'>=\s*0\.5\.', pragma) and not re.search(r'>=\s*0\.[678]\.', pragma)):
        return 'solc_0_5'
    if re.search(r'\b0\.6\.', pragma) or (re.search(r'>=\s*0\.6\.', pragma) and not re.search(r'>=\s*0\.[78]\.', pragma)):
        return 'solc_0_6'
    if re.search(r'\b0\.7\.', pragma) or (re.search(r'>=\s*0\.7\.', pragma) and not re.search(r'>=\s*0\.8\.', pragma)):
        return 'solc_0_7'
    if re.search(r'(?:^|=\s*|\^\s*)0\.8\.[0-4]\b', pragma) or re.search(r'<\s*0\.8\.[5-9]\b', pragma):
        return 'solc_0_8_4'
    return 'solc'


def compiler_for_source(source_text, root=ROOT):
    """Choose the matching installed compiler for the target pragma (compat helper)."""
    pkg = detect_solc_pkg(source_text)
    if pkg != 'solc':
        candidate = root / 'scripts' / 'reproduction-runtime' / 'node_modules' / pkg / 'bin' / 'solcjs'
        if candidate.is_file():
            return str(candidate)
    fallback = root / '.venv-static' / 'solc-0.8.30'
    if fallback.is_file():
        return str(fallback)
    solc_js = root / 'scripts' / 'reproduction-runtime' / 'node_modules' / 'solc' / 'bin' / 'solcjs'
    return str(solc_js) if solc_js.is_file() else None


def _slither_severity(impact):
    norm = str(impact or '').strip().lower()
    if norm in ('high', 'critical'):
        return 'ERROR'
    if norm == 'medium':
        return 'WARNING'
    if norm in ('low', 'informational', 'optimization'):
        return 'INFO'
    return 'WARNING'


def analyze(repository, engine, target=None, targets=None):
    repository = Path(repository).resolve()
    runtime = ROOT / '.venv-static'
    binary = runtime / 'bin' / ('semgrep' if engine == 'semgrep' else 'slither')
    if not binary.is_file():
        return {'status': 'unavailable', 'reason': 'Run scripts/install-static-analysis.sh', 'leads': [], 'detectedLeads': 0, 'limitation': STATIC_LIMITATION}
    if not shutil.which('bwrap'):
        return {'status': 'blocked_no_sandbox', 'leads': [], 'detectedLeads': 0, 'limitation': STATIC_LIMITATION}
    paths = subprocess.check_output(['git', '-c', 'core.hooksPath=/dev/null', 'ls-files', '-z'], cwd=repository, timeout=10).decode().split('\0')
    with tempfile.TemporaryDirectory(prefix='static-leads-') as temporary:
        tmp_path = Path(temporary)
        source = tmp_path / 'source'
        source.mkdir()
        size = 0
        copied = 0
        skipped = 0
        for name in paths[:10000]:
            if not name:
                continue
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
        # Preserve untracked declarative remappings if present
        repo_remappings = repository / 'remappings.txt'
        if repo_remappings.is_file() and not repo_remappings.is_symlink() and not (source / 'remappings.txt').exists():
            if repo_remappings.resolve().is_relative_to(repository) and repo_remappings.stat().st_size <= 256000:
                shutil.copyfile(repo_remappings, source / 'remappings.txt')

        base_command = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--cap-drop', 'ALL', '--clearenv']
        for folder in ('/usr', '/bin', '/lib', '/lib64'):
            if Path(folder).exists():
                base_command += ['--ro-bind', folder, folder]
        interpreter = (runtime / 'bin' / 'python').resolve(strict=True)
        python_prefix = Path(sys.base_prefix).resolve()
        if not interpreter.is_relative_to(python_prefix):
            return {'status': 'unavailable', 'reason': 'Virtualenv interpreter is outside the Python installation', 'leads': [], 'detectedLeads': 0, 'limitation': STATIC_LIMITATION}
        if not any(python_prefix.is_relative_to(Path(folder)) for folder in ('/usr', '/bin', '/lib', '/lib64')):
            base_command += ['--ro-bind', str(python_prefix), str(python_prefix)]

        repro_runtime = ROOT / 'scripts' / 'reproduction-runtime'
        runtime_deps = repro_runtime / 'node_modules'
        node_bin = shutil.which('node')
        if runtime_deps.is_dir():
            base_command += ['--ro-bind', str(runtime_deps), '/runtime-node-modules']
        if repro_runtime.is_dir():
            base_command += ['--ro-bind', str(repro_runtime), '/repro-runtime']
        if node_bin:
            base_command += ['--ro-bind', str(Path(node_bin).resolve()), '/probe-node']

        wrapper_dir = tmp_path / 'solc-wrapper'
        wrapper_dir.mkdir()
        wrapper_bin = wrapper_dir / 'solc'
        wrapper_bin.write_text('#!/bin/sh\nexec /probe-node /repro-runtime/solc-cli.cjs "$@"\n', encoding='utf8')
        wrapper_bin.chmod(0o755)

        base_command += [
            '--ro-bind', str(runtime), str(runtime),
            '--ro-bind', str(source), '/repo',
        ]
        if engine == 'slither':
            pre_targets = []
            if targets is not None:
                if isinstance(targets, str):
                    try:
                        parsed = json.loads(targets)
                        if isinstance(parsed, list):
                            pre_targets = [t for t in parsed if isinstance(t, str)]
                    except ValueError:
                        pre_targets = []
                elif isinstance(targets, (list, tuple)):
                    pre_targets = [t for t in targets if isinstance(t, str)]
            elif target:
                pre_targets = [target]
            _prepare_slither_locked_imports(repository, source, pre_targets)
        # Bind untracked node_modules / lib from repository for Solidity import resolution
        for dep_dir_name in ('node_modules', 'lib'):
            dep_dir = repository / dep_dir_name
            if dep_dir.is_dir() and not dep_dir.is_symlink() and dep_dir.resolve().is_relative_to(repository) and not (source / dep_dir_name).exists():
                base_command += ['--ro-bind', str(dep_dir.resolve()), '/repo/' + dep_dir_name]

        base_command += [
            '--ro-bind', str(wrapper_dir), '/solc-wrapper',
            '--ro-bind', str(ROOT / 'scripts/static-leads.yaml'), '/rules.yaml',
            '--ro-bind', str(ROOT / 'scripts/vendor/semgrep-rules'), '/vendor-rules',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/home',
            '--setenv', 'HOME', '/home',
            '--setenv', 'PATH', str(runtime / 'bin') + ':/solc-wrapper:/usr/bin:/bin',
            '--setenv', 'SEMGREP_SEND_METRICS', 'off',
            '--setenv', 'SEMGREP_ENABLE_VERSION_CHECK', '0',
            '--setenv', 'PYTHONNOUSERSITE', '1',
            '--chdir', '/repo',
        ]

        if engine == 'semgrep':
            command = [
                *base_command,
                str(binary),
                'scan', '--config', '/rules.yaml', '--config', '/vendor-rules',
                '--json', '--metrics=off', '--disable-version-check', '--jobs=1', '--max-memory=512', '--timeout=5', '/repo'
            ]
            try:
                with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                    run = subprocess.run(command, stdout=out, stderr=err, timeout=90, preexec_fn=limits)
                    out.seek(0)
                    raw = out.read(8 * 1024**2)
                    err.seek(0)
                    diagnostic = err.read(1000).decode('utf-8', errors='replace').strip() or raw[:1000].decode('utf-8', errors='replace').strip()
                    try:
                        data = json.loads(raw)
                    except ValueError:
                        return {
                            'status': 'failed', 'reason': 'Scanner returned no valid JSON',
                            'exitCode': run.returncode, 'diagnostic': diagnostic, 'leads': [],
                            'detectedLeads': 0, 'limitation': STATIC_LIMITATION,
                        }
            except (subprocess.TimeoutExpired, ValueError, OSError) as error:
                return {'status': 'failed', 'reason': type(error).__name__, 'leads': [], 'detectedLeads': 0, 'limitation': STATIC_LIMITATION}

            leads = []
            for item in data.get('results', []):
                leads.append({
                    'path': item.get('path', '').removeprefix('/repo/'),
                    'line': item.get('start', {}).get('line'),
                    'rule': item.get('check_id'),
                    'message': str(item.get('extra', {}).get('message', ''))[:300],
                    'severity': item.get('extra', {}).get('severity', 'INFO'),
                })
            leads = [
                lead for lead in leads
                if isinstance(lead['path'], str) and not Path(lead['path']).is_absolute()
                and '..' not in Path(lead['path']).parts and isinstance(lead['line'], int) and lead['line'] > 0
            ]
            leads.sort(key=lambda lead: ({'ERROR': 0, 'WARNING': 1}.get(lead.get('severity'), 2), lead['path'], lead['line']))
            complete = run.returncode == 0 and not data.get('errors') and data.get('success', True)
            return {
                'status': 'completed' if complete else 'partial',
                'complete': False,
                'detectedLeads': len(leads),
                'coverage': {
                    'copiedFiles': copied, 'skippedSizeFiles': skipped,
                    'filesBeyondLimit': max(0, len(paths) - 10000),
                },
                'leads': leads[:128],
                'limitation': STATIC_LIMITATION,
            }

        # Slither engine
        raw_targets = []
        if targets is not None:
            if isinstance(targets, str):
                try:
                    parsed_targets = json.loads(targets)
                    if isinstance(parsed_targets, list):
                        raw_targets = [t for t in parsed_targets if isinstance(t, str)]
                except ValueError:
                    raw_targets = []
            elif isinstance(targets, (list, tuple)):
                raw_targets = [t for t in targets if isinstance(t, str)]
        elif target:
            raw_targets = [target]

        valid_targets = []
        for t in raw_targets[:24]:
            try:
                resolved_t = (source / t).resolve()
            except OSError:
                continue
            if not resolved_t.is_relative_to(source) or not resolved_t.is_file() or not t.endswith('.sol'):
                continue
            valid_targets.append(t)

        if not valid_targets:
            return {'status': 'unsupported_target', 'leads': [], 'detectedLeads': 0, 'limitation': STATIC_LIMITATION}

        leads = []
        completed_runs = 0
        unavailable_runs = 0
        failed_runs = 0
        all_clean = True
        last_error = None
        last_exit = None
        started = time.monotonic()

        for t in valid_targets:
            if time.monotonic() - started > 75:
                all_clean = False
                break
            target_text = (source / t).read_text(errors='replace')
            pkg = detect_solc_pkg(target_text)
            native_0_8_30 = runtime / 'solc-0.8.30'
            use_native = (pkg == 'solc' and native_0_8_30.is_file())
            has_shim = bool(node_bin and (repro_runtime / 'solc-cli.cjs').is_file() and (runtime_deps / pkg).is_dir())
            if not use_native and not has_shim:
                unavailable_runs += 1
                all_clean = False
                continue

            solc_path = str(native_0_8_30) if use_native else '/solc-wrapper/solc'
            env_args = ['--setenv', 'TOMEY_SOLC_PKG', pkg] if not use_native else []
            solc_extra_args = []
            if use_native and (repository / 'node_modules').is_dir():
                solc_extra_args = ['--solc-args', '--base-path /repo --include-path /repo/node_modules --allow-paths /repo,/repo/node_modules']

            command = [
                *base_command,
                *env_args,
                str(binary),
                '/repo/' + t,
                '--compile-force-framework', 'solc',
                '--solc', solc_path,
                *solc_extra_args,
                '--json', '-',
                '--disable-color',
            ]
            try:
                with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                    run = subprocess.run(command, stdout=out, stderr=err, timeout=45, preexec_fn=lambda: limits(slither=True))
                    out.seek(0)
                    raw = out.read(8 * 1024**2)
                    err.seek(0)
                    diagnostic = err.read(1000).decode('utf-8', errors='replace').strip() or raw[:1000].decode('utf-8', errors='replace').strip()
                    try:
                        data = json.loads(raw)
                    except ValueError:
                        failed_runs += 1
                        all_clean = False
                        last_error = diagnostic
                        last_exit = run.returncode
                        continue
            except (subprocess.TimeoutExpired, ValueError, OSError) as error:
                failed_runs += 1
                all_clean = False
                last_error = type(error).__name__
                continue

            completed_runs += 1
            if run.returncode != 0 or data.get('errors') or not data.get('success', True):
                all_clean = False
            for item in data.get('results', {}).get('detectors', [])[:32]:
                sev = _slither_severity(item.get('impact'))
                for element in item.get('elements', [])[:2]:
                    mapping = element.get('source_mapping', {})
                    rel_path = str(mapping.get('filename_relative') or mapping.get('filename_absolute') or '').removeprefix('/repo/')
                    if not rel_path:
                        rel_path = t
                    leads.append({
                        'path': rel_path,
                        'line': (mapping.get('lines') or [0])[0],
                        'rule': item.get('check'),
                        'message': str(item.get('description', ''))[:300],
                        'severity': sev,
                    })

        if completed_runs == 0:
            if unavailable_runs > 0 and failed_runs == 0:
                return {'status': 'unavailable_compiler', 'reason': 'No installed solc matches the target pragma', 'leads': [], 'detectedLeads': 0, 'limitation': STATIC_LIMITATION}
            return {
                'status': 'failed',
                'reason': 'Scanner returned no valid JSON',
                **({'exitCode': last_exit} if last_exit is not None else {}),
                **({'diagnostic': last_error} if last_error else {}),
                'leads': [],
                'detectedLeads': 0,
                'limitation': STATIC_LIMITATION,
            }

        seen = set()
        deduped = []
        for lead in leads:
            if not (isinstance(lead['path'], str) and not Path(lead['path']).is_absolute()
                    and '..' not in Path(lead['path']).parts and isinstance(lead['line'], int) and lead['line'] > 0):
                continue
            key = (lead['path'], lead['line'], lead['rule'])
            if key in seen:
                continue
            seen.add(key)
            deduped.append(lead)
        deduped.sort(key=lambda lead: ({'ERROR': 0, 'WARNING': 1}.get(lead.get('severity'), 2), lead['path'], lead['line']))
        return {
            'status': 'completed' if all_clean else 'partial',
            'complete': False,
            'detectedLeads': len(deduped),
            'coverage': {
                'copiedFiles': copied, 'skippedSizeFiles': skipped,
                'filesBeyondLimit': max(0, len(paths) - 10000),
            },
            'leads': deduped[:128],
            'limitation': STATIC_LIMITATION,
        }


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--repository', required=True)
    parser.add_argument('--engine', choices=['semgrep', 'slither'], required=True)
    parser.add_argument('--target')
    parser.add_argument('--targets')
    args = parser.parse_args()
    print(json.dumps(analyze(args.repository, args.engine, args.target, args.targets)))
