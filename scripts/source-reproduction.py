#!/usr/bin/env python3
"""Bounded offline probes of Python, JavaScript, Java and Solidity source functions in bubblewrap.

A probe confirms only its named behavior, never complete exploitability.
No model-generated commands or scripts are executed. Source code runs only
inside a fresh, network-isolated namespace with resource limits.
"""
from __future__ import annotations
import argparse
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_dependencies import prepare_dependencies, prepare_pinned_foundry_submodules, prepare_locked_python_wheels, DependencyError
from solidity_access_evidence import authorization_transition_observed

SUPPORTED_EXECUTION_STATUS = {
    'behavior_observed',
    'behavior_not_observed',
    'observation_only',
    'unsupported_execution',
    'unsupported_dependencies',
    'invalid_probe',
    'probe_failed',
    'timeout',
    'blocked_no_runtime',
    'blocked_no_sandbox',
}

PROBE = r'''
import contextlib, importlib.util, io, json, os, pathlib, sys, resource, urllib.parse, re
resource.setrlimit(resource.RLIMIT_NPROC,(0,0))
specification=json.loads(pathlib.Path('/spec.json').read_text())
file=pathlib.Path('/repo',specification['file']).resolve()
if not file.is_relative_to('/repo'): raise ValueError('Source outside repository')
sys.path[:0]=['/repo/.tomey-python-deps','/repo',str(file.parent)]
control='TOMEY_CONTROL_'+specification['nonce']
attack=('<em data-tomey="'+specification['nonce']+'">TOMEY_PROBE</em>'
        if specification['kind'] in ('html_reflection','entry_html_reflection') else '../../TOMEY_ESCAPE_'+specification['nonce'])
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    module_spec=importlib.util.spec_from_file_location('autohack_probe_target',str(file))
    module=importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    function=getattr(module,specification['function'])
    if specification['kind']=='entry_html_reflection':
        entry_source=file.read_text()
        entry_keys=set(re.findall(r'\.get\(\s*["\']([A-Za-z_][A-Za-z0-9_-]{0,63})["\']\s*,',entry_source))
        if 'parse_qs' not in entry_source or len(entry_keys)!=1:
            raise ValueError('Unsupported or ambiguous Python request-parameter extraction')
        entry_parameter=next(iter(entry_keys))
        control_url='http://localhost/?'+entry_parameter+'='+urllib.parse.quote(control,safe='')
        attack_url='http://localhost/?'+entry_parameter+'='+urllib.parse.quote(attack,safe='')
        normal=function(control_url)
        observed=function(attack_url)
    else:
        normal=function(control)
        observed=function(attack)
if not isinstance(normal,str) or not isinstance(observed,str): raise ValueError('Probe requires string return values')
if len(normal)>16000 or len(observed)>16000: raise ValueError('Probe output too large')
print(json.dumps({'control_input':control,'control_output':normal,'attack_input':attack,'attack_output':observed,
  **({'entry_control_url':control_url,'entry_attack_url':attack_url,'entry_selector':specification['function'],'entry_parameter':entry_parameter}
     if specification['kind']=='entry_html_reflection' else {})}))
'''


def observed_non_deployer_state_transition(steps):
    """Prove only a replayable changed getter after a non-deployer send."""
    if not isinstance(steps, list):
        return False
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or step.get('operation') != 'send':
            continue
        if step.get('sender') not in (1, 2) or step.get('reverted') is not False or type(step.get('passed')) is not bool:
            continue
        before=next((v for v in reversed(steps[:index])
                     if isinstance(v,dict) and v.get('operation')=='observe'),None)
        after=next((v for v in steps[index+1:]
                    if isinstance(v,dict) and v.get('operation')=='observe' and before and
                    v.get('function')==before.get('function') and
                    v.get('sender')==before.get('sender')),None)
        if before and after and before.get('actual')!=after.get('actual'):
            return True
    return False


def execution_capability(repository: Path, file: str, function: str, kind: str) -> tuple[bool, str | None]:
    """Allow the implementation to execute the kinds it can actually construct.

    The repo now supports source-derived constructor/method sequences for Java and
    contract sequences for Solidity. Anything outside those supported execution
    families is reported as unsupported_execution rather than as a generic failed
    reproduction.
    """
    target = (repository / file).resolve(strict=True)
    if not target.is_relative_to(repository):
        return False, 'Probe source escapes repository'
    if not target.is_file() or target.stat().st_size > 256000:
        return False, 'Probe source is missing or too large'
    source = target.read_text(errors='replace')
    if file.endswith('.java'):
        parts = function.split('.')
        if len(parts) != 2:
            return False, f'Java probe target {function} must be Class.method'
        class_name, method_name = parts
        if kind == 'java_sequence':
            if not re.search(rf'\bclass\s+{re.escape(class_name)}\b', source):
                return False, f'Java class {class_name} is not declared in {file}'
            if not re.search(rf'\b(?:public|protected|private)?\s*(?:static\s+)?[A-Za-z0-9_<>,\[\]\s]+\s+{re.escape(method_name)}\s*\(', source):
                return False, f'Java method {method_name} is not declared in {file}'
            return True, None
        if not re.search(
            r'\b(?:public\s+)?(?:static\s+)?(?:final\s+)?'
            r'(?:String|byte\[\]|CharSequence|StringBuilder|StringBuffer|ByteBuffer|Path|File|URI|Object)\s+'
            + re.escape(method_name) + r'\s*\(\s*(?:final\s+)?'
            r'(?:String|byte\[\]|CharSequence|StringBuilder|StringBuffer|ByteBuffer|Path|File|URI|Object)'
            r'\s+[A-Za-z_$][\w$]*\s*\)',
            source,
            re.M,
        ):
            return False, f'Java method {function} is not supported by the current execution adapter'
        return True, None
    if file.endswith('.sol'):
        if kind == 'solidity_sequence':
            parts = function.split('.')
            if len(parts) != 2:
                return False, f'Solidity probe target {function} must be Contract.function'
            contract_name, method_name = parts
            if not re.search(rf'\bcontract\s+{re.escape(contract_name)}\b', source):
                return False, f'Solidity contract {contract_name} is not declared in {file}'
            if not re.search(rf'\bfunction\s+{re.escape(method_name)}\s*\(', source):
                return False, f'Solidity function {method_name} is not declared in {file}'
            return True, None
        return True, None
    return True, None


class MarkupMarker(HTMLParser):
    """Recognize the nonce-bearing probe element, not its byte-for-byte spelling."""
    def __init__(self, nonce):
        super().__init__(convert_charrefs=True)
        self.nonce = nonce.casefold()
        self.found = False
        self.raw_text = None

    def handle_starttag(self, tag, attrs):
        if self.raw_text:
            return
        if tag in {'script', 'style', 'textarea', 'title', 'xmp', 'iframe', 'noembed', 'noframes', 'plaintext'}:
            self.raw_text = tag
            return
        if tag == 'em' and any(name == 'data-tomey' and value is not None and value.casefold() == self.nonce for name, value in attrs):
            self.found = True

    def handle_endtag(self, tag):
        if tag == self.raw_text and tag != 'plaintext':
            self.raw_text = None


def reflected_markup(data, nonce):
    normal, observed = data['control_output'], data['attack_output']
    if data['control_input'].casefold() not in normal.casefold():
        return False
    attack_parser, control_parser = MarkupMarker(nonce), MarkupMarker(nonce)
    attack_parser.feed(observed)
    attack_parser.close()
    control_parser.feed(normal)
    control_parser.close()
    return attack_parser.found and not control_parser.found


def observed_nonincumbent_role_transition(data):
    """Recognize a replayable local role transition, not its security significance.

    The signer must differ from the incumbent; the recorded getter must change
    to that signer despite an expected-revert hypothesis. Independent review
    determines whether reassignment violated an actual security boundary.
    """
    if not isinstance(data,dict):
        return False
    accounts=data.get('accounts')
    steps=data.get('steps')
    if (not isinstance(accounts,list) or len(accounts)<3 or
            not isinstance(steps,list) or len(steps)<3):
        return False
    role_getter=re.compile(r'^(?:owner|operator|administrator|admin|governor|manager|controller)\(\)$',re.I)
    for before,change,after in zip(steps,steps[1:],steps[2:]):
        if (before.get('operation')!='observe' or
                change.get('operation')!='send' or
                after.get('operation')!='observe' or
                before.get('function')!=after.get('function') or
                not role_getter.fullmatch(str(before.get('function',''))) or
                change.get('reverted') is not False or
                change.get('passed') is not False):
            continue
        sender=change.get('sender')
        if type(sender) is not int or sender not in (1,2):
            continue
        incumbent=str(before.get('actual','')).lower()
        successor=str(after.get('actual','')).lower()
        attacker=str(accounts[sender]).lower()
        if (incumbent.startswith('0x') and len(incumbent)==42 and
                incumbent!=attacker and successor==attacker):
            return True
    return False


def limits(node=False, java=False):
    resource.setrlimit(resource.RLIMIT_CPU,(15,15))
    resource.setrlimit(resource.RLIMIT_AS,((32 if node else 4 if java else 1)*1024**3,)*2)
    resource.setrlimit(resource.RLIMIT_FSIZE,(1024**2,1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE,(64,64))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))


def foundry_settings(profile: dict) -> dict:
    """Translate only supported declarative compiler options, with strict types."""
    if not isinstance(profile, dict):
        raise ValueError('Invalid Foundry default profile')
    settings = {}
    for key in ('optimizer', 'via_ir'):
        if key in profile and type(profile[key]) is not bool:
            raise ValueError('Foundry ' + key + ' must be a boolean')
    runs = profile.get('optimizer_runs', 200)
    if type(runs) is not int or not 0 <= runs <= 4294967295:
        raise ValueError('Invalid Foundry optimizer_runs')
    if 'optimizer' in profile or 'optimizer_runs' in profile:
        settings['optimizer'] = {'enabled': profile.get('optimizer', False), 'runs': runs}
    if 'via_ir' in profile:
        settings['viaIR'] = profile['via_ir']
    return settings


def prepare_java_classpath(repository: Path, target: Path, destination: Path) -> list[str]:
    """Stage bounded, already-resolved Java dependency JARs for sandbox-only use.

    No target Gradle/Maven scripts run, and neither host cache nor network is
    exposed to the source verifier. Only existing regular ZIP/JAR artifacts
    matching an imported package are copied into the temporary sandbox.
    """
    import zipfile
    source = target.read_text(errors='replace')[:256000]
    imports = re.findall(r'^\s*import\s+(static\s+)?([\w.]+)(\.\*)?\s*;', source, re.M)
    if not imports:
        return []
    wanted = set()
    for static_keyword, item, wildcard in imports:
        if item.startswith(('java.', 'javax.', 'jdk.', 'sun.')) or wildcard:
            continue
        parts = item.split('.')
        if len(parts) >= 2:
            # Static imports name a member, not a class.
            wanted.add('/'.join(parts[:-1] if static_keyword else parts) + '.class')
    if not wanted:
        return []
    roots = [repository / 'lib', repository / 'libs', repository / 'vendor',
             repository / 'build' / 'libs', repository / 'target',
             Path.home() / '.gradle' / 'caches' / 'modules-2' / 'files-2.1',
             Path.home() / '.m2' / 'repository']
    destination.mkdir(mode=0o700)
    copied = []
    count = 0
    total = 0
    visited = 0
    for root in roots:
        if not root.is_dir() or root.is_symlink():
            continue
        for parent, dirs, files in os.walk(root, followlinks=False):
            visited += 1
            if visited > 10000 or len(copied) >= 96:
                return copied
            dirs[:] = sorted(d for d in dirs if not (Path(parent) / d).is_symlink())
            for name in sorted(files):
                if not name.endswith('.jar'):
                    continue
                count += 1
                if count > 3000 or len(copied) >= 96:
                    return copied
                jar = Path(parent) / name
                try:
                    if jar.is_symlink() or not jar.is_file():
                        continue
                    size = jar.stat().st_size
                    if not 0 < size <= 16 * 1024**2 or total + size > 192 * 1024**2:
                        continue
                    with zipfile.ZipFile(jar) as archive:
                        matched = wanted.intersection(archive.namelist())
                        if not matched:
                            continue
                    # In-repository JARs are already mounted at /repo.
                    # Avoid a second bind mount for them; cached host JARs
                    # must still be copied into the isolated dependency mount.
                    if jar.resolve().is_relative_to(repository):
                        copied.append('/repo/' + str(jar.relative_to(repository)))
                    else:
                        dest = destination / (str(len(copied)).zfill(3) + '.jar')
                        shutil.copyfile(jar, dest)
                        copied.append('/java-deps/' + dest.name)
                    total += size
                    wanted.difference_update(matched)
                    if not wanted:
                        return copied
                except (OSError, zipfile.BadZipFile, ValueError):
                    continue
    return copied


def run_probe(repository: Path, specification: dict, _dependency_round: int = 0) -> dict:
    repository=repository.resolve(strict=True)
    if not repository.is_dir(): raise ValueError('Repository directory required')
    file=specification.get('file','')
    function=specification.get('function','')
    kind=specification.get('kind','')
    nonce=specification.get('nonce','')
    if not isinstance(file,str) or len(file)>4096 or Path(file).suffix not in ('.py','.js','.mjs','.cjs','.sol','.java'): raise ValueError('Python, JavaScript, Java or Solidity source path required')
    target=(repository/file).resolve(strict=True)
    if not target.is_relative_to(repository) or not target.is_file() or target.stat().st_size>256000: raise ValueError('Source outside repository or too large')
    if not isinstance(function,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,79}(?:\.[A-Za-z][A-Za-z0-9_]{0,79})?',function): raise ValueError('Public top-level function name required')
    if kind not in ('html_reflection','entry_html_reflection','path_construction','solidity_sequence','java_sequence'): raise ValueError('Unsupported probe kind')
    if not isinstance(nonce,str) or not re.fullmatch(r'[a-f0-9]{32}',nonce): raise ValueError('Invalid probe nonce')
    language = 'python' if file.endswith('.py') else 'solidity' if file.endswith('.sol') else 'java' if file.endswith('.java') else 'javascript'
    if kind == 'entry_html_reflection' and (language not in ('python','javascript','java') or
            not re.search(r'(handler|controller|route|entry|server)',file,re.I) or
            not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,79}(?:\.[A-Za-z][A-Za-z0-9_]{0,79})?',function)):
        raise ValueError('Entry probe requires a supported handler method and source file')
    if language not in ('solidity','java') and '.' in function: raise ValueError('Top-level function name required')
    if kind == 'solidity_sequence':
        if language != 'solidity' or '.' not in function: raise ValueError('Solidity Contract.function required')
        sequence = specification.get('sequence')
        if not isinstance(sequence,dict) or len(json.dumps(sequence)) > 16000: raise ValueError('Invalid Solidity sequence')
    elif kind == 'java_sequence':
        if language != 'java' or '.' not in function: raise ValueError('Java Class.method required')
        sequence = specification.get('sequence')
        if not isinstance(sequence,dict) or len(json.dumps(sequence)) > 16000: raise ValueError('Invalid Java sequence')
        steps = sequence.get('steps')
        if not isinstance(steps,list) or not 1 <= len(steps) <= 12 or not any(
            isinstance(step,dict) and step.get('method') == function.split('.')[1] for step in steps):
            raise ValueError('Java sequence must invoke selected method')
    elif 'sequence' in specification: raise ValueError('Sequence requires sequence probe kind')

    supported, detail = execution_capability(repository, file, function, kind)
    if not supported:
        return {'status': 'unsupported_execution', 'behavior_observed': False, 'detail': detail or 'Target is not expressible by the current execution environment'}

    runtime = Path(__file__).resolve().parent / 'reproduction-runtime'
    node = shutil.which('node') if language in ('javascript','solidity') else None
    java_home = Path(shutil.which('javac')).resolve().parent.parent if shutil.which('javac') else None
    java_config_binds = []
    if language == 'java' and java_home:
        security_link = java_home / 'conf/security/java.security'
        if security_link.is_symlink():
            resolved_security = security_link.resolve()
            if resolved_security.is_relative_to('/etc/') and resolved_security.is_file():
                config_root = resolved_security.parent.parent
                if config_root.parent == Path('/etc'):
                    java_config_binds = ['--dir', '/etc', '--ro-bind', str(config_root), str(config_root)]
    if language == 'java' and (not java_home or not (java_home/'bin/java').is_file()):
        return {'status':'blocked_no_runtime','behavior_observed':False,'detail':'Run scripts/install-reproduction-runtime.sh to install a JDK'}
    if language in ('javascript','solidity') and not node:
        return {'status':'blocked_no_runtime','behavior_observed':False,'detail':'Node.js is required'}
    if language == 'solidity' and not all((runtime/'node_modules'/name).is_dir() for name in ('solc','ethers','ganache')):
        return {'status':'blocked_no_runtime','behavior_observed':False,'detail':'Run npm install --prefix scripts/reproduction-runtime'}
    sandbox=shutil.which('bwrap')
    if not sandbox: return {'status':'blocked_no_sandbox','behavior_observed':False}
    if language == 'javascript':
        try: prepare_dependencies(repository)
        except (DependencyError, OSError, ValueError) as error:
            return {'status':'unsupported_dependencies','behavior_observed':False,'detail':str(error)[:1000]}
    specification = {**specification, 'compilerSettings': {}}
    if language == 'solidity' and (repository/'foundry.toml').is_file():
        try:
            import tomllib
            config_file = (repository/'foundry.toml').resolve()
            if not config_file.is_relative_to(repository): raise ValueError('Foundry config outside repository')
            if config_file.stat().st_size > 256000: raise ValueError('Foundry config too large')
            profiles = tomllib.loads(config_file.read_text()).get('profile', {})
            if not isinstance(profiles, dict): raise ValueError('Invalid Foundry profiles')
            profile = profiles.get('default', {})
            settings = foundry_settings(profile)
            remappings = profile.get('remappings',[])
            if not isinstance(remappings,list) or any(not isinstance(x,str) for x in remappings):
                raise ValueError('Invalid Foundry remappings')
            specification = {**specification,'remappings':remappings,'compilerSettings':settings}
        except (ImportError, OSError, ValueError) as error:
            return {'status':'unsupported_dependencies','behavior_observed':False,'detail':str(error)[:1000]}
    source_hash=hashlib.sha256(target.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix='autohack-reproduction-') as temporary:
        work=Path(temporary)
        (work/'probe.py').write_text((runtime/('java-sequence.py' if kind == 'java_sequence' else 'java-probe.py')).read_text() if language == 'java' else PROBE)
        (work/'spec.json').write_text(json.dumps(specification))
        java_jars = prepare_java_classpath(repository,target,work/'java-deps') if language == 'java' else []
        # Controller-owned only: never accept a model-supplied classpath.
        specification = {**specification, 'javaClasspath': java_jars}
        (work/'spec.json').write_text(json.dumps(specification))
        java_dependency_bind = ['--ro-bind',str(work/'java-deps'),'/java-deps'] if language == 'java' else []
        runtime_binds = ['--ro-bind',str(java_home),'/jdk',*java_config_binds,'--ro-bind',str(runtime),'/runtime'] if language == 'java' else [] if language == 'python' else [
            '--ro-bind',str(Path(node).resolve()),'/probe-node',
            '--ro-bind',str(runtime),'/runtime']
        invocation = ['/usr/bin/python3','-I','/probe.py'] if language in ('python','java') else [
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
                                     start_new_session=True,preexec_fn=lambda: limits(language in ('javascript','solidity'),language == 'java'))
            try: code=process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait()
                return {'status':'timeout','behavior_observed':False}
            finally:
                try: os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError: pass
        if code and language == 'solidity' and _dependency_round < 8:
            diagnostic = (work/'stderr').read_text(errors='replace')
            try: missing = json.loads(diagnostic.rsplit('TOMEY_ERROR ', 1)[1]).get('missingImports', [])
            except (IndexError, ValueError): missing = []
            if missing and isinstance(missing, list) and len(missing) <= 128 and all(isinstance(x,str) and len(x)<=4096 for x in missing):
                try:
                    # Foundry libraries may be pinned git submodules rather than
                    # npm packages. Retrieve only repository-committed gitlinks,
                    # then retry in the unchanged isolated verifier.
                    if prepare_pinned_foundry_submodules(repository, missing, specification.get('remappings', [])):
                        return run_probe(repository, specification, _dependency_round + 1)
                    prepare_dependencies(repository, missing)
                except (DependencyError, OSError, ValueError) as error:
                    return {'status':'unsupported_dependencies','behavior_observed':False,'detail':str(error)[:1000]}
                return run_probe(repository, specification, _dependency_round + 1)
        if code and language == 'python':
            diagnostic = (work/'stderr').read_text(errors='replace')
            match = re.search(r"ModuleNotFoundError: No module named '([^']+)'", diagnostic)
            if match:
                if _dependency_round == 0:
                    try:
                        if prepare_locked_python_wheels(repository):
                            return run_probe(repository, specification, _dependency_round + 1)
                    except (DependencyError, OSError, ValueError, UnicodeError) as error:
                        return {'status':'unsupported_dependencies','behavior_observed':False,
                                'detail':str(error)[:1000]}
                return {'status':'unsupported_dependencies','behavior_observed':False,
                        'detail':'Python module not available in pinned pure-wheel dependencies: '+match.group(1)}
        if code and language == 'java':
            diagnostic = (work/'stderr').read_text(errors='replace')
            if 'TOMEY_INVALID_JAVA_PROBE:' in diagnostic:
                return {'status':'invalid_probe','behavior_observed':False,
                        'detail':diagnostic.split('TOMEY_INVALID_JAVA_PROBE:',1)[1].splitlines()[0][:400]}
            if 'error: cannot find symbol' in diagnostic or 'error: package ' in diagnostic:
                return {'status':'unsupported_dependencies','behavior_observed':False,
                        'detail':'Java project types missing from isolated compiler classpath: '+diagnostic[-700:]}
        if code:
            diagnostic=(work/'stderr').read_text(errors='replace')
            # Ganache may print an optional native-module warning before the
            # actual TOMEY_ERROR. Keep the structured root cause first, rather
            # than truncating it behind unrelated compatibility chatter.
            if language == 'solidity' and 'TOMEY_ERROR ' in diagnostic:
                try:
                    cause=json.loads(diagnostic.rsplit('TOMEY_ERROR ',1)[1])
                    detail=str(cause.get('detail','Solidity runtime failure'))[:1200]
                    if isinstance(cause.get('missingImports'),list) and cause['missingImports']:
                        detail+='; missing imports: '+repr(cause['missingImports'][:8])[:350]
                except (ValueError,TypeError,AttributeError):
                    detail=diagnostic[-1200:]
            else:
                detail=diagnostic[-1200:]
            return {'status':'probe_failed','behavior_observed':False,'exit_code':code,'detail':detail}
        if hashlib.sha256(target.read_bytes()).hexdigest()!=source_hash: raise ValueError('Source changed during probe')
        data=json.loads((work/'stdout').read_text())
        if kind == 'solidity_sequence':
            if not isinstance(data.get('steps'),list) or not data['steps'] or any(type(step.get('passed')) is not bool for step in data['steps'] if step.get('operation') != 'observe'):
                raise ValueError('Invalid transaction observations')
            # An arbitrary expected-value mismatch is NOT evidence. A
            # nonadministrator mutation of a source-proven privileged role,
            # established by before/after EVM receipts and an independently
            # inspected role-gated consumer, IS a reproducible security
            # behavior. Reporting impact still requires separate review.
            source_proven = authorization_transition_observed(
                repository,target,specification['function'],data)
            return {'status':'behavior_observed' if source_proven else 'observation_only',
                    'behavior_observed':source_proven,
                    'source_sha256':source_hash,'kind':kind,'observations':data,
                    'limitation':('Verified nonadministrator role mutation with before/after EVM observations and a source-declared privileged role consumer; reachability and exploit impact still require independent review.'
                      if source_proven else
                      'Only bounded Solidity transactions and assertions were observed. An expected-value mismatch is not independent security proof.')}
        if kind == 'java_sequence':
            steps=data.get('steps')
            if not isinstance(steps,list) or not steps or not all(
                isinstance(step,dict) and type(step.get('passed')) is bool for step in steps):
                raise ValueError('Invalid Java sequence observations')
            # Important: a mismatched expected value is only a test observation.
            # It is not a validated security finding and must never be classified as
            # a successful reproduction of a vulnerability.
            return {'status':'observation_only',
                    'behavior_observed':False,
                    'source_sha256':source_hash,
                    'kind':kind,
                    'observations':data,
                    'limitation':'Only bounded Java constructor and method calls were executed. Expected-value mismatches are observations, not validated security findings.'}
        normal,observed=data['control_output'],data['attack_output']
        if kind in ('html_reflection','entry_html_reflection'):
            matches=reflected_markup(data, nonce)
        else:
            base=Path(os.path.normpath(normal)).parent
            attack_path=Path(os.path.normpath(observed))
            matches=normal.endswith(data['control_input']) and attack_path.name=='TOMEY_ESCAPE_'+nonce and not attack_path.is_relative_to(base)
        if kind == 'entry_html_reflection' and language in ('python','javascript'):
            if not (data.get('entry_control_url') and data.get('entry_attack_url')):
                raise ValueError('Entry proof requires recorded URL inputs')
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
