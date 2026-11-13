"""Materialize integrity-checked npm lockfile packages without executing installers."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import base64
import configparser
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
from pathlib import Path, PurePosixPath
import tarfile
import zipfile
import stat
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit, quote

class DependencyError(ValueError):
    pass

def inside(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or path == root:
        raise DependencyError("Dependency path escapes repository")
    return path

def package_url(url: str) -> bool:
    parsed = urlsplit(url)
    return (parsed.scheme == "https" and parsed.hostname == "registry.npmjs.org"
            and parsed.port in (None, 443) and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment)

def download(url: str) -> bytes:
    if not package_url(url):
        raise DependencyError("Only npm registry lockfile tarballs are supported")
    # Validate each redirect before following it.
    class RegistryRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if not package_url(newurl):
                raise DependencyError("Dependency redirect leaves npm registry")
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    with urllib.request.build_opener(RegistryRedirect()).open(url, timeout=10) as response:
        data = response.read(20 * 1024 * 1024 + 1)
    if len(data) > 20 * 1024 * 1024:
        raise DependencyError("Dependency archive exceeds 20 MiB")
    return data

def unpack(data: bytes, destination: Path, budget: list[int]) -> None:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 20000:
            raise DependencyError("Too many files in dependency archive")
        for member in members:
            parts = PurePosixPath(member.name).parts
            if not parts or parts[0] != "package" or ".." in parts or member.issym() or member.islnk():
                raise DependencyError("Unsupported dependency archive path/link")
            if len(parts) == 1:
                continue
            target = inside(destination, "/".join(parts[1:]))
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                budget[0] += member.size
                if budget[0] > 256 * 1024 * 1024:
                    raise DependencyError("Dependency extraction exceeds 256 MiB")
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise DependencyError("Missing dependency file data")
                with source, target.open("wb") as output:
                    while chunk := source.read(65536):
                        output.write(chunk)
            else:
                raise DependencyError("Unsupported dependency archive entry")

def prepare_dependencies(repository: Path, required_imports: list[str] | None = None) -> None:
    """Support npm lockfile v2/v3 plus local workspaces; no lifecycle scripts."""
    repository = repository.resolve()
    manifest = inside(repository, "package.json")
    if not manifest.is_file():
        if required_imports: raise DependencyError("Missing imports require a package manifest and lockfile")
        return
    package = json.loads(manifest.read_text())
    if required_imports is None and not any(package.get(key) for key in ("dependencies", "devDependencies", "optionalDependencies", "workspaces")):
        return
    lock_path = inside(repository, "package-lock.json")
    if not lock_path.is_file():
        # Checked-in/vendor dependencies remain usable without downloading.
        if (repository / "node_modules").is_dir():
            return
        raise DependencyError("Target dependencies require npm package-lock.json v2/v3 or vendored node_modules")
    if lock_path.stat().st_size > 4 * 1024 * 1024:
        raise DependencyError("Target lockfile exceeds 4 MiB")
    raw = lock_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    marker = inside(repository, "node_modules/.tomey-lock.sha256")
    if required_imports is None and marker.is_file() and marker.read_text() == digest:
        return
    lock = json.loads(raw)
    if lock.get("lockfileVersion") not in (2, 3) or not isinstance(lock.get("packages"), dict):
        raise DependencyError("Target requires npm lockfile v2/v3")
    entries = [(name, item) for name, item in lock["packages"].items() if name]
    if required_imports is not None:
        # A large lockfile is an inventory, not an installation request. Limit
        # the *selected* dependency closure, not the entire repository lock.
        # Solidity compiler diagnostics give import paths; resolve each to its
        # longest locked package prefix (including scoped npm packages).
        locked = dict(entries)
        selected = set()
        pending = []
        for request in required_imports:
            if not isinstance(request, str) or not request or len(request) > 4096:
                raise DependencyError("Invalid npm import request")
            candidates = [name for name in locked if name.startswith("node_modules/")
                          and (request == name[13:] or request.startswith(name[13:] + "/"))]
            if not candidates:
                raise DependencyError("No locked npm package supplies import: " + request)
            pending.append(max(candidates, key=len))
        # Include lockfile-declared runtime dependencies, respecting nested npm
        # resolution (nearest node_modules wins). Do not download unrelated
        # development dependencies from the rest of the lockfile.
        while pending:
            name = pending.pop()
            if name in selected:
                continue
            selected.add(name)
            if len(selected) > 4096:
                raise DependencyError("Selected npm dependency closure exceeds 4096 package entries")
            item = locked[name]
            if not isinstance(item, dict):
                raise DependencyError("Malformed npm lockfile package entry")
            dependencies = item.get("dependencies", {})
            if not isinstance(dependencies, dict):
                raise DependencyError("Malformed locked npm dependencies")
            for dependency in dependencies:
                if not isinstance(dependency, str) or not re.fullmatch(r"(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+", dependency):
                    raise DependencyError("Invalid locked npm dependency name")
                # node_modules/parent/node_modules/child, then progressively
                # hoisted ancestors, ending at root node_modules/child.
                parent = name
                resolved = None
                while True:
                    candidate = parent + "/node_modules/" + dependency
                    if candidate in locked:
                        resolved = candidate
                        break
                    marker = parent.rfind("/node_modules/")
                    if marker < 0:
                        break
                    parent = parent[:marker]
                if resolved is None:
                    candidate = "node_modules/" + dependency
                    if candidate in locked:
                        resolved = candidate
                if resolved is None:
                    raise DependencyError("Locked npm dependency is missing: " + dependency)
                pending.append(resolved)
        entries = [(name, item) for name, item in entries if name in selected]
    elif len(entries) > 4096:
        # Large lockfiles are inventories, not a reason to reject the entire
        # source repository. Defer materialization until the isolated compiler
        # reports concrete missing imports. The required_imports path above
        # then installs only the integrity-pinned transitive closure.
        # Never run package lifecycle scripts or install the full lockfile.
        return
    # Parent packages must be materialized before nested dependencies.
    entries.sort(key=lambda entry: (entry[0].count("/"), entry[0]))
    started = time.monotonic()
    budget = [0]
    def fetch(entry):
        name, item = entry
        if "node_modules" not in PurePosixPath(name).parts or item.get("link"):
            return None
        return download(item.get("resolved", ""))
    # At most four bounded archives are held at once. Never run lifecycle scripts.
    def batches():
        with ThreadPoolExecutor(max_workers=4) as pool:
            for offset in range(0, len(entries), 4):
                if time.monotonic() - started > 85:
                    raise DependencyError("Dependency preparation exceeded time budget")
                batch = entries[offset:offset+4]
                yield from zip(batch, pool.map(fetch, batch))
    for (name, item), data in batches():
        if "node_modules" not in PurePosixPath(name).parts:
            continue  # Workspace source entries are already in the checkout.
        if (not name.startswith("node_modules/") or "\\" in name
                or any(part in ("", ".", "..") for part in name.split("/"))):
            raise DependencyError("Unsupported npm package location")
        destination = inside(repository, name)
        if item.get("link"):
            source = inside(repository, item.get("resolved", ""))
            if not source.is_dir():
                raise DependencyError("Workspace dependency is missing")
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                destination.symlink_to(source, target_is_directory=True)
            continue
        integrity = item.get("integrity", "")
        checks = [v.split("-", 1) for v in integrity.split() if v.startswith(("sha512-", "sha256-"))]
        if not checks:
            raise DependencyError("Dependency has no SHA-256/SHA-512 integrity")
        if time.monotonic() - started > 85:
            raise DependencyError("Dependency preparation exceeded time budget")
        if not any(base64.b64encode(hashlib.new(algorithm, data).digest()).decode() == expected
                   for algorithm, expected in checks):
            raise DependencyError("Dependency integrity mismatch")
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Extract beside the package then move only complete verified content.
        with tempfile.TemporaryDirectory(prefix=".tomey-package-", dir=destination.parent) as temporary:
            staging = Path(temporary)
            unpack(data, staging, budget)
            if destination.exists():
                import shutil
                shutil.rmtree(destination)
            os.replace(staging, destination)
    if required_imports is None:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(digest)

def prepare_pinned_foundry_submodules(repository: Path, missing_imports: list[str],
                                     remappings: list[str] | None = None) -> bool:
    """Resolve missing Foundry library sources from exact checked-in gitlinks.

    No Gradle/Forge/npm build or target hooks execute. Only GitHub HTTPS URLs
    from .gitmodules are eligible, and the fetched commit must match the
    repository's 160000 gitlink, not a mutable upstream branch.
    """
    repository = repository.resolve(strict=True)
    manifest = repository / ".gitmodules"
    if not manifest.is_file() or manifest.is_symlink() or manifest.stat().st_size > 128000:
        return False
    if not (repository / ".git").exists():
        return False
    config = configparser.RawConfigParser(interpolation=None)
    try:
        config.read_string(manifest.read_text())
    except (configparser.Error, UnicodeError):
        raise DependencyError("Malformed Foundry git-submodule declaration")
    declared = []
    for section in config.sections():
        if not section.startswith('submodule '):
            continue
        path = config.get(section, 'path', fallback='')
        url = config.get(section, 'url', fallback='')
        if (not re.fullmatch(r'lib/[A-Za-z0-9_.-]+', path)
                or not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?', url)):
            continue
        declared.append((path, url))
    mappings = []
    # Match the compiler's resolution rules: it also reads remappings.txt.
    text_remappings = []
    remap_file = repository / 'remappings.txt'
    if remap_file.is_file() and not remap_file.is_symlink() and remap_file.stat().st_size <= 128000:
        text_remappings = [line.strip() for line in remap_file.read_text().splitlines()
                           if line.strip() and not line.lstrip().startswith('#')]
    for item in [*(remappings or []), *text_remappings]:
        if isinstance(item, str) and '=' in item:
            prefix, replacement = item.split('=', 1)
            if prefix and replacement and '..' not in Path(replacement).parts:
                mappings.append((prefix, replacement))
    candidates = set()
    for request in missing_imports:
        if not isinstance(request, str) or len(request) > 4096 or '\\\\' in request:
            continue
        candidates.add(request)
        for prefix, replacement in mappings:
            if request.startswith(prefix):
                candidates.add(replacement + request[len(prefix):])
    installed = False
    for path, url in declared[:32]:
        if not any(item.startswith(path + '/') for item in candidates):
            continue
        target = inside(repository, path)
        if target.is_file() or target.is_symlink():
            raise DependencyError("Foundry dependency path is not a normal directory")
        if target.is_dir() and any(target.iterdir()):
            continue
        try:
            gitlink = subprocess.run(
                ['git','-C',str(repository),'ls-tree','HEAD','--',path],
                capture_output=True, text=True, check=True, timeout=10)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
            raise DependencyError("Cannot read pinned Foundry dependency revision") from error
        match = re.fullmatch(r'160000 commit ([a-f0-9]{40})\t' + re.escape(path) + r'\n?', gitlink.stdout)
        if not match:
            raise DependencyError("Foundry dependency lacks a pinned gitlink: " + path)
        revision = match.group(1)
        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".tomey-foundry-", dir=target.parent) as temporary:
            staging = Path(temporary) / 'library'
            environment = {**os.environ, 'GIT_TERMINAL_PROMPT':'0',
                           'GIT_LFS_SKIP_SMUDGE':'1','GIT_CONFIG_NOSYSTEM':'1',
                           'GIT_CONFIG_GLOBAL':'/dev/null'}
            try:
                subprocess.run(['git','init','--quiet',str(staging)],env=environment,check=True,timeout=10,
                               stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                subprocess.run(['git','-C',str(staging),'-c','protocol.file.allow=never',
                                '-c','protocol.ext.allow=never','fetch','--quiet','--depth=1',
                                url, revision],env=environment,check=True,timeout=75,
                               stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                subprocess.run(['git','-C',str(staging),'checkout','--quiet','--detach',revision],
                               env=environment,check=True,timeout=20,
                               stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                actual = subprocess.check_output(['git','-C',str(staging),'rev-parse','HEAD'],
                                                 env=environment,text=True,timeout=10).strip()
            except (subprocess.CalledProcessError,subprocess.TimeoutExpired,OSError) as error:
                raise DependencyError("Pinned Foundry library could not be retrieved: " + path) from error
            if actual != revision:
                raise DependencyError("Foundry library does not match pinned revision: " + path)
            if target.exists():
                target.rmdir()  # only empty directories may be replaced
            shutil.move(str(staging), str(target))
            installed = True
    return installed


def python_registry_read(url: str, host: str, limit: int) -> bytes:
    """Bounded PyPI read with same-origin redirects only."""
    def allowed(destination):
        parsed = urlsplit(destination)
        return (parsed.scheme == 'https' and parsed.hostname == host and
                parsed.port in (None, 443) and not parsed.username and not parsed.password
                and not parsed.fragment)
    if not allowed(url):
        raise DependencyError('Python package URL outside trusted registry')
    class SameOriginRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, destination):
            if not allowed(destination):
                raise DependencyError('Python dependency redirect leaves trusted registry')
            return super().redirect_request(request, fp, code, msg, headers, destination)
    opener = urllib.request.build_opener(SameOriginRedirect())
    with opener.open(url, timeout=12) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise DependencyError('Python registry response exceeds size limit')
    return data


def prepare_locked_python_wheels(repository: Path) -> bool:
    """Install only hash-pinned pure-Python wheels; never execute pip/setup scripts.

    Accept standard 'name==version --hash=sha256:...' entries from requirements.lock
    or requirements.txt. Transitive packages must themselves have locked entries.
    """
    repository = repository.resolve(strict=True)
    lock = next((repository / name for name in ('requirements.lock', 'requirements.txt')
                 if (repository / name).is_file()), None)
    if lock is None:
        return False
    if lock.is_symlink() or lock.stat().st_size > 128000:
        raise DependencyError('Python requirements file is not an eligible lock')
    raw = lock.read_bytes()
    specs = []
    for line in raw.decode('utf8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(
            r'([A-Za-z0-9][A-Za-z0-9_.-]{0,79})==([A-Za-z0-9][A-Za-z0-9_.!+-]{0,79})\s+--hash=sha256:([a-fA-F0-9]{64})',
            line)
        if not match:
            raise DependencyError('Python dependencies require exact versions and SHA-256 hashes')
        specs.append(match.groups())
    if not specs or len(specs) > 24:
        raise DependencyError('Python wheel lock must list 1-24 pinned packages')
    destination = inside(repository, '.tomey-python-deps')
    marker = hashlib.sha256(raw).hexdigest()
    if destination.is_dir() and not destination.is_symlink() and (
            destination / '.tomey-lock.sha256').is_file() and (
            destination / '.tomey-lock.sha256').read_text() == marker:
        return True
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise DependencyError('Unsafe Python dependency directory')
    with tempfile.TemporaryDirectory(prefix='.tomey-python-', dir=repository) as temporary:
        staging = Path(temporary) / 'site'
        staging.mkdir()
        unpacked_bytes = 0
        installed_paths = set()
        for name, version, digest in specs:
            metadata_url = ('https://pypi.org/pypi/' + quote(name, safe='') + '/' +
                            quote(version, safe='') + '/json')
            try:
                release = json.loads(python_registry_read(metadata_url, 'pypi.org', 512000))
            except (ValueError, OSError) as error:
                raise DependencyError('Python release metadata unavailable: '+name) from error
            wheels = [entry for entry in release.get('urls', []) if
                      isinstance(entry, dict) and
                      re.search(r'-(?:py3|py2\.py3)-none-any\.whl$', str(entry.get('filename',''))) and
                      entry.get('digests', {}).get('sha256') == digest.lower()]
            if len(wheels) != 1:
                raise DependencyError('No hash-matching pure Python wheel for '+name+'=='+version)
            url = wheels[0].get('url','')
            try:
                archive = python_registry_read(url, 'files.pythonhosted.org', 20*1024*1024)
            except (OSError, ValueError) as error:
                raise DependencyError('Python wheel download failed: '+name) from error
            if hashlib.sha256(archive).hexdigest() != digest.lower():
                raise DependencyError('Python wheel digest mismatch: '+name)
            try:
                with zipfile.ZipFile(io.BytesIO(archive)) as wheel:
                    members = wheel.infolist()
                    if len(members)>3000:
                        raise DependencyError('Python wheel contains too many files')
                    for item in members:
                        pathname = PurePosixPath(item.filename)
                        if (pathname.is_absolute() or not pathname.parts or
                            '..' in pathname.parts or '\\' in item.filename or
                            any(part.endswith('.data') for part in pathname.parts) or
                            stat.S_ISLNK(item.external_attr >> 16)):
                            raise DependencyError('Unsupported wheel path/link')
                        if item.is_dir():
                            continue
                        if item.filename in installed_paths:
                            raise DependencyError('Conflicting Python wheel files')
                        installed_paths.add(item.filename)
                        unpacked_bytes += item.file_size
                        if unpacked_bytes > 128*1024*1024:
                            raise DependencyError('Python dependency extraction exceeds limit')
                        target = inside(staging, item.filename)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with target.open('wb') as output:
                            output.write(wheel.read(item))
            except (zipfile.BadZipFile, OSError) as error:
                raise DependencyError('Invalid Python wheel archive') from error
        (staging / '.tomey-lock.sha256').write_text(marker)
        if destination.exists():
            shutil.rmtree(destination)
        os.replace(staging, destination)
    return True
