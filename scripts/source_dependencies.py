"""Materialize integrity-checked npm lockfile packages without executing installers."""
from __future__ import annotations
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import tarfile
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit

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

def prepare_dependencies(repository: Path) -> None:
    """Support npm lockfile v2/v3 plus local workspaces; no lifecycle scripts."""
    repository = repository.resolve()
    manifest = inside(repository, "package.json")
    if not manifest.is_file():
        return
    package = json.loads(manifest.read_text())
    if not any(package.get(key) for key in ("dependencies", "devDependencies", "optionalDependencies", "workspaces")):
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
    if marker.is_file() and marker.read_text() == digest:
        return
    lock = json.loads(raw)
    if lock.get("lockfileVersion") not in (2, 3) or not isinstance(lock.get("packages"), dict):
        raise DependencyError("Target requires npm lockfile v2/v3")
    entries = [(name, item) for name, item in lock["packages"].items() if name]
    if len(entries) > 4096:
        raise DependencyError("Target lockfile exceeds 4096 package entries")
    started = time.monotonic()
    budget = [0]
    for name, item in entries:
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
        data = download(item.get("resolved", ""))
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
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(digest)
