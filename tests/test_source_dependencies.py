import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import source_dependencies as deps

def archive(name="package/index.js", content=b"exports.value=1"):
    result=io.BytesIO()
    with tarfile.open(fileobj=result,mode="w:gz") as tar:
        entry=tarfile.TarInfo(name);entry.size=len(content)
        tar.addfile(entry,io.BytesIO(content))
    return result.getvalue()

class DependencyTests(unittest.TestCase):
    def test_registry_restriction(self):
        for url in ("file:///etc/passwd","https://example.com/x.tgz","https://user@registry.npmjs.org/x",
                    "https://registry.npmjs.org.evil.test/x"):
            with self.assertRaises(deps.DependencyError): deps.download(url)

    def test_archive_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(deps.DependencyError):
                deps.unpack(archive("package/../../escape"),Path(directory),[0])

    def test_large_lockfile_and_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            data=archive()
            (root/"package.json").write_text(json.dumps({"dependencies":{"owned":"1.0.0"}}))
            item={"resolved":"https://registry.npmjs.org/owned/-/owned-1.0.0.tgz",
                  "integrity":"sha512-"+base64.b64encode(hashlib.sha512(data).digest()).decode()}
            entries={f"node_modules/pkg{i}":item for i in range(686)}
            lock=root/"package-lock.json"
            lock.write_text(json.dumps({"lockfileVersion":3,"packages":entries}))
            with patch.object(deps,"download",return_value=data) as download:
                deps.prepare_dependencies(root)
                self.assertEqual(download.call_count,686)
            (root/"node_modules/.tomey-lock.sha256").unlink()
            entries.update({f"node_modules/pkg{i}":item for i in range(4097)})
            lock.write_text(json.dumps({"lockfileVersion":3,"packages":entries}))
            with patch.object(deps,"download") as download:
                with self.assertRaisesRegex(deps.DependencyError,"4096 package entries"):
                    deps.prepare_dependencies(root)
                download.assert_not_called()

    def test_integrity_and_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            data=archive()
            (root/"package.json").write_text(json.dumps({"dependencies":{"owned":"1.0.0"}}))
            lock={"lockfileVersion":3,"packages":{"":{},"node_modules/owned":{
                "resolved":"https://registry.npmjs.org/owned/-/owned-1.0.0.tgz",
                "integrity":"sha512-"+base64.b64encode(hashlib.sha512(data).digest()).decode()}}}
            (root/"package-lock.json").write_text(json.dumps(lock))
            with patch.object(deps,"download",return_value=data) as download:
                deps.prepare_dependencies(root)
                deps.prepare_dependencies(root)
                self.assertEqual(download.call_count,1)
                self.assertEqual((root/"node_modules/owned/index.js").read_bytes(),b"exports.value=1")
            (root/"node_modules/.tomey-lock.sha256").unlink()
            with patch.object(deps,"download",return_value=b"corrupted"):
                with self.assertRaises(deps.DependencyError): deps.prepare_dependencies(root)

if __name__ == "__main__": unittest.main()
