"""Real isolated language probes; opt in with TOMEY_REPRODUCTION_INTEGRATION=1."""
import importlib.util
import os
import base64
import hashlib
import io
import json
import tarfile
from unittest.mock import patch
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("source_reproduction", ROOT / "scripts/source-reproduction.py")
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class ValidationTests(unittest.TestCase):
    def test_rejects_escape_and_unsupported_extension(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            repo.mkdir()
            (Path(directory) / "outside.js").write_text("exports.render = x => x;")
            (repo / "x.txt").write_text("")
            for name in ("../outside.js", "x.txt"):
                with self.assertRaises(ValueError):
                    driver.run_probe(repo, {"file":name, "function":"render",
                        "kind":"html_reflection", "nonce":"a"*32})


@unittest.skipUnless(os.getenv("TOMEY_REPRODUCTION_INTEGRATION") == "1", "requires installed sandbox/runtime")
class LanguageTests(unittest.TestCase):
    def probe(self, name, source, function="render", observed=True, kind="html_reflection", extra=None):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / name).write_text(source)
            for file, content in (extra or {}).items():
                (repo / file).parent.mkdir(parents=True, exist_ok=True)
                (repo / file).write_text(content)
            result = driver.run_probe(repo, {"file":name, "function":function,
                "kind":kind, "nonce":"a"*32})
            self.assertEqual(result["status"], "behavior_observed" if observed else "behavior_not_observed", result)
            self.assertEqual(result["behavior_observed"], observed)
            return result

    def test_python_unchanged(self):
        self.probe("render.py", "def render(x):\n    return '<p>'+x+'</p>'\n")

    def test_commonjs(self):
        self.probe("render.cjs", "exports.render = x => '<p>'+x+'</p>';")

    def test_javascript_package_esm_and_async(self):
        self.probe("render.js", "export async function render(x) { return '<p>'+x+'</p>'; }",
                   extra={"package.json":'{"type":"module"}'})

    def test_mjs_negative_control(self):
        self.probe("render.mjs", "export const render = x => x.replaceAll('<','&lt;');", observed=False)

    def test_path_construction(self):
        self.probe("path.cjs", "exports.render = x => '/safe/'+x;", kind="path_construction")

    def test_solidity_real_compilation_and_evm(self):
        self.probe("Render.sol", 'pragma solidity ^0.8.20; contract Render {'
                   'function render(string memory x) public pure returns(string memory) {'
                   'return string.concat("<p>",x,"</p>"); }}', function="Render.render")

    def test_solidity_negative_control(self):
        self.probe("Render.sol", 'pragma solidity ^0.8.20; contract Render {'
                   'function render(string memory) public pure returns(string memory) {return "safe";}}',
                   function="Render.render", observed=False)

    def test_js_import_and_logging(self):
        self.probe("render.mjs", "import {wrap} from './helper.mjs'; console.log('noise');"
                   "export const render = wrap;",
                   extra={"helper.mjs":"export const wrap = x => '<p>'+x+'</p>';"})

    def test_js_exception_is_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo/"fail.cjs").write_text("exports.render = () => {throw Error('fixture failure')};")
            result = driver.run_probe(repo, {"file":"fail.cjs","function":"render",
                "kind":"html_reflection","nonce":"a"*32})
            self.assertEqual(result["status"], "probe_failed", result)
            self.assertFalse(result["behavior_observed"])


    def test_javascript_locked_package_dependency_without_scripts(self):
        content = b"exports.wrap = x => '<p>'+x+'</p>';"
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            info = tarfile.TarInfo("package/index.js"); info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        tarball = data.getvalue()
        lock = {"lockfileVersion":3,"packages":{"":{},"node_modules/owned-wrap":{
            "resolved":"https://registry.npmjs.org/owned-wrap/-/owned-wrap-1.0.0.tgz",
            "integrity":"sha512-"+base64.b64encode(hashlib.sha512(tarball).digest()).decode()}}}
        with patch("source_dependencies.download", return_value=tarball) as download:
            self.probe("render.cjs", "exports.render = require('owned-wrap').wrap;",
                extra={"package.json":json.dumps({"dependencies":{"owned-wrap":"1.0.0"}}),
                       "package-lock.json":json.dumps(lock)})
            self.assertEqual(download.call_count,1)

    def test_solidity_node_modules_import(self):
        self.probe("Render.sol", 'pragma solidity ^0.8.20; import "@owned/Wrap.sol";'
            'contract Render {function render(string memory x) public pure returns(string memory) {return Wrap.wrap(x);}}',
            function="Render.render", extra={"node_modules/@owned/Wrap.sol":
            'pragma solidity ^0.8.20; library Wrap {function wrap(string memory x) internal pure returns(string memory) {return string.concat("<p>",x,"</p>");}}'})

    def test_solidity_foundry_remapping(self):
        self.probe("Render.sol", 'pragma solidity ^0.8.20; import "owned/Wrap.sol";'
            'contract Render {function render(string memory x) public pure returns(string memory) {return Wrap.wrap(x);}}',
            function="Render.render", extra={"foundry.toml":'[profile.default]\nremappings = ["owned/=lib/owned/src/"]\n',
            "lib/owned/src/Wrap.sol":'pragma solidity ^0.8.20; library Wrap {function wrap(string memory x) internal pure returns(string memory) {return string.concat("<p>",x,"</p>");}}'})

    def test_solidity_text_remapping(self):
        self.probe("Render.sol", 'pragma solidity ^0.8.20; import "owned/Wrap.sol";'
            'contract Render {function render(string memory x) public pure returns(string memory) {return Wrap.wrap(x);}}',
            function="Render.render", extra={"remappings.txt":"owned/=lib/owned/src/\n",
            "lib/owned/src/Wrap.sol":'pragma solidity ^0.8.20; library Wrap {function wrap(string memory x) internal pure returns(string memory) {return string.concat("<p>",x,"</p>");}}'})


if __name__ == "__main__":
    unittest.main()
