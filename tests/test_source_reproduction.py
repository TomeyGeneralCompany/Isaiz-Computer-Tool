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
    def test_markup_transformations_and_text_contexts(self):
        nonce='ab12'*8
        attack='<em data-tomey="'+nonce+'">TOMEY_PROBE</em>'
        def detected(output, control=None):
            return driver.reflected_markup({'control_input':'TOMEY_CONTROL_'+nonce,
                'control_output':control or 'TOMEY_CONTROL_'+nonce,
                'attack_output':output},nonce)
        self.assertTrue(detected(attack))
        self.assertTrue(detected(attack.upper(), ('TOMEY_CONTROL_'+nonce).upper()))
        self.assertTrue(detected(attack.lower(), ('TOMEY_CONTROL_'+nonce).lower()))
        self.assertTrue(detected("<EM DATA-TOMEY='"+nonce+"'>TOMEY_PROBE</EM>"))
        for output in (attack.replace('<','&lt;').replace('>','&gt;'),
                       '<!--'+attack+'-->', '<textarea>'+attack+'</textarea>',
                       '<script>"'+attack+'"</script>', '<title>'+attack+'</title>',
                       '<div title="'+attack.replace('"','&quot;')+'">text</div>',
                       '<em data-tomey="wrong">TOMEY_PROBE</em>'):
            self.assertFalse(detected(output),output)
        self.assertFalse(detected(attack, 'constant output'))
        self.assertFalse(detected(attack, 'TOMEY_CONTROL_'+nonce+attack))

    def test_foundry_compiler_settings(self):
        self.assertEqual(driver.foundry_settings({}), {})
        self.assertEqual(driver.foundry_settings({'optimizer': True, 'optimizer_runs': 500, 'via_ir': True}),
                         {'optimizer': {'enabled': True, 'runs': 500}, 'viaIR': True})
        self.assertEqual(driver.foundry_settings({'optimizer': False, 'via_ir': False}),
                         {'optimizer': {'enabled': False, 'runs': 200}, 'viaIR': False})
        for profile in ([], {'via_ir': 'true'}, {'optimizer': 1}, {'optimizer_runs': True},
                        {'optimizer_runs': -1}, {'optimizer_runs': 4294967296}):
            with self.assertRaises(ValueError):
                driver.foundry_settings(profile)

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
            (repo / name).parent.mkdir(parents=True, exist_ok=True)
            (repo / name).write_text(source)
            for file, content in (extra or {}).items():
                (repo / file).parent.mkdir(parents=True, exist_ok=True)
                (repo / file).write_text(content)
            result = driver.run_probe(repo, {"file":name, "function":function,
                "kind":kind, "nonce":"a"*32})
            self.assertEqual(result["status"], "behavior_observed" if observed else "behavior_not_observed", result)
            self.assertEqual(result["behavior_observed"], observed)
            return result

    def test_python_uppercase_markup(self):
        self.probe("render.py", "def render(x):\n    return x.upper()\n")

    def test_javascript_uppercase_markup(self):
        self.probe("render.cjs", "exports.render = x => x.toUpperCase();")

    def test_java_tron_interface_probe_is_invalid_not_compilation_failure(self):
        # Real TRON-style interface: non-string arguments and void return.
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            target = repo / "actuator/src/main/java/org/tron/core/vm/program/listener/ProgramListener.java"
            target.parent.mkdir(parents=True)
            target.write_text("package org.tron.core.vm.program.listener; "
                              "public interface ProgramListener { "
                              "void onMemoryWrite(int address, byte[] data); "
                              "void onStoragePut(DataWord key, DataWord value); }")
            result = driver.run_probe(repo, {"file":str(target.relative_to(repo)),
                "function":"ProgramListener.onMemoryWrite", "kind":"html_reflection", "nonce":"a"*32})
            self.assertEqual(result["status"], "invalid_probe", result)
            self.assertFalse(result["behavior_observed"])
            self.assertIn("one-input/text-output", result["detail"])

    def test_java_missing_dependency_is_not_false_reproduction(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "Render.java").write_text(
                "public class Render { public static String render(String x) { "
                "return UnknownDependency.process(x); } }")
            result = driver.run_probe(repo, {"file":"Render.java",
                "function":"Render.render", "kind":"html_reflection", "nonce":"a"*32})
            self.assertEqual(result["status"], "unsupported_dependencies", result)
            self.assertFalse(result["behavior_observed"])

    def test_java_uppercase_markup(self):
        self.probe("Render.java", 'public class Render { public static String render(String x) { return x.toUpperCase(); }}', function="Render.render")

    def test_python_escaped_markup(self):
        self.probe("render.py", "import html\ndef render(x):\n    return '<p>'+html.escape(x)+'</p>'\n", observed=False)

    def test_python_unchanged(self):
        self.probe("render.py", "def render(x):\n    return '<p>'+x+'</p>'\n")

    def test_java_static_string(self):
        self.probe("Render.java", 'public class Render { public static String render(String x) { return "<p>"+x+"</p>"; }}', function="Render.render")

    def test_java_instance_string_reflection(self):
        self.probe("Render.java",
                   'public class Render { public Render() {} public String render(String x) { return "<p>"+x+"</p>"; }}',
                   function="Render.render")

    def test_java_static_byte_array_reflection(self):
        self.probe("Render.java",
                   'import java.nio.charset.StandardCharsets; public class Render {'
                   'public static byte[] render(byte[] x) { return ("<p>"+new String(x, StandardCharsets.UTF_8)+"</p>").getBytes(StandardCharsets.UTF_8); }}',
                   function="Render.render")

    def test_java_instance_byte_array_negative(self):
        self.probe("Render.java",
                   'import java.nio.charset.StandardCharsets; public class Render { public Render() {} '
                   'public byte[] render(byte[] x) { return new String(x, StandardCharsets.UTF_8).replace("<","&lt;").getBytes(StandardCharsets.UTF_8); }}',
                   function="Render.render", observed=False)

    def test_java_package_and_source_dependency(self):
        self.probe("src/main/java/example/Render.java",
                   'package example; public class Render { public static String render(String x) { return Helper.wrap(x); }}',
                   function="Render.render", extra={"src/main/java/example/Helper.java":
                       'package example; public class Helper { public static String wrap(String x) { return x; }}'})

    def test_java_charsequence_and_object_output(self):
        self.probe("Render.java",
                   'public class Render { public static Object render(CharSequence x) { return "<p>"+x+"</p>"; }}',
                   function="Render.render")

    def test_java_stringbuilder_overload(self):
        self.probe("Render.java",
                   'public class Render { public static StringBuilder render(StringBuilder x) { return new StringBuilder("<p>").append(x).append("</p>"); }}',
                   function="Render.render")

    def test_java_bytebuffer(self):
        self.probe("Render.java",
                   'import java.nio.ByteBuffer; import java.nio.charset.StandardCharsets; '
                   'public class Render { public static ByteBuffer render(ByteBuffer x) { '
                   'return ByteBuffer.wrap(("<p>"+StandardCharsets.UTF_8.decode(x)+"</p>").getBytes(StandardCharsets.UTF_8)); }}',
                   function="Render.render")

    def test_java_path_parameter_and_result(self):
        self.probe("Render.java",
                   'import java.nio.file.Path; public class Render { public static Path render(Path x) { return Path.of("/safe").resolve(x); }}',
                   function="Render.render", kind="path_construction")

    def test_java_file_parameter_and_result(self):
        self.probe("Render.java",
                   'import java.io.File; public class Render { public static File render(File x) { return new File("/safe",x.toString()); }}',
                   function="Render.render", kind="path_construction")

    def test_java_uri_parameter_and_result(self):
        self.probe("Render.java",
                   'import java.net.URI; public class Render { public static URI render(URI x) { return URI.create("/safe/"+x.toString()); }}',
                   function="Render.render", kind="path_construction")

    def test_java_negative_control(self):
        self.probe("Render.java", 'public class Render { public static String render(String x) { return x.replace("<", "&lt;"); }}',
                   function="Render.render", observed=False)

    def test_java_missing_dependency_is_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo/"Render.java").write_text('import absent.Dependency; public class Render { public static String render(String x) { return x; }}')
            result = driver.run_probe(repo, {"file":"Render.java", "function":"Render.render",
                "kind":"html_reflection", "nonce":"a"*32})
            self.assertEqual(result["status"], "probe_failed", result)
            self.assertFalse(result["behavior_observed"])

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

    def test_solidity_foundry_optimizer_and_via_ir(self):
        arguments = ','.join('uint a' + str(i) for i in range(18))
        expression = '+'.join('a' + str(i) for i in range(18))
        source = ('pragma solidity ^0.8.20; contract Render {'
                  'function render(string memory x) public pure returns(string memory) {return x;}'
                  'function sum(' + arguments + ') external pure returns(uint) {return ' + expression + ';}}')
        # The extra function makes legacy compilation fail even though render is simple.
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo/'Render.sol').write_text(source)
            spec = {'file':'Render.sol','function':'Render.render','kind':'html_reflection','nonce':'a'*32}
            failed = driver.run_probe(repo, spec)
            self.assertEqual(failed['status'], 'probe_failed', failed)
            self.assertIn('Stack too deep', failed['detail'])
            (repo/'foundry.toml').write_text('[profile.default]\noptimizer = true\noptimizer_runs = 200\nvia_ir = true\n')
            passed = driver.run_probe(repo, spec)
            self.assertEqual(passed['status'], 'behavior_observed', passed)

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

    def test_solidity_longest_remapping_wins(self):
        self.probe("Render.sol", 'pragma solidity ^0.8.20; import "owned/deep/Wrap.sol";'
            'contract Render {function render(string memory x) public pure returns(string memory) {return Wrap.wrap(x);}}',
            function="Render.render", extra={"remappings.txt":"owned/=lib/wrong/\nowned/deep/=lib/right/\n",
            "lib/wrong/deep/Wrap.sol":'pragma solidity ^0.8.20; library Wrap {function wrap(string memory) internal pure returns(string memory) {return "safe";}}',
            "lib/right/Wrap.sol":'pragma solidity ^0.8.20; library Wrap {function wrap(string memory x) internal pure returns(string memory) {return string.concat("<p>",x,"</p>");}}'})

    def test_solidity_text_remapping(self):
        self.probe("Render.sol", 'pragma solidity ^0.8.20; import "owned/Wrap.sol";'
            'contract Render {function render(string memory x) public pure returns(string memory) {return Wrap.wrap(x);}}',
            function="Render.render", extra={"remappings.txt":"owned/=lib/owned/src/\n",
            "lib/owned/src/Wrap.sol":'pragma solidity ^0.8.20; library Wrap {function wrap(string memory x) internal pure returns(string memory) {return string.concat("<p>",x,"</p>");}}'})


@unittest.skipUnless(os.getenv("TOMEY_REPRODUCTION_INTEGRATION") == "1", "requires installed sandbox/runtime")
class StatefulSolidityTests(unittest.TestCase):
    SOURCE = """pragma solidity ^0.8.20;
contract Store {
 uint256 public value; address public owner;
 constructor(uint256 initial) payable { value=initial;owner=msg.sender; }
 function set(uint256 x) external {require(msg.sender==owner,"owner"); value=x;}
 function deposit() external payable {value+=msg.value;}
 function balance() external view returns(uint256) {return address(this).balance;}
}
"""
    def run_sequence(self, sequence):
        with tempfile.TemporaryDirectory() as directory:
            repo=Path(directory)
            (repo/"Store.sol").write_text(self.SOURCE)
            return driver.run_probe(repo,{"file":"Store.sol","function":"Store.set",
                "kind":"solidity_sequence","nonce":"a"*32,"sequence":sequence})

    def sequence(self):
        return {"constructorArgs":["9007199254740993"],"constructorValueWei":"10","steps":[
            {"operation":"call","function":"value()","args":[],"expect":"9007199254740993"},
            {"operation":"send","function":"set(uint256)","args":["7"]},
            {"operation":"call","function":"value()","args":[],"expect":"7"},
            {"operation":"send","function":"deposit()","args":[],"sender":2,"valueWei":"5"},
            {"operation":"call","function":"balance()","args":[],"expect":"15"}]}

    def test_constructor_state_changes_payable_and_deterministic_replay(self):
        sequence=self.sequence()
        first=self.run_sequence(sequence)
        self.assertEqual(first['status'],'behavior_not_observed',first)
        self.assertFalse(first['behavior_observed'])
        self.assertTrue(all(step['passed'] for step in first['observations']['steps']))
        self.assertEqual(self.run_sequence(sequence)['observations'],first['observations'])

    def test_self_contained_solidity_ignores_unrelated_js_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            repo=Path(directory)
            (repo/"Store.sol").write_text(self.SOURCE)
            (repo/"package.json").write_text('{"devDependencies":{"unrelated":"1"}}')
            result=driver.run_probe(repo,{"file":"Store.sol","function":"Store.set",
                "kind":"solidity_sequence","nonce":"a"*32,"sequence":self.sequence()})
            self.assertEqual(result['status'],'behavior_not_observed',result)

    def test_solidity_fetches_only_the_missing_import(self):
        data=io.BytesIO()
        library=b'pragma solidity ^0.8.20; library Owned {function initial(uint256 x) internal pure returns(uint256){return x;}}'
        with tarfile.open(fileobj=data,mode='w:gz') as tar:
            entry=tarfile.TarInfo('package/Owned.sol');entry.size=len(library)
            tar.addfile(entry,io.BytesIO(library))
        archive=data.getvalue()
        with tempfile.TemporaryDirectory() as directory:
            repo=Path(directory)
            (repo/'Store.sol').write_text(self.SOURCE.replace('contract Store', 'import "owned/Owned.sol"; contract Store').replace('value=initial;', 'value=Owned.initial(initial);'))
            (repo/'package.json').write_text('{"dependencies":{"owned":"1"},"devDependencies":{"unrelated":"1"}}')
            (repo/'package-lock.json').write_text(json.dumps({'lockfileVersion':3,'packages':{
                'node_modules/owned':{'resolved':'https://registry.npmjs.org/owned/-/owned-1.tgz',
                    'integrity':'sha512-'+base64.b64encode(hashlib.sha512(archive).digest()).decode()},
                'node_modules/unrelated':{'resolved':'https://invalid.test/archive'}}}))
            with patch('source_dependencies.download',return_value=archive) as download:
                result=driver.run_probe(repo,{'file':'Store.sol','function':'Store.set',
                    'kind':'solidity_sequence','nonce':'a'*32,'sequence':self.sequence()})
                self.assertEqual(result['status'],'behavior_not_observed',result)
                self.assertEqual(download.call_count,1)
                self.assertFalse((repo/'node_modules/unrelated').exists())

    def test_assertion_mismatch_is_recorded(self):
        sequence=self.sequence();sequence['steps'][2]['expect']='8'
        result=self.run_sequence(sequence)
        self.assertEqual(result['status'],'behavior_observed',result)
        self.assertFalse(result['observations']['steps'][2]['passed'])
        self.assertEqual(result['observations']['steps'][2]['actual'],'7')

    def test_expected_and_unexpected_revert(self):
        sequence=self.sequence()
        sequence['steps'].insert(1,{'operation':'send','function':'set(uint256)','args':['2'],'sender':1,'expectRevert':True})
        result=self.run_sequence(sequence)
        self.assertEqual(result['status'],'behavior_not_observed',result)
        self.assertTrue(result['observations']['steps'][1]['reverted'])
        sequence['steps'][1]['expectRevert']=False
        self.assertEqual(self.run_sequence(sequence)['status'],'probe_failed')

    def test_invalid_setup_does_not_become_a_finding(self):
        sequence=self.sequence();sequence['constructorArgs']=[]
        result=self.run_sequence(sequence)
        self.assertEqual(result['status'],'probe_failed',result)
        self.assertFalse(result['behavior_observed'])
        sequence=self.sequence();sequence['steps'][1]['args']=['not a number'];sequence['steps'][1]['expectRevert']=True
        self.assertEqual(self.run_sequence(sequence)['status'],'probe_failed')


if __name__ == "__main__":
    unittest.main()
