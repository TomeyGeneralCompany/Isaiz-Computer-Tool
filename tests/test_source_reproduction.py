"""Real isolated language probes; opt in with TOMEY_REPRODUCTION_INTEGRATION=1."""
import importlib.util
import os
import base64
import hashlib
import io
import json
import tarfile
import zipfile
from unittest.mock import patch, Mock
from pathlib import Path
import tempfile
import subprocess
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

    def test_nonincumbent_role_transition_requires_actual_account_change(self):
        accounts=['0x'+'11'*20,'0x'+'22'*20,'0x'+'33'*20]
        steps=[
            {'operation':'observe','function':'operator()','sender':0,'actual':accounts[0]},
            {'operation':'send','function':'rotateOperator(address)','sender':1,
             'reverted':False,'passed':False},
            {'operation':'observe','function':'operator()','sender':0,'actual':accounts[1]},
        ]
        evidence={'accounts':accounts,'steps':steps}
        self.assertTrue(driver.observed_nonincumbent_role_transition(evidence))
        guarded={'accounts':accounts,'steps':[
            steps[0],{**steps[1],'reverted':True,'passed':True},
            {**steps[2],'actual':accounts[0]}
        ]}
        self.assertFalse(driver.observed_nonincumbent_role_transition(guarded))
        incumbent={'accounts':accounts,'steps':[
            steps[0],{**steps[1],'sender':0},steps[2]]}
        self.assertFalse(driver.observed_nonincumbent_role_transition(incumbent))
        arbitrary={'accounts':accounts,'steps':[
            {**steps[0],'function':'value()'},steps[1],
            {**steps[2],'function':'value()'}]}
        self.assertFalse(driver.observed_nonincumbent_role_transition(arbitrary))
        unchanged={'accounts':accounts,'steps':[
            steps[0],steps[1],{**steps[2],'actual':accounts[0]}]}
        self.assertFalse(driver.observed_nonincumbent_role_transition(unchanged))

    def test_foundry_submodule_recovers_exact_gitlink_without_build_scripts(self):
        from source_dependencies import prepare_pinned_foundry_submodules
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / '.git').mkdir()
            (repo / '.gitmodules').write_text(
                '[submodule "open-lib"]\n path = lib/open-lib\n'
                ' url = https://github.com/owned/open-lib.git\n')
            revision = 'a' * 40
            invoked = []
            def command(args, **kwargs):
                invoked.append(args)
                if 'ls-tree' in args:
                    return Mock(stdout='160000 commit ' + revision + '\tlib/open-lib\n')
                if 'init' in args:
                    Path(args[-1]).mkdir(parents=True, exist_ok=True)
                if 'checkout' in args:
                    checkout = Path(args[2])
                    (checkout / 'Sample.sol').write_text('library Sample {}')
                return Mock(returncode=0)
            with (patch('source_dependencies.subprocess.run', side_effect=command),
                  patch('source_dependencies.subprocess.check_output', return_value=revision+'\n')):
                installed = prepare_pinned_foundry_submodules(repo, ['owned/Sample.sol'],
                    ['owned/=lib/open-lib/'])
            self.assertTrue(installed)
            self.assertTrue((repo / 'lib/open-lib/Sample.sol').is_file())
            fetches = [args for args in invoked if 'fetch' in args]
            self.assertEqual(len(fetches), 1)
            self.assertEqual(fetches[0][-2:],
                             ['https://github.com/owned/open-lib.git', revision])

    def test_foundry_submodule_rejects_unpinned_or_untrusted_dependency(self):
        from source_dependencies import prepare_pinned_foundry_submodules, DependencyError
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / '.git').mkdir()
            manifest = repo / '.gitmodules'
            manifest.write_text('[submodule "evil"]\n path = lib/evil\n'
                                ' url = https://untrusted.invalid/evil.git\n')
            with patch('source_dependencies.subprocess.run') as run:
                self.assertFalse(prepare_pinned_foundry_submodules(
                    repo,['lib/evil/Lib.sol']))
                run.assert_not_called()
            manifest.write_text('[submodule "owned"]\n path = lib/owned\n'
                                ' url = https://github.com/owned/lib.git\n')
            with patch('source_dependencies.subprocess.run',
                       return_value=Mock(stdout='')) as run:
                with self.assertRaises(DependencyError):
                    prepare_pinned_foundry_submodules(repo,['lib/owned/Lib.sol'])
                self.assertEqual(run.call_count,1)

    def test_python_requirements_without_hash_is_not_auto_installed(self):
        from source_dependencies import prepare_locked_python_wheels, DependencyError
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / 'requirements.txt').write_text('untrusted==1.0\n')
            with patch('source_dependencies.python_registry_read') as download:
                with self.assertRaises(DependencyError):
                    prepare_locked_python_wheels(repo)
                download.assert_not_called()

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

    def test_stateful_python_factory_sequence(self):
        with tempfile.TemporaryDirectory() as directory:
            repo=Path(directory)
            (repo/'counter.py').write_text(
                'class Counter:\n'
                ' def __init__(self,start=0): self.value=start\n'
                ' def advance(self,by=1): self.value+=by; return self.value\n'
                'def make(start=0): return Counter(start)\n')
            sequence={'factory':'make','constructor':[2],
                      'steps':[{'method':'advance','args':[3],'expected':5},
                               {'method':'advance','args':[4],'expected':99}]}
            result=driver.run_probe(repo,{'file':'counter.py','function':'advance',
                'kind':'python_sequence','nonce':'a'*32,'sequence':sequence})
            self.assertEqual(result['status'],'observation_only',result)
            self.assertFalse(result['behavior_observed'])
            self.assertEqual([s['actual'] for s in result['observations']['steps']],[5,9])
            self.assertEqual([s['passed'] for s in result['observations']['steps']],[True,False])

    def test_stateful_javascript_factory_sequence(self):
        with tempfile.TemporaryDirectory() as directory:
            repo=Path(directory)
            (repo/'counter.cjs').write_text(
                'exports.make = function(start) {let value=start; return {\n'
                'advance(by) {value += by; return value;}};};\n')
            sequence={'factory':'make','constructor':[2],
                      'steps':[{'method':'advance','args':[3],'expected':5},
                               {'method':'advance','args':[4],'expected':99}]}
            result=driver.run_probe(repo,{'file':'counter.cjs','function':'advance',
                'kind':'javascript_sequence','nonce':'a'*32,'sequence':sequence})
            self.assertEqual(result['status'],'observation_only',result)
            self.assertFalse(result['behavior_observed'])
            self.assertEqual([s['actual'] for s in result['observations']['steps']],[5,9])
            self.assertEqual([s['passed'] for s in result['observations']['steps']],[True,False])

    def test_python_uppercase_markup(self):
        self.probe("render.py", "def render(x):\n    return x.upper()\n")

    def test_python_hash_pinned_pure_wheel_is_imported_in_sandbox(self):
        content = b'def wrap(x):\n    return "<p>" + x + "</p>"\n'
        wheel_bytes = io.BytesIO()
        with zipfile.ZipFile(wheel_bytes, 'w') as wheel:
            wheel.writestr('owned_test_pkg/__init__.py', content)
        archive = wheel_bytes.getvalue()
        digest = hashlib.sha256(archive).hexdigest()
        metadata = json.dumps({'urls':[{
            'filename':'owned_test_pkg-1.0-py3-none-any.whl',
            'digests':{'sha256':digest},
            'url':'https://files.pythonhosted.org/packages/owned_test_pkg-1.0-py3-none-any.whl'
        }]}).encode()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo/'render.py').write_text(
                'import owned_test_pkg\n'
                'def render(x):\n    return owned_test_pkg.wrap(x)\n')
            (repo/'requirements.lock').write_text('owned_test_pkg==1.0 --hash=sha256:'+digest+'\n')
            with patch('source_dependencies.python_registry_read',
                       side_effect=[metadata, archive]) as download:
                result=driver.run_probe(repo, {'file':'render.py','function':'render',
                    'kind':'html_reflection','nonce':'a'*32})
            self.assertEqual(result['status'],'behavior_observed',result)
            self.assertTrue(result['behavior_observed'])
            self.assertEqual(download.call_count,2)

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
            self.assertEqual(result["status"], "unsupported_execution", result)
            self.assertFalse(result["behavior_observed"])
            self.assertIn("not supported by the current execution adapter", result["detail"])

    def test_java_resolves_prebuilt_dependency_jar_without_running_build_scripts(self):
        # Real external dependency, compiled before the verifier's sandbox.
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            helper = repo / 'fixture/external/Helper.java'
            helper.parent.mkdir(parents=True)
            helper.write_text('package external; public class Helper { '
                              'public static String wrap(String x) { return "<p>" + x + "</p>"; } }')
            classes = repo / 'fixture/classes'
            classes.mkdir()
            subprocess.run(['javac', '-d', str(classes), str(helper)], check=True)
            lib = repo / 'lib'
            lib.mkdir()
            subprocess.run(['jar', 'cf', str(lib / 'helper.jar'), '-C', str(classes), '.'], check=True)
            (repo / 'Render.java').write_text('import external.Helper; public class Render { '
                'public static String render(String x) { return Helper.wrap(x); } }')
            # Prove the fixture JAR is usable before entering bubblewrap.
            subprocess.run(['javac', '-classpath', str(lib / 'helper.jar'), '-d', str(classes),
                            str(repo / 'Render.java')], check=True)
            result = driver.run_probe(repo, {'file':'Render.java',
                'function':'Render.render','kind':'html_reflection','nonce':'a'*32})
            self.assertEqual(result['status'], 'behavior_observed', result)
            self.assertTrue(result['behavior_observed'])

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

    def test_java_cross_module_source_dependency(self):
        self.probe("module-a/src/main/java/example/Render.java",
                   'package example; import shared.Helper; public class Render { '
                   'public static String render(String x) { return Helper.wrap(x); }}',
                   function="Render.render", extra={
                     "module-b/src/main/java/shared/Helper.java":
                       'package shared; public class Helper { '
                       'public static String wrap(String x) { return "<p>"+x+"</p>"; }}'})

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

    def test_java_missing_dependency_is_unsupported(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo/"Render.java").write_text('import absent.Dependency; public class Render { public static String render(String x) { return x; }}')
            result = driver.run_probe(repo, {"file":"Render.java", "function":"Render.render",
                "kind":"html_reflection", "nonce":"a"*32})
            self.assertEqual(result["status"], "unsupported_dependencies", result)
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

    def test_source_proven_nonadmin_role_change_is_reproduced(self):
        # The same owned role transition used by the Gauntlet is exercised
        # in the real isolated EVM, not just with mock observation JSON.
        with tempfile.TemporaryDirectory() as directory:
            repo=Path(directory)
            (repo/"Authority.sol").write_text("""pragma solidity ^0.8.20;
contract Authority {
 address public administrator; address public operator;
 constructor(){administrator=msg.sender;operator=msg.sender;}
 function rotateOperator(address next) external {require(next!=address(0),"zero");operator=next;}
 function changeAdministrator(address next) external {require(msg.sender==administrator,"admin");administrator=next;}
}""")
            (repo/"Vault.sol").write_text("""pragma solidity ^0.8.20;
contract Vault {
 address public operator;
 function settle() external {require(msg.sender==operator,"operator only");}
}""")
            sequence={"constructorArgs":[],"steps":[
                {"operation":"observe","function":"operator()","args":[]},
                {"operation":"send","function":"rotateOperator(address)","args":["$account2"],"sender":1},
                {"operation":"observe","function":"operator()","args":[]}
            ]}
            spec={"file":"Authority.sol","function":"Authority.rotateOperator","kind":"solidity_sequence",
                  "nonce":"a"*32,"sequence":sequence}
            result=driver.run_probe(repo,spec)
            self.assertEqual(result["status"],"behavior_observed",result)
            self.assertTrue(result["behavior_observed"])
            self.assertNotEqual(result["observations"]["steps"][0]["actual"],
                                result["observations"]["steps"][2]["actual"])
            self.assertEqual(driver.run_probe(repo,spec)["observations"],result["observations"])
            # Removing source evidence of a privileged consumer must not
            # permit the same observed transition to be called a violation.
            (repo/"Vault.sol").unlink()
            negative=driver.run_probe(repo,spec)
            self.assertEqual(negative["status"],"observation_only",negative)
            self.assertFalse(negative["behavior_observed"])

    def test_constructor_state_changes_payable_and_deterministic_replay(self):
        sequence=self.sequence()
        first=self.run_sequence(sequence)
        self.assertEqual(first['status'],'observation_only',first)
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
            self.assertEqual(result['status'],'observation_only',result)

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
                self.assertEqual(result['status'],'observation_only',result)
                self.assertEqual(download.call_count,1)
                self.assertFalse((repo/'node_modules/unrelated').exists())

    def test_assertion_mismatch_is_recorded(self):
        sequence=self.sequence();sequence['steps'][2]['expect']='8'
        result=self.run_sequence(sequence)
        self.assertEqual(result['status'],'observation_only',result)
        self.assertFalse(result['observations']['steps'][2]['passed'])
        self.assertEqual(result['observations']['steps'][2]['actual'],'7')
        self.assertFalse(result['behavior_observed'])

    def test_expected_and_unexpected_revert(self):
        sequence=self.sequence()
        sequence['steps'].insert(1,{'operation':'send','function':'set(uint256)','args':['2'],'sender':1,'expectRevert':True})
        result=self.run_sequence(sequence)
        self.assertEqual(result['status'],'observation_only',result)
        self.assertTrue(result['observations']['steps'][1]['reverted'])
        sequence['steps'][1]['expectRevert']=False
        result=self.run_sequence(sequence)
        self.assertEqual(result['status'],'observation_only')
        self.assertTrue(any(step.get('reverted') is True and step.get('passed') is False
                            for step in result['observations']['steps']))

    def test_invalid_setup_does_not_become_a_finding(self):
        sequence=self.sequence();sequence['constructorArgs']=[]
        result=self.run_sequence(sequence)
        self.assertEqual(result['status'],'probe_failed',result)
        self.assertFalse(result['behavior_observed'])
        sequence=self.sequence();sequence['steps'][1]['args']=['not a number'];sequence['steps'][1]['expectRevert']=True
        self.assertEqual(self.run_sequence(sequence)['status'],'probe_failed')


if __name__ == "__main__":
    unittest.main()
