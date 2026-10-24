"""Fixed Java adapter, invoked only inside the isolated reproduction namespace."""
import base64
import json
from pathlib import Path
import re
import subprocess

spec = json.loads(Path('/spec.json').read_text())
target = (Path('/repo') / spec['file']).resolve(strict=True)
if not target.is_relative_to('/repo'):
    raise ValueError('Source outside repository')
# Do not execute project build files or annotation processors.
source = target.read_text()
code = re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"', '', source, flags=re.S)
package = re.search(r'\bpackage\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*;', code)
package = package[1] if package else ''
parts = spec['function'].split('.')
if len(parts) != 2 or parts[0] != target.stem:
    raise ValueError('Java probe requires FileClass.method')
source_root = target.parent
for component in reversed(package.split('.') if package else []):
    if source_root.name != component:
        raise ValueError('Java package must match source directory')
    source_root = source_root.parent
if not source_root.is_relative_to('/repo'):
    raise ValueError('Java source root outside repository')
classes = Path('/tmp/classes')
classes.mkdir()
harness = Path('/tmp/TomeyJavaProbe.java')
harness.write_text(r'''
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
public class TomeyJavaProbe {
 public static void main(String[] args) throws Exception {
  java.io.PrintStream output = System.out;
  System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
  Class<?> target = Class.forName(args[0]);
  Method method = target.getMethod(args[1], String.class);
  if (!Modifier.isStatic(method.getModifiers()) || method.getReturnType() != String.class)
   throw new IllegalArgumentException("Public static String method required");
  String[] results = new String[2];
  for(int i=0;i<2;i++) {
   String input = new String(Base64.getDecoder().decode(args[i+2]), StandardCharsets.UTF_8);
   String result = (String)method.invoke(null, input);
   if(result == null || result.length()>16000) throw new IllegalArgumentException("Invalid result size");
   results[i] = Base64.getEncoder().encodeToString(result.getBytes(StandardCharsets.UTF_8));
  }
  output.println(results[0]); output.println(results[1]);
 }
}
''')
jvm = ['-Xmx128m', '-XX:ActiveProcessorCount=2', '-XX:+UseSerialGC']
subprocess.run(['/jdk/bin/javac', *['-J'+x for x in jvm], '-proc:none', '-encoding', 'UTF-8',
                '-classpath', str(classes), '-sourcepath', str(source_root), '-d', str(classes),
                str(target), str(harness)], check=True, timeout=15)
control = 'TOMEY_CONTROL_' + spec['nonce']
attack = ('<em data-tomey="'+spec['nonce']+'">TOMEY_PROBE</em>'
          if spec['kind'] == 'html_reflection' else '../../TOMEY_ESCAPE_'+spec['nonce'])
result = subprocess.run(['/jdk/bin/java', *jvm, '-cp', str(classes), 'TomeyJavaProbe',
                         (package+'.' if package else '')+parts[0], parts[1],
                         *[base64.b64encode(x.encode()).decode() for x in (control, attack)]],
                        check=True, stdout=subprocess.PIPE, timeout=8)
lines = result.stdout.decode().splitlines()
if len(lines) != 2:
    raise ValueError('Invalid Java probe output')
normal, observed = [base64.b64decode(x, validate=True).decode() for x in lines]
print(json.dumps(dict(control_input=control, control_output=normal,
                     attack_input=attack, attack_output=observed)))
