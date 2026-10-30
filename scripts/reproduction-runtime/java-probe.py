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
# Preflight the fixed adapter's supported signature before invoking javac.
# A void/interface callback with project-specific parameters is not a valid
# String/byte/Path probe; compilation errors must not hide that fact.
method_name = re.escape(parts[1])
declaration = re.search(
    r'\\b(?:public\\s+)?(?:static\\s+)?(?:final\\s+)?'
    r'(?:String|byte\\[\\]|CharSequence|StringBuilder|StringBuffer|ByteBuffer|Path|File|URI|Object)\\s+'
    + method_name + r'\\s*\\(\\s*(?:final\\s+)?'
    r'(?:String|byte\\[\\]|CharSequence|StringBuilder|StringBuffer|ByteBuffer|Path|File|URI|Object)'
    r'\\s+[A-Za-z_$][\\w$]*\\s*\\)',
    code
)
if not declaration:
    raise ValueError('TOMEY_INVALID_JAVA_PROBE: no supported one-input/text-output declaration')
if re.search(r'\\binterface\\s+' + re.escape(parts[0]) + r'\\b', code) and not re.search(r'\\bstatic\\b', declaration.group(0)):
    raise ValueError('TOMEY_INVALID_JAVA_PROBE: interface instance method cannot be constructed')
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
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.io.File;
import java.net.URI;
import java.util.Base64;
public class TomeyJavaProbe {
 static int priority(Class<?> c) {
  if(c == String.class)return 0;
  if(c == byte[].class)return 1;
  if(c == CharSequence.class)return 2;
  if(c == StringBuilder.class)return 3;
  if(c == StringBuffer.class)return 4;
  if(c == ByteBuffer.class)return 5;
  if(c == Path.class)return 6;
  if(c == File.class)return 7;
  if(c == URI.class)return 8;
  if(c == Object.class)return 9;
  return -1;
 }
 static Object argument(Class<?> c, byte[] data) {
  String value = new String(data,StandardCharsets.UTF_8);
  if(c == String.class || c == CharSequence.class || c == Object.class)return value;
  if(c == byte[].class)return data;
  if(c == StringBuilder.class)return new StringBuilder(value);
  if(c == StringBuffer.class)return new StringBuffer(value);
  if(c == ByteBuffer.class)return ByteBuffer.wrap(data);
  if(c == Path.class)return Path.of(value);
  if(c == File.class)return new File(value);
  if(c == URI.class)return URI.create(value);
  throw new IllegalArgumentException("Unsupported argument type");
 }
 static byte[] outputBytes(Object value) {
  if(value == null)throw new IllegalArgumentException("Null probe result");
  if(value instanceof byte[])return (byte[])value;
  if(value instanceof ByteBuffer) {
   ByteBuffer b=((ByteBuffer)value).asReadOnlyBuffer();
   if(b.remaining()>16000)throw new IllegalArgumentException("Probe output too large");
   byte[] result=new byte[b.remaining()];b.get(result);return result;
  }
  if(value instanceof CharSequence || value instanceof Path ||
     value instanceof File || value instanceof URI)
   return value.toString().getBytes(StandardCharsets.UTF_8);
  throw new IllegalArgumentException("Unsupported probe result type");
 }
 public static void main(String[] args) throws Exception {
  java.io.PrintStream output=System.out;
  System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
  Class<?> target=Class.forName(args[0]);
  Method method=null;
  int best=100;
  for(Method candidate:target.getMethods()) {
   if(!candidate.getName().equals(args[1]) || candidate.getParameterCount()!=1)continue;
   int rank=priority(candidate.getParameterTypes()[0]);
   if(rank<0 || rank>=best)continue;
   Class<?> ret=candidate.getReturnType();
   if(ret != String.class && ret != byte[].class && ret != Object.class &&
      !CharSequence.class.isAssignableFrom(ret) && !ByteBuffer.class.isAssignableFrom(ret) &&
      !Path.class.isAssignableFrom(ret) && !File.class.isAssignableFrom(ret) &&
      !URI.class.isAssignableFrom(ret))continue;
   method=candidate;best=rank;
  }
  if(method==null)throw new IllegalArgumentException("No supported public one-argument overload");
  Object receiver=Modifier.isStatic(method.getModifiers())?null:target.getConstructor().newInstance();
  String[] results=new String[2];
  for(int i=0;i<2;i++) {
   byte[] input=Base64.getDecoder().decode(args[i+2]);
   Object value=method.invoke(receiver,argument(method.getParameterTypes()[0],input));
   byte[] bytes=outputBytes(value);
   if(bytes.length>16000)throw new IllegalArgumentException("Probe output too large");
   results[i]=Base64.getEncoder().encodeToString(bytes);
  }
  output.println(results[0]);output.println(results[1]);
 }
}
''')
jvm = ['-Xmx128m', '-XX:ActiveProcessorCount=2', '-XX:+UseSerialGC']
# javac on JDK 21 can exceed a 128 MiB heap while initializing compiler
# modules; keep runtime probes tight, but give compilation bounded headroom.
javac_jvm = ['-Xmx512m', '-XX:ActiveProcessorCount=2', '-XX:+UseSerialGC']
subprocess.run(['/jdk/bin/javac', *['-J'+x for x in javac_jvm], '-proc:none', '-encoding', 'UTF-8',
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
normal, observed = [base64.b64decode(x, validate=True).decode('utf-8') for x in lines]
print(json.dumps(dict(control_input=control, control_output=normal,
                     attack_input=attack, attack_output=observed)))
