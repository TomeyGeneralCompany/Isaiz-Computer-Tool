"""Fixed Java adapter, invoked only inside the isolated reproduction namespace."""
import base64
import json
import os
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
# A declarative stateful path: fixed reflection driver, no model-generated Java.
# Only public constructors/methods and primitive/String parameters are accepted.
sequence_mode = spec['kind'] == 'java_sequence'
if sequence_mode:
    sequence = spec.get('sequence')
    if not isinstance(sequence, dict):
        raise ValueError('TOMEY_INVALID_JAVA_PROBE: Java sequence required')
    steps = sequence.get('steps')
    constructor = sequence.get('constructor', [])
    if not isinstance(steps, list) or not 1 <= len(steps) <= 12:
        raise ValueError('TOMEY_INVALID_JAVA_PROBE: 1-12 Java steps required')
    if not isinstance(constructor, list) or len(constructor) > 8:
        raise ValueError('TOMEY_INVALID_JAVA_PROBE: constructor arguments invalid')
    for step in steps:
        if not isinstance(step, dict) or not re.fullmatch(r'[A-Za-z_$][\\w$]{0,79}', str(step.get('method', ''))):
            raise ValueError('TOMEY_INVALID_JAVA_PROBE: invalid Java step')
        if not isinstance(step.get('args', []), list) or len(step.get('args', [])) > 8:
            raise ValueError('TOMEY_INVALID_JAVA_PROBE: invalid Java arguments')
    for value in [*constructor, *(v for step in steps for v in step.get('args', []))]:
        if type(value) not in (str, int, float, bool) or len(str(value)) > 2048:
            raise ValueError('TOMEY_INVALID_JAVA_PROBE: unsupported argument')
method_name = re.escape(parts[1])
declaration = re.search(
    r'\b(?:public\s+)?(?:static\s+)?(?:final\s+)?'
    r'(?:String|byte\[\]|CharSequence|StringBuilder|StringBuffer|ByteBuffer|Path|File|URI|Object)\s+'
    + method_name + r'\s*\(\s*(?:final\s+)?'
    r'(?:String|byte\[\]|CharSequence|StringBuilder|StringBuffer|ByteBuffer|Path|File|URI|Object)'
    r'\s+[A-Za-z_$][\w$]*\s*\)',
    code
)
if not declaration and not sequence_mode:
    raise ValueError('TOMEY_INVALID_JAVA_PROBE: no supported one-input/text-output declaration')
if re.search(r'\binterface\s+' + re.escape(parts[0]) + r'\b', code) and not re.search(r'\bstatic\b', declaration.group(0)):
    raise ValueError('TOMEY_INVALID_JAVA_PROBE: interface instance method cannot be constructed')
source_root = target.parent
for component in reversed(package.split('.') if package else []):
    if source_root.name != component:
        raise ValueError('Java package must match source directory')
    source_root = source_root.parent
if not source_root.is_relative_to('/repo'):
    raise ValueError('Java source root outside repository')
# Resolve other checked-out module source roots without running Maven/Gradle,
# downloading dependencies or mounting host caches. Bound the traversal so a
# large repository cannot turn a single probe into an unbounded tree walk.
roots = [source_root]
seen = {str(source_root)}
directories_visited = 0
for parent, directories, _ in os.walk('/repo', followlinks=False):
    directories_visited += 1
    if directories_visited > 12000 or len(roots) >= 48:
        break
    directories[:] = sorted(d for d in directories if d not in (
        '.git', '.gradle', '.m2', 'node_modules', 'target', 'build',
        'dist', 'vendor', '.venv', '__pycache__'))
    relative_parent = Path(parent).relative_to('/repo')
    if relative_parent.parts[-3:] == ('src', 'main', 'java'):
        if parent not in seen:
            roots.append(Path(parent))
            seen.add(parent)
        directories[:] = []
sourcepath = os.pathsep.join(str(root) for root in roots)
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

if sequence_mode:
    # The precompiled driver is constructed by this trusted adapter, not by Qwen.
    harness.write_text(r'''
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
public class TomeyJavaProbe {
  static Object parse(String encoded, Class<?> type) {
    String value=new String(Base64.getDecoder().decode(encoded),StandardCharsets.UTF_8);
    if(type==String.class)return value;
    if(type==int.class || type==Integer.class)return Integer.valueOf(value);
    if(type==long.class || type==Long.class)return Long.valueOf(value);
    if(type==boolean.class || type==Boolean.class)return Boolean.valueOf(value);
    if(type==double.class || type==Double.class)return Double.valueOf(value);
    if(type==float.class || type==Float.class)return Float.valueOf(value);
    if(type==short.class || type==Short.class)return Short.valueOf(value);
    if(type==byte.class || type==Byte.class)return Byte.valueOf(value);
    throw new IllegalArgumentException("Unsupported Java parameter type: "+type.getName());
  }
  static Executable match(Executable[] options,String method,String[] values) {
    for(Executable candidate:options) {
      if(candidate instanceof Method && !((Method)candidate).getName().equals(method))continue;
      Class<?>[] types=candidate.getParameterTypes();
      if(types.length!=values.length)continue;
      try {
        for(int i=0;i<types.length;i++)parse(values[i],types[i]);
        return candidate;
      }catch(IllegalArgumentException e){}
    }
    throw new IllegalArgumentException("No supported public overload: "+method);
  }
  static String[] arguments(String[] tokens,int from,int count) {
    return java.util.Arrays.copyOfRange(tokens,from,from+count);
  }
  static Object[] values(Executable callable,String[] encoded) {
    Class<?>[] types=callable.getParameterTypes();
    Object[] result=new Object[types.length];
    for(int i=0;i<types.length;i++)result[i]=parse(encoded[i],types[i]);
    return result;
  }
  static String out(Object object) {
    if(object==null)return "null";
    if(object instanceof Number || object instanceof Boolean || object instanceof String || object instanceof Character)
      return String.valueOf(object);
    throw new IllegalArgumentException("Unsupported return type: "+object.getClass().getName());
  }
  public static void main(String[] argv) throws Exception {
    java.io.PrintStream out=System.out;
    System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
    Class<?> cls=Class.forName(argv[0]);
    int cursor=1;
    int constructorCount=Integer.parseInt(argv[cursor++]);
    String[] init=arguments(argv,cursor,constructorCount);cursor+=constructorCount;
    Object instance=null;
    if(constructorCount>0) {
      Constructor<?> ctor=(Constructor<?>)match(cls.getConstructors(),"constructor",init);
      instance=ctor.newInstance(values(ctor,init));
    }
    int stepCount=Integer.parseInt(argv[cursor++]);
    String[] results=new String[stepCount];
    for(int j=0;j<stepCount;j++) {
      String name=argv[cursor++];
      int length=Integer.parseInt(argv[cursor++]);
      String[] encoded=arguments(argv,cursor,length);cursor+=length;
      Method method=(Method)match(cls.getMethods(),name,encoded);
      if(!Modifier.isStatic(method.getModifiers()) && instance==null) {
        Constructor<?> ctor=cls.getConstructor();
        instance=ctor.newInstance();
      }
      Object actual=method.invoke(Modifier.isStatic(method.getModifiers())?null:instance,values(method,encoded));
      results[j]=Base64.getEncoder().encodeToString(out(actual).getBytes(StandardCharsets.UTF_8));
    }
    for(String result:results)out.println(result);
  }
}
''')
jvm = ['-Xmx128m', '-XX:ActiveProcessorCount=2', '-XX:+UseSerialGC']
# javac on JDK 21 can exceed a 128 MiB heap while initializing compiler
# modules; keep runtime probes tight, but give compilation bounded headroom.
javac_jvm = ['-Xmx512m', '-XX:ActiveProcessorCount=2', '-XX:+UseSerialGC']
subprocess.run(['/jdk/bin/javac', *['-J'+x for x in javac_jvm], '-proc:none', '-encoding', 'UTF-8',
                '-classpath', str(classes), '-sourcepath', sourcepath, '-d', str(classes),
                str(target), str(harness)], check=True, timeout=15)
if sequence_mode:
    def encode(value):
        return base64.b64encode(str(value).lower().encode() if type(value) is bool else str(value).encode()).decode()
    argv = [(package + '.' if package else '') + parts[0],
            str(len(constructor)), *[encode(v) for v in constructor],
            str(len(steps))]
    for step in steps:
        argv += [step['method'], str(len(step.get('args', [])))]
        argv += [encode(v) for v in step.get('args', [])]
    outcome = subprocess.run(['/jdk/bin/java', *jvm, '-cp', str(classes),
                              'TomeyJavaProbe', *argv], check=True,
                             stdout=subprocess.PIPE, timeout=8)
    lines = outcome.stdout.decode().splitlines()
    if len(lines) != len(steps):
        raise ValueError('Invalid Java stateful sequence output')
    observations = []
    for step, encoded in zip(steps, lines):
        actual = base64.b64decode(encoded, validate=True).decode('utf8')
        expected = step.get('expected')
        observations.append(dict(operation='call', function=step['method'],
                                 actual=actual, expected=expected,
                                 passed=(expected is None or actual == str(expected).lower()
                                         if type(expected) is bool else
                                         expected is None or actual == str(expected))))
    print(json.dumps(dict(steps=observations, constructor=constructor)))
    raise SystemExit(0)
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
