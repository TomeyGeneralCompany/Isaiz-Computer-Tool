"""Execute bounded declarative Java constructor/method sequences inside bubblewrap."""
import json, base64, os, re, subprocess
from pathlib import Path

spec=json.loads(Path('/spec.json').read_text())
target=(Path('/repo')/spec['file']).resolve(strict=True)
if not target.is_relative_to('/repo') or target.suffix!='.java':
    raise ValueError('TOMEY_INVALID_JAVA_PROBE: invalid source')
parts=spec['function'].split('.')
if len(parts)!=2 or parts[0]!=target.stem:
    raise ValueError('TOMEY_INVALID_JAVA_PROBE: Class.method must match file')
sequence=spec['sequence']
steps=sequence['steps']
if not any(step['method']==parts[1] for step in steps):
    raise ValueError('TOMEY_INVALID_JAVA_PROBE: selected method not invoked')
source=target.read_text()
package_match=re.search(r'\bpackage\s+([\\w.]+)\s*;',source)
package=package_match[1] if package_match else ''
root=target.parent
for component in reversed(package.split('.') if package else []):
    if root.name!=component:raise ValueError('TOMEY_INVALID_JAVA_PROBE: package layout mismatch')
    root=root.parent
roots=[root]
visited=0
for parent,dirs,_ in os.walk('/repo',followlinks=False):
    visited+=1
    if visited>12000 or len(roots)>48:break
    dirs[:]=sorted(d for d in dirs if d not in {'.git','.gradle','.m2','node_modules','target','build','dist','.venv'})
    if Path(parent).parts[-3:]==('src','main','java'):
        if Path(parent) not in roots:roots.append(Path(parent))
        dirs[:]=[]
classes=Path('/tmp/classes');classes.mkdir()
harness=Path('/tmp/TomeyJavaSequence.java')
harness.write_text(r"""
import java.lang.reflect.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
public class TomeyJavaSequence {
 static Object arg(String encoded,Class<?> type) {
  String raw=new String(Base64.getDecoder().decode(encoded.substring(2)),StandardCharsets.UTF_8);
  char tag=encoded.charAt(0);
  if(tag=='s') {
   if(type==String.class||type==CharSequence.class||type==Object.class)return raw;
   if(type==char.class||type==Character.class) {if(raw.length()!=1)throw new IllegalArgumentException("char");return raw.charAt(0);}
  }
  if(tag=='b'&&(type==boolean.class||type==Boolean.class))return Boolean.parseBoolean(raw);
  if(tag=='n') {
   if(type==int.class||type==Integer.class)return Integer.valueOf(raw);
   if(type==long.class||type==Long.class)return Long.valueOf(raw);
   if(type==double.class||type==Double.class)return Double.valueOf(raw);
   if(type==float.class||type==Float.class)return Float.valueOf(raw);
   if(type==short.class||type==Short.class)return Short.valueOf(raw);
   if(type==byte.class||type==Byte.class)return Byte.valueOf(raw);
  }
  throw new IllegalArgumentException("unsupported argument type "+type.getName());
 }
 static Object[] bind(String[] encoded,Class<?>[] types) {
  if(encoded.length!=types.length)throw new IllegalArgumentException("argument count");
  Object[] values=new Object[types.length];
  for(int i=0;i<types.length;i++)values[i]=arg(encoded[i],types[i]);
  return values;
 }
 static Object construct(Class<?> type,String[] args) throws Exception {
  for(Constructor<?> c:type.getConstructors()) {
   try{return c.newInstance(bind(args,c.getParameterTypes()));}
   catch(IllegalArgumentException ignored){}
  }
  throw new IllegalArgumentException("no supported public constructor");
 }
 static Method method(Class<?> type,String name,String[] args) {
  for(Method m:type.getMethods()) {
   if(!m.getName().equals(name))continue;
   try{bind(args,m.getParameterTypes());return m;}catch(IllegalArgumentException ignored){}
  }
  throw new IllegalArgumentException("no supported public method: "+name);
 }
 public static void main(String[] argv) throws Exception {
  java.io.PrintStream out=System.out;
  System.setOut(new java.io.PrintStream(java.io.OutputStream.nullOutputStream()));
  Class<?> type=Class.forName(argv[0]);
  int p=1, count=Integer.parseInt(argv[p++]);
  String[] ctor=new String[count];
  for(int i=0;i<count;i++)ctor[i]=argv[p++];
  Object instance=null;
  int steps=Integer.parseInt(argv[p++]);
  String[] results=new String[steps];
  for(int i=0;i<steps;i++){
   String name=argv[p++];int n=Integer.parseInt(argv[p++]);String[] args=new String[n];
   for(int j=0;j<n;j++)args[j]=argv[p++];
   Method m=method(type,name,args);
   if(!Modifier.isStatic(m.getModifiers())&&instance==null)instance=construct(type,ctor);
   Object result=m.invoke(Modifier.isStatic(m.getModifiers())?null:instance,bind(args,m.getParameterTypes()));
   String value=result==null?"null":String.valueOf(result);
   if(value.length()>16000)throw new IllegalArgumentException("result too large");
   results[i]=Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }
  for(String result:results)out.println(result);
 }
}
""")
jvm=['-Xmx128m','-XX:ActiveProcessorCount=2','-XX:+UseSerialGC']
compiler=['-J-Xmx512m','-J-XX:ActiveProcessorCount=2','-J-XX:+UseSerialGC']
subprocess.run(['/jdk/bin/javac',*compiler,'-proc:none','-encoding','UTF-8',
                '-classpath',str(classes),'-sourcepath',os.pathsep.join(map(str,roots)),
                '-d',str(classes),str(target),str(harness)],check=True,timeout=15)
def token(value):
    if isinstance(value,bool):tag='b';text=str(value).lower()
    elif isinstance(value,(int,float)):tag='n';text=str(value)
    elif isinstance(value,str):tag='s';text=value
    else:raise ValueError('TOMEY_INVALID_JAVA_PROBE: invalid argument')
    return tag+':'+base64.b64encode(text.encode()).decode()
ctor=[token(x) for x in sequence.get('constructor',[])]
argv=[(package+'.' if package else '')+parts[0],str(len(ctor)),*ctor,str(len(steps))]
for step in steps:
    args=[token(x) for x in step.get('args',[])]
    argv.extend([step['method'],str(len(args)),*args])
result=subprocess.run(['/jdk/bin/java',*jvm,'-cp',str(classes),'TomeyJavaSequence',*argv],
                      check=True,stdout=subprocess.PIPE,timeout=8)
lines=result.stdout.decode().splitlines()
if len(lines)!=len(steps):raise ValueError('TOMEY_INVALID_JAVA_PROBE: incorrect output count')
observed=[]
for step,line in zip(steps,lines):
    actual=base64.b64decode(line,validate=True).decode()
    expected=step.get('expected')
    passed=(str(expected).lower() if isinstance(expected,bool) else str(expected))==actual if 'expected' in step else True
    observed.append(dict(operation='call',function=step['method'],actual=actual,**({'expected':expected} if 'expected' in step else {}),passed=passed))
print(json.dumps({'constructor':sequence.get('constructor',[]),'steps':observed}))
