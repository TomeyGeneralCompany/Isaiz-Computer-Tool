/** Deterministic Java source-driven arguments, mirroring Solidity ABI fixtures.
 * Conservatively supports public primitive/String instance methods.
 * Unknown types and ambiguous overloads fail closed; no invented expectations.
 */
import type {JavaSequence} from './java-sequence';
export interface ControllerJavaProbe {selector:string;sequence:JavaSequence;methodLine:number}
const typeFixtures:Record<string,unknown>={
  int:1,long:1,short:1,byte:1,float:1,double:1,
  boolean:true,char:'A',String:'TOMEY_LOCAL_PROBE',
  'java.lang.String':'TOMEY_LOCAL_PROBE',
};
function argumentsFor(parameters:string):unknown[]|null {
  if(!parameters.trim())return [];
  const args:unknown[]=[];
  for(const fragment of parameters.split(',')){
    const parameter=fragment.trim().replace(/\bfinal\s+/g,'').replace(/@\w+(?:\([^)]*\))?\s*/g,'');
    const match=/^([\w.]+)\s+[A-Za-z_$]\w*$/.exec(parameter);
    if(!match||!(match[1] in typeFixtures)||args.length>=8)return null;
    args.push(typeFixtures[match[1]]);
  }
  return args;
}
export function controllerJavaProbes(file:string,source:string):ControllerJavaProbe[] {
  if(!file.endsWith('.java')||source.length>256000)return [];
  const cls=file.split('/').at(-1)!.slice(0,-5);
  if(!new RegExp('\\b(?:public\\s+)?class\\s+'+cls+'\\b').test(source))return [];
  // Explicit constructors must have at least one safely fixtureable form;
  // the implicit default constructor exists only when no constructors exist.
  const ctorRe=new RegExp('\\b(?:public|protected|private)\\s+'+cls+'\\s*\\(([^)]*)\\)\\s*\\{','g');
  const constructors=[...source.matchAll(ctorRe)];
  const visible=constructors.filter(c=>!c[0].startsWith('private'));
  const constructorArgs=constructors.length?
    visible.map(c=>argumentsFor(c[1])).find(a=>a!==null)??null:[];
  if(!constructorArgs)return [];
  const methodRe=/\bpublic\s+(?:(?:static|final|synchronized)\s+)*(?:void|int|long|short|byte|boolean|String|java\.lang\.String)\s+([A-Za-z_$]\w*)\s*\(([^)]*)\)\s*(?:throws\s+[\w.,\s]+)?\s*\{/g;
  const found=[...source.matchAll(methodRe)].filter(m=>
    !['toString','getClass','hashCode','equals','wait','notify'].includes(m[1]));
  const counts=new Map<string,number>();
  for(const m of found)counts.set(m[1],(counts.get(m[1])||0)+1);
  const runnable=found.flatMap(m=>{
    if(counts.get(m[1])!==1)return [];
    const args=argumentsFor(m[2]);
    if(!args)return [];
    return [{name:m[1],args,methodLine:source.slice(0,m.index!).split('\n').length}];
  });
  const getters=runnable.filter(m=>/^(?:get[A-Z]|is[A-Z]|current|count|balance|size|value|total|owner|operator)/.test(m.name)&&m.args.length===0);
  const prioritized=[...runnable].sort((a,b)=>{
    const rank=(name:string)=>/^(?:rotate|set|change|update|transfer|grant|assign|advance|increment|decrement|withdraw|deposit)/.test(name)?0:1;
    return rank(a.name)-rank(b.name)||a.methodLine-b.methodLine;
  });
  return prioritized.slice(0,6).map(method=>{
    const getter=getters.find(g=>g.name!==method.name);
    const steps=getter?[
      {method:getter.name,args:getter.args},
      {method:method.name,args:method.args},
      {method:getter.name,args:getter.args}
    ]:[
      {method:method.name,args:method.args},
      {method:method.name,args:method.args}
    ];
    return {selector:cls+'.'+method.name,methodLine:method.methodLine,
      sequence:{constructor:constructorArgs,steps}};
  });
}
