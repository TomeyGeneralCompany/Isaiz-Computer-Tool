/** Conservative controller-owned source-grounded stateful probes.
 * Nominate only an explicit factory and an actually declared public method.
 * All resulting calls are observations, never automatic vulnerability proof.
 */
import type {PolyglotSequence} from './polyglot-sequence';
export type StatefulSourcePlan={
  kind:'python_sequence'|'javascript_sequence';selector:string;
  sequence:PolyglotSequence;factoryLine:number;methodLine:number;
};
const lineAt=(source:string,pos:number)=>source.slice(0,pos).split('\n').length;
/** Fixture only declared primitive defaults/types; never evaluate source expressions. */
function parameterFixtures(parameters:string,python:boolean,fallback:number):PolyglotSequence['constructor']|null {
  if(!parameters.trim())return [];
  const parts=parameters.split(',');if(parts.length>8)return null;
  const values:PolyglotSequence['constructor']=[];
  for(const part of parts) {
    const match=/^\s*([A-Za-z]\w*)(?:\s*:\s*(int|float|bool|str))?(?:\s*=\s*(.+))?\s*$/.exec(part);
    if(!match || (!python && match[2]))return null;
    const literal=match[3]?.trim();
    if(literal!==undefined) {
      if(/^-?\d+(?:\.\d+)?$/.test(literal) && Number.isFinite(Number(literal)))values.push(Number(literal));
      else if(/^(?:True|False|true|false)$/.test(literal))values.push(literal.toLowerCase()==='true');
      else if(/^"[^"\\]*"$/.test(literal)||/^'[^'\\]*'$/.test(literal))values.push(literal.slice(1,-1));
      else return null;
    }else values.push(match[2]==='str'?'TOMEY_LOCAL_PROBE':match[2]==='bool'?true:fallback);
  }
  return values;
}
export function sourceStatefulPlans(file:string,source:string):StatefulSourcePlan[] {
  if(source.length>256000)return [];
  if(/\.(?:js|cjs|mjs)$/.test(file)) {
    // The factory must demonstrably return an object literal with a method
    // declaration. Do not guess global methods from unrelated source.
    const factory=/\b(?:exports\.|export\s+(?:const|let)\s+)([A-Za-z][A-Za-z0-9_]*)\s*=\s*(?:async\s*)?(?:function(?:\s+[A-Za-z]\w*)?\s*\([^)]*\)|\([^)]*\)\s*=>)\s*\{/g;
    const plans:StatefulSourcePlan[]=[];
    for(const f of source.matchAll(factory)){
      const tail=source.slice(f.index!,f.index!+6000);
      const returned=/\breturn\s*\{([\s\S]{0,3000})/.exec(tail);
      if(!returned)continue;
      const method=/\b([A-Za-z][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*\{/g;
      for(const m of returned[1].matchAll(method)){
        if(['constructor','toString','valueOf'].includes(m[1]))continue;
        const selectedArgs=parameterFixtures(m[2],false,1);
        if(!selectedArgs)continue;
        const rawParams=/(?:\bfunction(?:\s+[A-Za-z]\w*)?\s*\(|\()\s*([^)]*)\)/.exec(f[0])?.[1].trim()||'';
        const ctor=parameterFixtures(rawParams,false,0);
        if(!ctor)continue;
        plans.push({kind:'javascript_sequence',selector:m[1],factoryLine:lineAt(source,f.index!),
          methodLine:lineAt(source,f.index!+returned.index+returned[0].indexOf(m[0])),
          sequence:{factory:f[1],constructor:ctor,
            steps:[{method:m[1],args:selectedArgs},{method:m[1],args:selectedArgs}]}});
        if(plans.length>=32)return plans;
      }
      if(plans.length>=32)break;
    }
    return plans;
  }
  if(file.endsWith('.py')) {
    const classes=[...source.matchAll(/^class\s+([A-Za-z][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*:/gm)];
    const plans:StatefulSourcePlan[]=[];
    for(const cls of classes.slice(0,8)){
      const tail=source.slice(cls.index!+cls[0].length);
      const next=/^class\s+[A-Za-z]/m.exec(tail);
      const body=tail.slice(0,Math.min(next?.index??tail.length,5000));
      const method=/^    def\s+([A-Za-z][A-Za-z0-9_]*)\s*\(\s*self\s*(?:,\s*([^)]*))?\)\s*(?:->\s*[A-Za-z]\w*)?\s*:/gm;
      const named=[...body.matchAll(method)].filter(x=>!x[1].startsWith('_'));
      const factoryRe=new RegExp('^def\\s+([A-Za-z][A-Za-z0-9_]*)\\s*\\(([^)]*)\\)\\s*(?:->\\s*[A-Za-z]\\w*\\s*)?:[ \\t]*(?:\\n(?:[ \\t]+[^\\n]*\\n){0,6}[ \\t]+)?return\\s+'+cls[1]+'\\s*\\(','gm');
      const make=factoryRe.exec(source);
      if(!make)continue;
      for(const m of named){
        const args=parameterFixtures(m[2]||'',true,1);
        const ctor=parameterFixtures(make[2],true,0);
        if(!args||!ctor)continue;
        plans.push({kind:'python_sequence',selector:m[1],factoryLine:lineAt(source,make.index),
          methodLine:lineAt(source,cls.index!+cls[0].length+m.index!),
          sequence:{factory:make[1],constructor:ctor,
            steps:[{method:m[1],args},{method:m[1],args}]}});
        if(plans.length>=32)return plans;
      }
      if(plans.length>=32)break;
    }
    return plans;
  }
  return [];
}
