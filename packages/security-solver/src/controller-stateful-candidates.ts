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
        const args=m[2].trim()?m[2].split(',').map(x=>x.trim()):[];
        if(args.length>1 || args.some(x=>!/^[A-Za-z][A-Za-z0-9_]*$/.test(x)))continue;
        const selectedArgs=args.length?[1]:[];
        const rawParams=/\b(?:function(?:\s+[A-Za-z]\w*)?\s*\(|\()\s*([^)]*)\)/.exec(f[0])?.[1].trim()||'';
        const ctor=rawParams ? rawParams.split(',').map(x=>x.trim()):[];
        if(ctor.length>1||ctor.some(x=>!/^[A-Za-z][A-Za-z0-9_]*$/.test(x)))continue;
        plans.push({kind:'javascript_sequence',selector:m[1],factoryLine:lineAt(source,f.index!),
          methodLine:lineAt(source,f.index!+returned.index+returned[0].indexOf(m[0])),
          sequence:{factory:f[1],constructor:ctor.length?[0]:[],
            steps:[{method:m[1],args:selectedArgs},{method:m[1],args:selectedArgs}]}});
        if(plans.length>=24)return plans;
      }
      if(plans.length>=3)break;
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
      const method=/^    def\s+([A-Za-z][A-Za-z0-9_]*)\s*\(\s*self\s*(?:,\s*([^)]*))?\)\s*:/gm;
      const named=[...body.matchAll(method)].filter(x=>!x[1].startsWith('_'));
      const factoryRe=new RegExp('^def\\s+([A-Za-z][A-Za-z0-9_]*)\\s*\\(([^)]*)\\)\\s*:\\s*\\n(?:[ \\t]+[^\\n]*\\n){0,6}[ \\t]+return\\s+'+cls[1]+'\\s*\\(','gm');
      const make=factoryRe.exec(source);
      if(!make)continue;
      for(const m of named){
        const args=m[2]?.trim()?m[2].split(',').map(x=>x.trim()):[];
        if(args.length>1||args.some(x=>!/^[A-Za-z][A-Za-z0-9_]*(?:\s*=\s*[0-9]+)?$/.test(x)))continue;
        const ctor=make[2].trim()?make[2].split(',').map(x=>x.trim()):[];
        if(ctor.length>1||ctor.some(x=>!/^[A-Za-z][A-Za-z0-9_]*(?:\s*=\s*[0-9]+)?$/.test(x)))continue;
        plans.push({kind:'python_sequence',selector:m[1],factoryLine:lineAt(source,make.index),
          methodLine:lineAt(source,cls.index!+cls[0].length+m.index!),
          sequence:{factory:make[1],constructor:ctor.length?[0]:[],
            steps:[{method:m[1],args:args.length?[1]:[]},{method:m[1],args:args.length?[1]:[]}]}});
        if(plans.length>=24)return plans;
      }
      if(plans.length>=3)break;
    }
    return plans;
  }
  return [];
}
