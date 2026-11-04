import {readFile,realpath} from 'node:fs/promises';
import {dirname,join,resolve,relative,sep} from 'node:path';

export type FlowFact={path:string;line:number;source:string;relationship:string};
export type FlowTrace={facts:FlowFact[];unresolved:string[];limitation:string};

/** Source-backed and bounded, never an exploitability proof. */
export async function traceSourceCalls(repository:string,file:string,selector:string,maxDepth=5):Promise<FlowTrace> {
  const base=await realpath(repository);
  const facts:FlowFact[]=[]; const unresolved:string[]=[];
  const visited=new Set<string>();
  const safeRead=async(p:string):Promise<string|null>=>{
    if(!p || p.startsWith('/') || p.split(/[\\/]/).includes('..'))return null;
    try{
      const full=await realpath(resolve(base,p));
      const rel=relative(base,full);
      if(rel==='..'||rel.startsWith('..'+sep))return null;
      const code=await readFile(full,'utf8');
      return code.length<=256000?code:null;
    }catch{return null;}
  };
  let currentFile=file,method=selector.split('.').at(-1)||selector;
  for(let depth=0;depth<maxDepth;depth++){
    const key=currentFile+':'+method;
    if(visited.has(key))break;
    visited.add(key);
    const code=await safeRead(currentFile);
    if(!code){unresolved.push('Unable to read '+currentFile);break;}
    const lines=code.split('\n');
    if(!/^[A-Za-z_$][\w$]*$/.test(method)){unresolved.push('Invalid selector '+method);break;}
    const declaration=currentFile.endsWith('.py')
      ?new RegExp('^\\s*(?:async\\s+)?def\\s+'+method+'\\s*\\(')
      :new RegExp('\\b'+method+'\\s*\\(');
    const start=lines.findIndex(line=>declaration.test(line));
    if(start<0){unresolved.push('No source declaration for '+key);break;}
    const boundary=currentFile.endsWith('.py')?
      lines.findIndex((line,i)=>i>start&&/^(?:async\s+)?def\s+/.test(line)):
      -1;
    const until=boundary>=0?Math.min(boundary,start+12):Math.min(lines.length,start+12);
    for(let i=start;i<until;i++){
      if(!lines[i].trim())continue;
      facts.push({path:currentFile,line:i+1,source:lines[i],relationship:i===start?'source declaration':'implementation'});
    }
    const body=lines.slice(start,until).join('\n');
    let next:{path:string;method:string;binding:string}|null=null;
    if(currentFile.endsWith('.java')){
      for(const m of body.matchAll(/\b([A-Z][A-Za-z0-9_]*)\.([A-Za-z_$][\w$]*)\s*\(/g)){
        const p=join(dirname(currentFile),m[1]+'.java').split(sep).join('/');
        if(await safeRead(p)){next={path:p,method:m[2],binding:m[0]};break;}
      }
    }else if(currentFile.endsWith('.py')){
      for(const m of body.matchAll(/\b([A-Za-z_$][\w$]*)\s*\(/g)){
        const fn=m[1];
        const imp=new RegExp('^from\\s+([A-Za-z_][\\w.]*)\\s+import\\s+[^\\n]*\\b'+fn+'\\b','m').exec(code);
        if(!imp)continue;
        const p=imp[1].replace(/\./g,'/')+'.py';
        if(await safeRead(p)){next={path:p,method:fn,binding:m[0]};break;}
      }
    }else if(/\.(?:cjs|js|mjs)$/.test(currentFile)){
      for(const m of body.matchAll(/\b([A-Za-z_$][\w$]*)\s*\(/g)){
        const fn=m[1];
        const imp=new RegExp('(?:const|let|var)\\s*\\{[^}]*\\b'+fn+'\\b[^}]*\\}\\s*=\\s*require\\(["\\x27]([^"\\x27]+)["\\x27]\\)').exec(code);
        if(!imp || !imp[1].startsWith('./'))continue;
        const p=join(dirname(currentFile),imp[1]).split(sep).join('/');
        if(await safeRead(p)){next={path:p,method:fn,binding:m[0]};break;}
      }
    }
    if(!next)break;
    unresolved.push('Direct source reference '+currentFile+' -> '+next.path+' ('+next.binding+'); input trust and runtime dispatch still require assessment');
    currentFile=next.path;method=next.method;
  }
  return {facts,unresolved,limitation:'Bounded source-resolved call references only. Attacker control, runtime reachability, sanitization and security impact must still be verified.'};
}
