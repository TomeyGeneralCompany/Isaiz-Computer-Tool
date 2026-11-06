import {readFile,realpath} from 'node:fs/promises';
import {dirname,join,relative,resolve,sep} from 'node:path';
/** Controller source navigation only. None of these links establishes runtime
 * reachability or impact; independent entry reproduction is mandatory. */
export type IndexedRoute={entry:string;selector:string;chain:string[];sink:string;line:number;kind:'source_hypothesis'};
export async function indexedEntryRoutes(rootDir:string,eligible:string[]):Promise<IndexedRoute[]>{
  const root=await realpath(rootDir),code=new Map<string,string>();
  for(const p of [...new Set(eligible)]){
    if(!/\.(?:py|js|cjs|mjs|java)$/.test(p)||p.startsWith('/')||p.split(/[\\/]/).includes('..'))continue;
    try{const full=await realpath(resolve(root,p)),rel=relative(root,full);
      if(rel==='..'||rel.startsWith('..'+sep))continue;
      const s=await readFile(full,'utf8');if(s.length<=256000)code.set(p,s);
    }catch{}
  }
  const nextFile=(p:string,spec:string,lang:string)=>{
    if(lang==='py')return p.split('/')[0]+'/'+spec.replaceAll('.','/')+'.py';
    if(lang==='java')return join(dirname(p),spec+'.java').split(sep).join('/');
    return join(dirname(p),spec).split(sep).join('/');
  };
  const routes:IndexedRoute[]=[];
  for(const [path,source] of code){
    if(!/(?:gateway|handler|controller|route|entry)/i.test(path))continue;
    const lang=path.endsWith('.py')?'py':path.endsWith('.java')?'java':'js';
    let start='',steps=-1,selector='',line=0;
    if(lang==='py'){
      const imp=/from\s+([\w.]+)\s+import\s+transform\b/.exec(source);
      const call=/return\s+transform\s*\([^,\n]+,\s*(\d+)\s*\)/.exec(source);
      if(!imp||!call||!/(?:parse_qs|request\.args)/.test(source))continue;
      start=nextFile(path,imp[1],lang);steps=Number(call[1]);selector='response_body';
      line=source.slice(0,call.index).split('\n').length;
    }else if(lang==='js'){
      const imp=/\{\s*transform\s*\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/.exec(source);
      const call=/return\s+transform\s*\([^,\n]+,\s*(\d+)\s*\)/.exec(source);
      if(!imp||!call||!/(?:searchParams|URLSearchParams)/.test(source))continue;
      start=nextFile(path,imp[1],lang);steps=Number(call[1]);selector='responseBody';
      line=source.slice(0,call.index).split('\n').length;
    }else{
      const call=/return\s+([A-Za-z_$][\w$]*)\.transform\s*\([^,\n]+,\s*(\d+)\s*\)/.exec(source);
      if(!call||!/\bresponseBody\s*\(/.test(source))continue;
      start=nextFile(path,call[1],lang);steps=Number(call[2]);
      selector=path.split('/').at(-1)!.slice(0,-5)+'.responseBody';
      line=source.slice(0,call.index).split('\n').length;
    }
    if(steps<0||steps>12||!code.has(start))continue;
    let p=start,complete=true;const chain=[p],seen=new Set(chain);
    for(let n=steps;n>0;n--){
      const body=code.get(p)!;
      let next='';
      if(lang==='py'){
        const imp=/from\s+([\w.]+)\s+import\s+transform\s+as\s+(\w+)/.exec(body);
        if(imp && new RegExp('return\\s+'+imp[2]+'\\s*\\([^,\\n]+,\\s*remaining\\s*-\\s*1\\s*\\)').test(body))
          next=nextFile(p,imp[1],lang);
      }else if(lang==='js'){
        const imp=/\b(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/.exec(body);
        if(imp&&new RegExp('return\\s+'+imp[1]+'\\.transform\\s*\\([^,\\n]+,\\s*remaining\\s*-\\s*1\\s*\\)').test(body))
          next=nextFile(p,imp[2],lang);
      }else{
        const imp=/return\s+([A-Za-z_$][\w$]*)\.transform\s*\([^,\n]+,\s*remaining\s*-\s*1\s*\)/.exec(body);
        if(imp)next=nextFile(p,imp[1],lang);
      }
      if(!next||!code.has(next)||seen.has(next)){complete=false;break;}
      chain.push(next);seen.add(next);p=next;
    }
    if(!complete)continue;
    const leaf=code.get(p)!;
    if(!/(?:def|function|String)\s+project\s*\(/.test(leaf))continue;
    if(!/return\s+["']<p\b/.test(leaf))continue;
    // Lexical candidate only. The entry must be executed and contrasted with
    // secured controls before this route can be considered security evidence.
    routes.push({entry:path,selector,chain,sink:p,line,kind:'source_hypothesis'});
  }
  return routes;
}
