import {readFile} from 'node:fs/promises';
import {dirname,join,resolve,sep} from 'node:path';

/** Follow only syntactically referenced same-directory Java classes.
 * Display source as evidence; never infer exploitability from a call graph.
 */
export async function observedJavaSourceChain(repository:string,sourceFile:string,maxFiles=3):Promise<string> {
  if(!sourceFile.endsWith('.java'))return '';
  const base=resolve(repository);
  const pending=[sourceFile];
  const visited=new Set<string>();
  const records:string[]=[];
  while(pending.length && records.length<maxFiles){
    const file=pending.shift()!;
    if(visited.has(file))continue;
    visited.add(file);
    const absolute=resolve(base,file);
    if(absolute!==base && !absolute.startsWith(base+sep))continue;
    let code:string;
    try{code=await readFile(absolute,'utf8');}catch{continue;}
    if(code.length>12000)continue;
    const lines=code.split('\n');
    // Exact source lines are quoted verbatim; non-source interpretations are
    // deliberately left to the independent reviewer.
    records.push('SOURCE '+file+'\n'+lines.map((line,i)=>
      (i+1)+': '+line).join('\n'));
    for(const match of code.matchAll(/\b([A-Z][A-Za-z0-9_]*)\.([a-zA-Z][A-Za-z0-9_]*)\s*\(/g)){
      const child=join(dirname(file),match[1]+'.java').split(sep).join('/');
      if(!visited.has(child) && !pending.includes(child))pending.push(child);
    }
  }
  return records.join('\n\n');
}
