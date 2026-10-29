import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile,realpath,stat,lstat} from 'node:fs/promises';
import {resolve,relative,sep} from 'node:path';
import {sourceCodeOnly} from './source-function-reference';
const execute=promisify(execFile);
/** Rank application source ahead of tooling; retain every path for coverage. */
export function sourcePriority(path:string):number {
  let score=0;
  if(/(?:^|\/)(?:contracts|src|actuator|app|lib)\//.test(path))score+=20;
  if(/(?:^|\/)(?:test|tests|fixtures|mocks|vendors?|scripts?|deploy|node_modules|\.github)\//i.test(path))score-=60;
  if(/(?:^|\/)(?:libs|interfaces)\//i.test(path))score-=10;
  if(/(?:^|\/)[^/]*(?:config|mock|test)[^/]*\.[^.]+$/i.test(path)||/(?:^|\/)\./.test(path))score-=40;
  return score;
}
const compiler=[0,8,30];
const compare=(a:number[],b:number[])=>a[0]-b[0] || a[1]-b[1] || a[2]-b[2];
/** Unknown syntax stays eligible; exclude only ranges we can conclusively evaluate. */
export function compilerCompatible(range:string):boolean | null {
  const alternatives=range.trim().split('||');
  let unknown=false;
  for(const alternative of alternatives) {
    const tokens=[...alternative.matchAll(/(\^|~|>=|<=|>|<|=)?\s*(\d+)\.(\d+)\.(\d+)/g)];
    if(!tokens.length || alternative.replace(/(\^|~|>=|<=|>|<|=)?\s*\d+\.\d+\.\d+/g,'').trim()) {unknown=true;continue;}
    const matches=tokens.every(t=>{
      const v=t.slice(2).map(Number),cmp=compare(compiler,v);
      switch(t[1]) {
        case '>=':return cmp>=0;case '<=':return cmp<=0;case '>':return cmp>0;case '<':return cmp<0;
        case '^':return cmp>=0 && compare(compiler,v[0]?[v[0]+1,0,0]:v[1]?[0,v[1]+1,0]:[0,0,v[2]+1])<0;
        case '~':return cmp>=0 && compare(compiler,[v[0],v[1]+1,0])<0;
        default:return cmp===0;
      }
    });
    if(matches)return true;
  }
  return unknown?null:false;
}
export async function inspectSourceCapability(directory:string,signal?:AbortSignal,recurseSubmodules=true) {
  const root=await realpath(directory);
  const {stdout}=await execute('git',['-c','core.hooksPath=/dev/null','ls-files',...(recurseSubmodules?['--recurse-submodules']:[]),'-z'],{cwd:root,maxBuffer:2000000,timeout:10000,signal});
  const files=stdout.split('\0').filter(Boolean);
  const unsupported:string[]=[];const sourcePaths:string[]=[];let candidates=0,compatible=0,unknown=false;
  for(const file of files) {
    signal?.throwIfAborted();
    if(!/\.(sol|py|js|mjs|cjs|java)$/.test(file) || /(?:^|\/)(?:node_modules)\//.test(file) || /(?:hardhat|webpack|eslint|prettier)\.config\.[cm]?js$/.test(file))continue;
    if(++candidates>10000) {unknown=true;break;}
    let full:string;
    try {
      if((await lstat(resolve(root,file))).isSymbolicLink()) {unknown=true;unsupported.push(file+': symlink not inspected');continue;}
      full=await realpath(resolve(root,file));
    } catch(error:any) {
      if(!['ENOENT','EACCES','ELOOP'].includes(error.code))throw error;
      unknown=true;unsupported.push(file+': unreadable source; coverage incomplete');continue;
    }
    const rel=relative(root,full);
    if(rel==='..'||rel.startsWith('..'+sep)|| (await stat(full)).size>256000) {unknown=true;continue;}
    if(file.endsWith('.java')) {
      const code=sourceCodeOnly(await readFile(full,'utf8'));
      // Source inspection is broader than the fixed reproduction adapter.
      // Keep Java source eligible even when no directly probeable signature is
      // found: excluding it conceals security-relevant callers and state.
      // The verifier itself still enforces supported entrypoints and returns
      // unsupported evidence rather than pretending an execution occurred.
      void code;
    }
    if(!file.endsWith('.sol')) {compatible++;sourcePaths.push(file);continue;}
    const code=sourceCodeOnly(await readFile(full,'utf8'));
    const pragmas=[...code.matchAll(/\bpragma\s+solidity\s+([^;]+);/g)];
    if(pragmas.some(p=>compilerCompatible(p[1])===false))unsupported.push(file+': requires a different Solidity compiler');
    else {compatible++;sourcePaths.push(file);}
  }
  sourcePaths.sort((a,b)=>sourcePriority(b)-sourcePriority(a)||a.localeCompare(b,"en"));
  const blocked=!unknown && compatible===0;
  return {blocked,reason:blocked?(candidates?'No candidate matches the installed compiler or function-probe entrypoint':'No runnable Python, JavaScript, Java or Solidity sources found'):null,
    compatibleFiles:compatible,sourcePaths,unsupported:unsupported.slice(0,30),limitation:'Preflight checks source types and recognized compiler ranges; Java files without directly supported entrypoints remain inspectable but may not be reproducible. Deployment dependencies and runtime behavior still require probes.'};
}
