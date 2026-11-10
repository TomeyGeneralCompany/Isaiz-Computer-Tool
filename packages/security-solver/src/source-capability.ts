import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile,realpath,stat,lstat} from 'node:fs/promises';
import {resolve,relative,sep} from 'node:path';
import {sourceCodeOnly} from './source-function-reference';
const execute=promisify(execFile);
/** Rank application source ahead of tooling; retain every path for coverage. */
export function sourcePriority(path:string):number {
  // Only rank navigation candidates; every eligible file remains inspectable
  // and callable by the verifier. A file's location does not prove a defect.
  const normalized=path.replaceAll('\\','/');
  const parts=normalized.toLowerCase().split('/').filter(Boolean);
  const folders=parts.slice(0,-1);
  const filename=parts.at(-1)||'';
  const has=(names:readonly string[])=>folders.some(folder=>names.includes(folder));
  const appRoots=['contracts','src','actuator','app'];
  let score=0;

  if(has(appRoots))score+=20;
  // The src/main/java convention is application code; test and generated
  // trees are different investigation targets.
  if(folders.includes('src') && folders.includes('main'))score+=10;

  // Third-party code exists in different locations across languages.
  // Subdirectories like src/vendor, app/node_modules, src/main/java/.../vendor
  // should not win the initial navigation window merely by exposing probes.
  if(has(['node_modules','site-packages','dist-packages','.venv','venv','virtualenv',
    '.m2','.gradle','vendor','vendors','third_party','third-party','external',
    'bower_components','packages-lock','__pycache__']))score-=90;
  if(has(['test','tests','testing','fixtures','fixture','mocks','mock','__tests__',
    'scripts','script','deploy','deployment','.github','examples','example']))score-=60;
  if(has(['dist','build','generated','gen','out','target','coverage',
    '.next','compiled','minified']))score-=45;

  // Solidity's contracts/libs and nested imports, Java library packages,
  // and Python/JS internal compatibility shims remain reachable but begin
  // after first-party application entry points.
  if(has(['lib','libs','libraries','interfaces','imports','deps','dependencies',
    'thirdparty','third_party','third-party']))score-=25;
  if(folders.includes('contracts') && has(['lib','libs','interfaces','imports']))score-=20;

  if(/(?:^|[._-])(?:config|mock|test|spec)(?:[._-]|$)/i.test(filename) ||
     filename.startsWith('.'))score-=40;
  // Support code with common names such as SafeERC20.sol, even when stored
  // directly under contracts/, should be inspected after app callers.
  return score;
}
const supportedCompilers = [
  [0, 8, 30],
  [0, 8, 4],
  [0, 7, 6],
  [0, 6, 12],
  [0, 5, 17]
];
const compare=(a:number[],b:number[])=>a[0]-b[0] || a[1]-b[1] || a[2]-b[2];
/** Unknown syntax stays eligible; exclude only ranges we can conclusively evaluate. */
export function compilerCompatible(range:string):boolean | null {
  const alternatives=range.trim().split('||');
  let unknown=false;
  for(const compiler of supportedCompilers) {
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
  }
  return unknown?null:false;
}
export async function inspectSourceCapability(directory:string,signal?:AbortSignal,recurseSubmodules=true) {
  const root=await realpath(directory);
  const {stdout}=await execute('git',['-c','core.hooksPath=/dev/null','ls-files',...(recurseSubmodules?['--recurse-submodules']:[]),'-z'],{cwd:root,maxBuffer:2000000,timeout:10000,signal});
  const files=stdout.split('\0').filter(Boolean);
  const unsupported:string[]=[];const sourcePaths:string[]=[];let candidates=0,compatible=0,unknown=false;
  const hasSolidity=files.some(f=>f.endsWith(".sol"));
  for(const file of files) {
    signal?.throwIfAborted();
    if(!/\.(sol|py|js|mjs|cjs|java)$/.test(file) || /(?:^|\/)(?:node_modules)\//.test(file) || /(?:hardhat|webpack|eslint|prettier)\.config\.[cm]?js$/.test(file))continue;
    if(hasSolidity && !file.endsWith(".sol") && /(?:^|\/)(?:test|tests|__tests__|testing|fixtures|fixture|mocks|mock|deploy|deploy-configs|scripts|\.github)\//i.test(file))continue;
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
