import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile,writeFile,rename} from 'node:fs/promises';
import {join,relative,resolve,sep,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';

const exec=promisify(execFile);
const MAX_SLITHER_TARGETS=6;
const excludedSolidityPath=/(?:^|\/)(?:mocks?|test|tests|__tests__|fixtures)(?:\/|$)/i;

export async function collectStaticLeads(root:string,repositories:Array<{directory:string;url:string}>,paths:string[],cache:string,signal:AbortSignal,
  testAssetsRoot?:string) {
  // Never infer scanner assets from PROJECT_ROOT; Crucible sets that variable
  // to a temporary target workspace. A caller may supply fixture assets in
  // explicit local tests without changing the production asset resolution.
  const app=testAssetsRoot||resolve(dirname(fileURLToPath(import.meta.url)),'../../..');
  if(process.env.LOCAL_STATIC_ANALYSIS==='false')return {status:'disabled',leads:[],runs:[]};
  const revision=createHash('sha256');
  try {
    for(const file of ['scripts/source-static.py','scripts/static-leads.yaml','scripts/vendor/semgrep-rules/manifest.json'])
      revision.update(await readFile(resolve(app,file)));
  } catch(error:any) {
    signal.throwIfAborted();
    return {status:'unavailable',leads:[],runs:[{engine:'configuration',status:'unavailable',reason:error.code||error.name}]};
  }
  const rulesRevision=revision.digest('hex');
  try {
    const saved=JSON.parse(await readFile(cache,'utf8'));
    if(saved.version===3&&saved.rulesRevision===rulesRevision&&Array.isArray(saved.leads)&&
      Array.isArray(saved.runs)&&saved.runs.length>0&&saved.runs.every((r:any)=>r.status==='completed'))return saved;
  }catch{}

  const runs:any[]=[],leads:any[]=[];
  for(const repo of repositories) {
    const prefix=relative(root,repo.directory).split(sep).join('/');
    // `paths` is already project-ranked by acquisition. Scan a bounded set of
    // project-owned contracts rather than whichever Solidity file appears first
    // (often a mock or dependency). The scanner output remains advisory only.
    const solidityTargets=[...new Set(paths.filter(p=>p.startsWith(prefix+'/')&&p.endsWith('.sol')))]
      .map(p=>p.slice(prefix.length+1))
      .filter(p=>!excludedSolidityPath.test(p))
      .slice(0,MAX_SLITHER_TARGETS);
    for(const engine of ['semgrep',...(solidityTargets.length?['slither']:[])]) {
      const targets=engine==='slither'?solidityTargets:[undefined];
      for(const target of targets) {
        signal.throwIfAborted();
        try {
          const {stdout}=await exec('python3',[resolve(app,'scripts/source-static.py'),'--repository',repo.directory,'--engine',engine,
            ...(target?['--target',target]:[])],{signal,timeout:110000,maxBuffer:128000,cwd:app});
          const value=JSON.parse(stdout);
          const failureDetail=value.status==='failed' ? {
            exitCode:Number.isInteger(value.exitCode)?value.exitCode:undefined,
            diagnostic:typeof value.diagnostic==='string'?value.diagnostic.replace(/[\r\n\t]+/g,' ').slice(0,512):undefined,
          } : {};
          runs.push({repository:repo.url,engine,...(target?{target}:{}),status:value.status,reason:value.reason,coverage:value.coverage,...failureDetail});
          for(const lead of (Array.isArray(value.leads)?value.leads:[]).slice(0,64)) {
            if(typeof lead.path!=='string'||!Number.isSafeInteger(lead.line)||lead.line<1)continue;
            const full=resolve(repo.directory,lead.path),local=relative(repo.directory,full);
            if(local==='..'||local.startsWith('..'+sep)||local.startsWith('/'))continue;
            leads.push({path:prefix+'/'+local.split(sep).join('/'),line:lead.line,rule:String(lead.rule).slice(0,160),
              message:String(lead.message).slice(0,300),severity:lead.severity,engine});
          }
        }catch(error:any) {
          signal.throwIfAborted();
          runs.push({repository:repo.url,engine,...(target?{target}:{}),status:'failed',reason:error.code||error.name});
        }
      }
    }
  }
  const result={version:3,rulesRevision,status:'navigation_only',leads:leads.slice(0,128),runs,
    limitation:'Detectors produce advisory candidates, not verified findings. Inspect and independently reproduce before reporting.'};
  const temporary=cache+'.'+process.pid+'.tmp';
  await writeFile(temporary,JSON.stringify(result),{mode:0o600});
  await rename(temporary,cache);
  return result;
}
