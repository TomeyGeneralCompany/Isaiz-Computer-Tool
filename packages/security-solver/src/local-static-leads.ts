import {createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile,writeFile,rename} from 'node:fs/promises';
import {relative,resolve,sep,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';

const exec=promisify(execFile);
const MAX_SLITHER_TARGETS=6;
const COLLECT_SLITHER_LIMIT=24;
const SLITHER_BATCH_SIZE=8;
const excludedSolidityPath=/(?:^|\/)(?:mocks?|test|tests|__tests__|fixtures|vendor|node_modules)(?:\/|$)|Mock\.sol$/i;
const coreContractTerms=/(?:core|vaults?|pools?|markets?|lending|staking|bridge|router|exchange|vesting|minter|treasury|strategy|controller|settlement|liquidation|oracle|escrow|rewards?|deposit|interest|zap)/i;

/**
 * Select a bounded, deterministic set of production Solidity files for Slither.
 * Acquisition order is retained within the same rank, while obvious core
 * protocol contracts are scanned before generic libraries and helpers.
 */
export function rankSolidityStaticTargets(paths:string[],repoPrefix:string,limit=MAX_SLITHER_TARGETS):string[] {
  const candidates=[...new Set(paths.filter(p=>p.startsWith(repoPrefix+'/')&&p.endsWith('.sol')))]
    .map((path,index)=>({path:path.slice(repoPrefix.length+1),index}))
    .filter(({path})=>!excludedSolidityPath.test(path));
  candidates.sort((a,b)=>Number(coreContractTerms.test(b.path))-Number(coreContractTerms.test(a.path))||a.index-b.index);
  return candidates.slice(0,Math.max(0,limit)).map(item=>item.path);
}

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
    if(saved.version===4&&saved.rulesRevision===rulesRevision&&Array.isArray(saved.leads)&&
      Array.isArray(saved.runs)&&saved.runs.length>0&&saved.runs.every((r:any)=>r.status==='completed'))return saved;
  }catch{}

  const runs:any[]=[],leads:any[]=[];
  for(const repo of repositories) {
    const prefix=relative(root,repo.directory).split(sep).join('/');
    const solidityTargets=rankSolidityStaticTargets(paths,prefix,COLLECT_SLITHER_LIMIT);
    const slitherBatches:Array<string[]|undefined>=[];
    for(let i=0;i<solidityTargets.length;i+=SLITHER_BATCH_SIZE)
      slitherBatches.push(solidityTargets.slice(i,i+SLITHER_BATCH_SIZE));
    for(const engine of ['semgrep',...(slitherBatches.length?['slither']:[])]) {
      const batches=engine==='slither'?slitherBatches:[undefined];
      for(const batch of batches) {
        signal.throwIfAborted();
        try {
          const {stdout}=await exec('python3',[resolve(app,'scripts/source-static.py'),'--repository',repo.directory,'--engine',engine,
            ...(batch?['--targets',JSON.stringify(batch)]:[])],{signal,timeout:110000,maxBuffer:256000,cwd:app});
          const value=JSON.parse(stdout);
          const failureDetail=value.status==='failed' ? {
            exitCode:Number.isInteger(value.exitCode)?value.exitCode:undefined,
            diagnostic:typeof value.diagnostic==='string'?value.diagnostic.replace(/[\r\n\t]+/g,' ').slice(0,512):undefined,
          } : {};
          const rawLeads=Array.isArray(value.leads)?value.leads:[];
          runs.push({repository:repo.url,engine,...(batch?{targets:batch,target:batch[0]}:{}),status:value.status,reason:value.reason,
            detectedLeads:Number.isInteger(value.detectedLeads)?value.detectedLeads:rawLeads.length,
            coverage:value.coverage,...failureDetail});
          for(const lead of rawLeads.slice(0,64)) {
            if(typeof lead.path!=='string'||!Number.isSafeInteger(lead.line)||lead.line<1)continue;
            const full=resolve(repo.directory,lead.path),local=relative(repo.directory,full);
            if(local==='..'||local.startsWith('..'+sep)||local.startsWith('/'))continue;
            leads.push({path:prefix+'/'+local.split(sep).join('/'),line:lead.line,rule:String(lead.rule).slice(0,160),
              message:String(lead.message).slice(0,300),severity:lead.severity,engine});
          }
        }catch(error:any) {
          signal.throwIfAborted();
          runs.push({repository:repo.url,engine,...(batch?{targets:batch,target:batch[0]}:{}),status:'failed',reason:error.code||error.name});
        }
      }
    }
  }
  const result={version:4,rulesRevision,status:'navigation_only',leads:leads.slice(0,128),runs,
    limitation:'Detectors produce advisory candidates, not verified findings. Inspect and independently reproduce before reporting.'};
  const temporary=cache+'.'+process.pid+'.tmp';
  await writeFile(temporary,JSON.stringify(result),{mode:0o600});
  await rename(temporary,cache);
  return result;
}
