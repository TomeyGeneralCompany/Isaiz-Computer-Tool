import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile,writeFile,rename} from 'node:fs/promises';
import {join,relative,resolve,sep} from 'node:path';
const exec=promisify(execFile);
export async function collectStaticLeads(root:string,repositories:Array<{directory:string;url:string}>,paths:string[],cache:string,signal:AbortSignal) {
  const app=process.env.PROJECT_ROOT||process.cwd();
  if(process.env.LOCAL_STATIC_ANALYSIS==='false')return {status:'disabled',leads:[],runs:[]};
  try {const saved=JSON.parse(await readFile(cache,'utf8'));if(saved.version===1&&Array.isArray(saved.leads)&&Array.isArray(saved.runs)&&saved.runs.length>0&&saved.runs.every((r:any)=>r.status==='completed'))return saved;}catch{}
  const runs:any[]=[],leads:any[]=[];
  for(const repo of repositories) {
    const prefix=relative(root,repo.directory).split(sep).join('/');
    const solidity=paths.find(p=>p.startsWith(prefix+'/')&&p.endsWith('.sol'))?.slice(prefix.length+1);
    for(const engine of ['semgrep',...(solidity?['slither']:[])]) {
      signal.throwIfAborted();
      try {
        const {stdout}=await exec('python3',[resolve(app,'scripts/source-static.py'),'--repository',repo.directory,'--engine',engine,...(engine==='slither'?['--target',solidity!]:[])],{signal,timeout:110000,maxBuffer:128000,cwd:app});
        const value=JSON.parse(stdout);runs.push({repository:repo.url,engine,status:value.status,reason:value.reason});
        for(const lead of (Array.isArray(value.leads)?value.leads:[]).slice(0,64)) {
          if(typeof lead.path!=='string'||!Number.isSafeInteger(lead.line)||lead.line<1)continue;
          const full=resolve(repo.directory,lead.path),local=relative(repo.directory,full);
          if(local==='..'||local.startsWith('..'+sep)||local.startsWith('/'))continue;
          leads.push({path:prefix+'/'+local.split(sep).join('/'),line:lead.line,rule:String(lead.rule).slice(0,160),message:String(lead.message).slice(0,300),engine});
        }
      }catch(error:any){signal.throwIfAborted();runs.push({repository:repo.url,engine,status:'failed',reason:error.code||error.name});}
    }
  }
  const result={version:1,status:'navigation_only',leads:leads.slice(0,128),runs,limitation:'Detectors produce candidates, not verified findings. Inspect and reproduce before reporting. Unsupported scanners do not block source reading.'};
  const temporary=cache+'.'+process.pid+'.tmp';
  await writeFile(temporary,JSON.stringify(result),{mode:0o600});await rename(temporary,cache);
  return result;
}
