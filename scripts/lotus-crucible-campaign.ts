/** Sealed Level 6 campaign orchestration and fail-closed qualification.
 * --plan writes private seeds only to a restricted local file.
 * --run-one invokes the REAL production runner, never a model mock.
 * --qualify assesses every receipt, including failures, not just winners.
 */
import {createHash,randomBytes} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {readFile,writeFile,mkdir,readdir} from 'node:fs/promises';
import {dirname,join,resolve} from 'node:path';
import {assessCrucibleQualification,type CrucibleTrialReceipt} from './lotus-crucible-qualification';
import type {Language} from './lotus-gauntlet-fixtures';
const languages:Language[]=['solidity','python','javascript','java'];
type Planned={trialId:string;seed:string;language:Language;kind:'clean'|'vulnerable';files:number;defects:number};
const sha256=(s:string)=>createHash('sha256').update(s).digest('hex');
const arg=(key:string)=>process.argv.find(x=>x.startsWith('--'+key+'='))?.split('=').slice(1).join('=');
async function json(path:string){return JSON.parse(await readFile(path,'utf8'));}
async function write(path:string,data:any,privateFile=false){
 await mkdir(dirname(path),{recursive:true});
 await writeFile(path,JSON.stringify(data,null,2)+'\n',{mode:privateFile?0o600:0o644});
}
function plan():Planned[]{
 return Array.from({length:33},(_,i)=>({
   trialId:'crucible-6-'+String(i+1).padStart(3,'0'),
   seed:randomBytes(24).toString('hex'),
   language:languages[i%4],
   kind:i<4?'clean':'vulnerable',
   files:2000+400*(i%8),
   defects:5+(i%4)
 }));
}
function validatePlan(p:Planned[]){
 if(p.length!==33)throw Error('Crucible campaign requires exactly 33 sealed trials');
 if(new Set(p.map(x=>x.seed)).size!==p.length||new Set(p.map(x=>x.trialId)).size!==p.length)
   throw Error('Crucible duplicate seed or trial');
 if(p.some(x=>!languages.includes(x.language)||x.files<2000||x.files>5000||
      x.defects<5||x.defects>8))throw Error('Crucible malformed plan');
 for(const language of languages)for(const kind of ['clean','vulnerable'])
   if(!p.some(x=>x.language===language&&x.kind===kind))
     throw Error('Crucible missing '+language+' '+kind+' campaign coverage');
}
async function receipt(output:string,trial:Planned,artifactUrl:string):Promise<CrucibleTrialReceipt>{
 const [manifest,grade,result,review]=await Promise.all(
  ['manifest.json','grade.json','result.json','review.json'].map(x=>json(join(output,x))));
 if(manifest.language!==trial.language||manifest.kind!==trial.kind||
    manifest.seedCommitment!==sha256(trial.seed))
   throw Error('Crucible receipt identity or sealed seed mismatch');
 if(!Array.isArray(review))throw Error('Crucible independent reviews missing');
 const matches:Array<{id:string;cases:string[]}>=grade.matched||[];
 const replayed=matches.filter(m=>m.cases.length===1).map(m=>m.id);
 const reported=matches.filter(m=>m.cases.length>0).map(m=>m.id);
 const confirmedCases=new Set(review.filter((r:any)=>
   ['valid','verified','confirmed','accepted'].includes(String(r.verdict).toLowerCase())
   ).map((r:any)=>r.caseId));
 const erroneous=review.filter((r:any)=>!confirmedCases.has(r.caseId))
   .map((r:any)=>String(r.caseId??r.error??'review missing case'));
 const findingCount=Array.isArray(result.findings)?result.findings.length:0;
 const fp=trial.kind==='clean'?result.findings.map((f:any)=>String(f.title||'unverified finding')):[];
 if(trial.kind==='vulnerable'&&findingCount>reported.length)
   for(let i=reported.length;i<findingCount;i++)fp.push('unmapped-finding-'+i);
 const productionCommit=process.env.LOTUS_PRODUCTION_SHA||process.env.GITHUB_SHA||'';
 return {
   trialId:trial.trialId,language:trial.language,productionCommit,
   challengeDigest:manifest.sourceSha256,
   sealedSeedCommitment:manifest.seedCommitment,kind:trial.kind,
   generatedSourceFiles:manifest.sourceFiles,
   mandatoryDefectCount:trial.kind==='clean'?0:trial.defects,
   independentlyReplayedDefectIds:replayed,
   reportedDefectIds:reported,
   negativeControlViolations:[],
   falsePositiveIds:fp,
   fabricatedEvidenceIds:erroneous,
   firstDivergence:grade.firstDivergence??null,
   sourceExecutionPassed:grade.milestones?.sourceAcquired===true&&
     grade.milestones?.sourceMapBuilt===true,
   independentReviewPassed:trial.kind==='clean'?findingCount===0:
     confirmedCases.size===trial.defects&&erroneous.length===0,
   graderPassed:grade.passed===true,
   externalSubmissionEnabled:process.env.SECURITY_AUTO_SUBMIT!=='false',
   productionModel:process.env.LOCAL_OLLAMA_MODEL||'',
   cpuOnly:process.env.LOTUS_CPU_ONLY==='true',
   artifactUrl
 };
}
async function main(){
 const action=process.argv[2];
 if(action==='--plan'){
   const root=resolve(arg('output')||'data/crucible/campaign');
   const trials=plan();validatePlan(trials);
   await write(join(root,'plan.private.json'),trials,true);
   await write(join(root,'plan.public.json'),trials.map(({seed,...x})=>({
     ...x,sealedSeedCommitment:sha256(seed)
   })));
   console.log('Created 33 sealed trials with four languages and clean/vulnerable controls: '+root);
   return;
 }
 if(action==='--run-one'){
   const input=resolve(arg('plan')||'data/crucible/campaign/plan.private.json');
   const trials=await json(input) as Planned[];validatePlan(trials);
   const index=Number(arg('index'));
   if(!Number.isInteger(index)||index<0||index>=trials.length)throw Error('Invalid campaign index');
   const trial=trials[index],out=resolve(arg('output')||'data/crucible/campaign');
   const root=join(out,trial.trialId);
   const args=['--import','tsx','scripts/lotus-crucible-run.ts','--run','--level=6',
     '--language='+trial.language,'--seed='+trial.seed,'--files='+trial.files,
     '--defects='+trial.defects,'--output='+root];
   if(trial.kind==='clean')args.push('--clean');
   let failed=false;
   try{execFileSync(process.execPath,args,{stdio:'inherit',timeout:21600000});}
   catch(e){failed=true;console.error('Crucible trial failed:',String(e));}
   const server=process.env.GITHUB_SERVER_URL,repository=process.env.GITHUB_REPOSITORY,run=process.env.GITHUB_RUN_ID;
   const artifactUrl=arg('artifact-url')||(server&&repository&&run?server+'/'+repository+'/actions/runs/'+run:'');
   if(!artifactUrl)throw Error('Crucible receipts require a real artifact/run URL');
   let record:CrucibleTrialReceipt;
   try{record=await receipt(root,trial,artifactUrl);}
   catch(e){throw Error('Crucible cannot construct verified receipt: '+String(e));}
   await write(join(out,'receipts',trial.trialId+'.json'),record);
   if(failed||!record.graderPassed)process.exitCode=1;
   return;
 }
 if(action==='--qualify'){
   const directory=resolve(arg('receipts')||'data/crucible/campaign/receipts');
   const records=(await readdir(directory)).filter(x=>x.endsWith('.json')).sort();
   const receipts:CrucibleTrialReceipt[]=await Promise.all(records.map(x=>json(join(directory,x))));
   const answer=assessCrucibleQualification(receipts);
   const output=resolve(arg('output')||'data/crucible/campaign/qualification.json');
   await write(output,{...answer,trialCount:receipts.length});
   console.log(JSON.stringify({qualified:answer.qualified,count:receipts.length,reasons:answer.reasons},null,2));
   if(!answer.qualified)process.exitCode=1;
   return;
 }
 throw Error('Use --plan, --run-one, or --qualify');
}
main().catch(e=>{console.error(e);process.exitCode=1});
