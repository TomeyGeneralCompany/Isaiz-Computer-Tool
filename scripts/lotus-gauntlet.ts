/** LOTUS Gauntlet: real production hunt against an owned synthetic repository.
 * --prepare creates an isolated fixture only. --run invokes the real controller.
 * The hidden answer key is never delivered to the model or checked into its source.
 */
import 'dotenv/config';
import {execFileSync} from 'node:child_process';
import {mkdir,mkdtemp,writeFile,readFile,copyFile,readdir,cp} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
const LEVELS:Record<number,number>={1:12,2:28,3:48,4:84,5:144};
import {createHash,randomBytes} from 'node:crypto';
import {generate,LANGUAGES,type Answer,type Language} from './lotus-gauntlet-fixtures';

/** Each invocation chooses one language uniformly unless an explicit replay language is provided. */
export function chooseLanguage(seed:string,override?:string):Language {
 if(override && override!=='random'){
   if(!(LANGUAGES as readonly string[]).includes(override))throw Error('Unsupported language: '+override);
   return override as Language;
 }
 const index=createHash('sha256').update(seed).digest().readUInt32BE(0)%LANGUAGES.length;
 return LANGUAGES[index];
}
async function prepare(root:string,level:number,language:Language,seed:string){
 const size=LEVELS[level];
 if(!size)throw Error('Level must be from 1 through 5');
 const fixture=join(root,'fixture');
 const challenge=generate(language,size);
 for(const [path,body] of Object.entries(challenge.files)){
   const full=join(fixture,path);await mkdir(dirname(full),{recursive:true});await writeFile(full,body);
 }
 await writeFile(join(fixture,'README.md'),'Message and settlement service. Analyze source, callers, data flow, authorization boundaries, and observable security behavior.\n');
 execFileSync('git',['init','-q',fixture]);
 execFileSync('git',['-C',fixture,'add','.']);
 execFileSync('git',['-C',fixture,'-c','user.name=Gauntlet','-c','user.email=fixture@example.invalid',
   'commit','-qm','Owned synthetic benchmark']);
 const commit=execFileSync('git',['-C',fixture,'rev-parse','HEAD'],{encoding:'utf8'}).trim();
 await writeFile(join(root,'answer-key.private.json'),JSON.stringify(challenge.answer,null,2),{mode:0o600});
 await writeFile(join(root,'manifest.json'),JSON.stringify({
   challenge:'gauntlet-blind-v2',language,seed,level,sourceFiles:size,commit,mode:'owned-synthetic'
 },null,2));
 return {fixture,answer:challenge.answer};
}
function grade(log:string,result:any,elapsed:number,review:any,answer:Answer){
 const count=(s:string)=>(log.split(s).length-1);
 const modelActions=log.split('\n').filter(line=>line.includes('[MODEL_ACTION]'));
 const targetRead=modelActions.some(line=>line.includes(answer.file) &&
   (line.includes('read_file')||line.includes('read_solidity')||line.includes('outline_solidity')));
 const targetProbe=modelActions.some(line=>line.includes(answer.selector) &&
   (line.includes('plan_probe')||line.includes('probe_intent')));
 const milestones={
  sourceAcquired:count('[ACQUISITION_REPOSITORY_DONE]')>0,
  sourceMapBuilt:count('[SOURCE_MAP]')>0,
  sourceRead:count('"action":"read_file"')+count('"action":"read_solidity"')+count('"action":"outline_solidity"')>0,
  relevantCandidateInspected:targetRead,
  hypothesisExamined:targetProbe,
  probePlanned:count('[PROBE_PLANNED]')>0,
  probeExecuted:count('[PROBE_RESULT]')>0,
  verifiedFinding:result.success===true && review?.verdict==='approve' &&
   Array.isArray(result.findings) && result.findings.some((f:any)=>
     f.reproductionCaseId && f.reproductionCaseId===review.caseId &&
     (String(f.reportBody||'')+' '+String(f.title||'')).includes(answer.selector.split('.').at(-1)!) &&
     (String(f.reportBody||'')+' '+String(f.title||'')).includes(answer.file))
 };
 const stages:Record<string,string>={sourceAcquired:'acquisition',sourceMapBuilt:'source_mapping',
  sourceRead:'navigation',relevantCandidateInspected:'candidate_selection',
  hypothesisExamined:'hypothesis',probePlanned:'probe_planning',probeExecuted:'probe_execution',
  verifiedFinding:'finding_and_review'};
 const firstDivergence=Object.keys(milestones).find(k=>!milestones[k as keyof typeof milestones]);
 const counters:Record<string,number>={};
 for(const key of ['WORKFLOW_REJECTED','FINAL_REJECTED','EMPTY_FINAL_RETRY','PROBE_PLANNED','PROBE_RESULT',
 'FINAL_UNVERIFIED_FINDINGS_BLOCKED','REJECTED_PLAN_SOURCE_HANDOFF','ALLOWANCE_EXTENDED','MODEL_ACTION'])
   counters[key]=count('['+key+']');
 return {version:2,level:result.level??4,language:answer.language,challenge:'gauntlet-blind-v2',
   firstDivergence:firstDivergence?stages[firstDivergence]:null,milestones,counters,
   resultStatus:result.success?'investigated':'failed_or_incomplete',
   findingCount:result.findings?.length||0,coverage:result.coverage||null,
   error:result.error||null,elapsedMs:elapsed};
}
async function main(){
 const args=process.argv.slice(2),run=args.includes('--run'),preview=args.includes('--prepare');
 if(run===preview)throw new Error('Specify --prepare OR --run');
 const level=Number((args.find(x=>x.startsWith('--level='))||'--level=4').split('=')[1]);
 if(!LEVELS[level])throw new Error('Invalid level');
 const requestedLanguage=(args.find(x=>x.startsWith('--language='))||'--language=random').split('=')[1];
 const selectedSeed=(args.find(x=>x.startsWith('--seed='))||'').split('=').slice(1).join('=')||randomBytes(16).toString('hex');
 if(selectedSeed.length>128 || !/^[A-Za-z0-9._-]+$/.test(selectedSeed))throw Error('Invalid replay seed');
 const language=chooseLanguage(selectedSeed,requestedLanguage);
 const root=(args.find(x=>x.startsWith('--output='))||'').split('=').slice(1).join('=')||
    await mkdtemp(join(tmpdir(),'lotus-gauntlet-'));
 await mkdir(root,{recursive:true,mode:0o700});
 try {await readFile(join(root,'manifest.json'));throw Error('Gauntlet output directory already contains a challenge');}
 catch(e:any){if(e?.code!=='ENOENT')throw e;}
 const {fixture,answer}=await prepare(root,level,language,selectedSeed);
 if(preview){console.log('Gauntlet prepared (NO model or tests run): '+root);return;}
 const app=join(root,'work');await mkdir(app);
 // Owned fixture cloning is an explicit test dependency, not a PATH shim.
 // All downstream capability, source-map, controller, probe, and review stages
 // run through the same implementation as the authorized real-program path.
 const sourceUrl='https://github.com/fixture/gauntlet-settlement';
 const sourceAcquirer=async (url:string,destination:string,options:{signal?:AbortSignal})=>{
   options.signal?.throwIfAborted();
   if(url!==sourceUrl)throw Error('Gauntlet rejected an unexpected source URL: '+url);
   await cp(fixture,destination,{recursive:true,errorOnExist:true,force:false});
   const actual=execFileSync('git',['-c','core.hooksPath=/dev/null','rev-parse','HEAD'],{
     cwd:destination,encoding:'utf8',timeout:10000}).trim();
   const expected=execFileSync('git',['-c','core.hooksPath=/dev/null','rev-parse','HEAD'],{
     cwd:fixture,encoding:'utf8',timeout:10000}).trim();
   if(actual!==expected)throw Error('Owned fixture revision was not preserved');
   return {missingDependencies:[]};
 };
 const old={PROJECT_ROOT:process.env.PROJECT_ROOT,GITHUB_TOKEN:process.env.GITHUB_TOKEN};
 const began=Date.now();
 let result:any={success:false,findings:[],error:'No investigation result'};
 let review:any=null;
 try{
  process.env.PROJECT_ROOT=app;
  process.env.GITHUB_TOKEN='owned-gauntlet-fixture';
  process.env.LOCAL_OLLAMA_MODEL ||= 'qwen3:4b';
  process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';
  process.env.AUTOHACK_AUTO_SOURCE_PREFETCH='true';
  process.env.AUTOHACK_GUIDED_SOURCE_PROBES='true';
  process.env.LOCAL_HUNT_DYNAMIC_ALLOWANCE='true';
  process.env.LOCAL_HUNT_MAX_TURNS ||= '80';
  process.env.SECURITY_AUTO_SUBMIT='false';
  const {runLocalProgramHunt,independentReview}=await import('../packages/security-solver/src/local-program-flow');
  const program:any={id:'owned-gauntlet-'+level+'-'+language,provider:'immunefi',name:'Controlled source application benchmark',
   scopeSummary:JSON.stringify({policy:'Owned synthetic application. Inspect source, data flow, authorization, input handling and application behavior. Local reproduction and diagnostics only. No submissions.',
    scopes:[{assetType:'SOURCE_CODE',eligibleForBounty:true,assetIdentifier:'https://github.com/fixture/gauntlet-settlement'}]})};
  result=await runLocalProgramHunt(program,undefined,undefined,undefined,false,sourceAcquirer);
  if(result.findings?.length){
   const finding=result.findings[0];
   if(finding.reproductionCaseId){
    const judged=await independentReview({...finding,id:'owned-gauntlet-review'} as any,
      program,finding.reproductionCaseId,new AbortController().signal);
    review={verdict:judged.review.verdict,caseId:judged.caseId,sourceSha256:judged.sourceSha256};
   }
  }
 }catch(e){result.error=String(e);}
 finally{
  if(old.PROJECT_ROOT===undefined)delete process.env.PROJECT_ROOT;else process.env.PROJECT_ROOT=old.PROJECT_ROOT;
  if(old.GITHUB_TOKEN===undefined)delete process.env.GITHUB_TOKEN;else process.env.GITHUB_TOKEN=old.GITHUB_TOKEN;
  const logs=join(app,'data','logs');
  let content='';
  for(const filename of await readdir(logs).catch(()=>[])){
   if(!filename.startsWith('local-hunt-') && !filename.startsWith('local-review-'))continue;
   const path=join(logs,filename);await copyFile(path,join(root,filename));
   if(filename.startsWith('local-hunt-') && filename.endsWith('.log'))content+=(await readFile(path,'utf8'))+'\n';
  }
  const resultData={success:result.success||false,coverage:result.coverage||null,
   error:result.error||null,auditRecord:result.auditRecord||null,level,
   findings:(result.findings||[]).map((f:any)=>({title:f.title,targetAsset:f.targetAsset,
     reproductionCaseId:f.reproductionCaseId,reportCreated:!!f.reportBody}))};
  await writeFile(join(root,'result.json'),JSON.stringify(resultData,null,2));
  await writeFile(join(root,'review.json'),JSON.stringify(review,null,2));
  const summary=grade(content,{...result,level},Date.now()-began,review,answer);
  await writeFile(join(root,'grade.json'),JSON.stringify(summary,null,2));
  console.log('Gauntlet report: '+JSON.stringify({root,seed:selectedSeed,language,summary},null,2));
 }
 if(!result.success)process.exitCode=1;
}
main().catch(e=>{console.error(e);process.exitCode=1});
