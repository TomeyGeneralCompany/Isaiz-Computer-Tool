/** LOTUS Gauntlet: real production hunt against an owned synthetic repository.
 * --prepare creates an isolated fixture only. --run invokes the real controller.
 * The hidden answer key is never delivered to the model or checked into its source.
 */
import 'dotenv/config';
import {execFileSync} from 'node:child_process';
import {mkdir,mkdtemp,writeFile,readFile,copyFile,readdir,cp,rm} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
const LEVELS:Record<number,number>={6:2000};
import {createHash,randomBytes} from 'node:crypto';
import {LANGUAGES,type Language} from './lotus-gauntlet-fixtures';
import {generateCrucible} from './lotus-crucible-generator';
import {createCrucibleInvestigatorPackage,type CrucibleAnswerKey} from './lotus-crucible-contract';

/** Each invocation chooses one language uniformly unless an explicit replay language is provided. */
export function chooseLanguage(seed:string,override?:string):Language {
 if(override && override!=='random'){
   if(!(LANGUAGES as readonly string[]).includes(override))throw Error('Unsupported language: '+override);
   return override as Language;
 }
 const index=createHash('sha256').update(seed).digest().readUInt32BE(0)%LANGUAGES.length;
 return LANGUAGES[index];
}
async function prepare(root:string,level:number,language:Language,seed:string,clean:boolean){
 const size=LEVELS[level];
 if(!size)throw Error('Level 6 only');
 const fixture=join(root,'fixture');
 const challenge=generateCrucible({language,seed,fileCount:size,clean});
 const investigatorPackage=createCrucibleInvestigatorPackage(challenge);
 const answer=challenge.privateAnswerKey;
 for(const [path,body] of Object.entries(investigatorPackage.files)){
   const full=join(fixture,path);await mkdir(dirname(full),{recursive:true});await writeFile(full,body);
 }
 await writeFile(join(fixture,'README.md'),'Message and settlement service. Analyze source, callers, data flow, authorization boundaries, and observable security behavior.\n');
 execFileSync('git',['init','-q',fixture]);
 execFileSync('git',['-C',fixture,'add','.']);
 execFileSync('git',['-C',fixture,'-c','user.name=Gauntlet','-c','user.email=fixture@example.invalid',
   'commit','-qm','Owned synthetic benchmark']);
 const commit=execFileSync('git',['-C',fixture,'rev-parse','HEAD'],{encoding:'utf8'}).trim();
 await writeFile(join(root,'answer-key.private.json'),JSON.stringify(answer,null,2),{mode:0o600});
 await writeFile(join(root,'manifest.json'),JSON.stringify({
   challenge:'crucible-v1',language,seedCommitment:createHash('sha256').update(seed).digest('hex'),level,kind:answer.kind,sourceSha256:investigatorPackage.sourceSha256,sourceFiles:Object.keys(investigatorPackage.files).filter(p=>/\.(?:sol|py|cjs|java)$/.test(p)).length,commit,mode:'owned-synthetic'
 },null,2));
 return {fixture,answer};
}
/** Fail-closed grader: verdicts without independent replay or exact target evidence do not qualify. */
function grade(log:string,result:any,elapsed:number,review:any[],answer:CrucibleAnswerKey){
 const findings:any[]=Array.isArray(result.findings)?result.findings:[];
 const reviews:any[]=Array.isArray(review)?review:[];
 const accepted=findings.filter(f=>f.reproductionCaseId&&reviews.some(r=>r.caseId===f.reproductionCaseId&&
  ['valid','verified','confirmed','accepted'].includes(String(r.verdict).toLowerCase())));
 const matched=answer.defects.map(d=>({id:d.id,cases:accepted.filter(f=>{
   const text=[f.targetAsset,f.title,f.reportBody,f.summary,f.sourceFile].filter(Boolean).join(' ');
   return [d.entryPath,...d.affectedPaths].some(p=>text.includes(p));
 }).map(f=>f.reproductionCaseId)}));
 const exact=answer.kind==='clean'?findings.length===0:
   findings.length===answer.defects.length&&accepted.length===answer.defects.length&&
   matched.every(m=>m.cases.length>0)&&
   new Set(matched.flatMap(m=>m.cases)).size===answer.defects.length;
 const milestones={sourceAcquired:log.includes('[ACQUISITION_REPOSITORY_DONE]'),
   sourceMapBuilt:log.includes('[SOURCE_MAP]'),probes:log.includes('[PROBE_RESULT]'),
   independentReplay:accepted.length>0,exactFindings:exact};
 const required=answer.kind==='clean'?
   ['sourceAcquired','sourceMapBuilt','exactFindings']:
   ['sourceAcquired','sourceMapBuilt','probes','independentReplay','exactFindings'];
 const firstDivergence=required.find(k=>!milestones[k as keyof typeof milestones])??null;
 const passed=firstDivergence===null;
 return {version:6,challenge:'crucible-v1',kind:answer.kind,language:answer.language,
   expectedDefects:answer.defects.length,reportedFindings:findings.length,
   matched,passed,firstDivergence,milestones,
   resultStatus:passed?'passed':'failed',error:result.error||null,elapsedMs:elapsed};
}
/** The owned synthetic repository is supplied without contacting a remote host.
 * The normal acquisition security checks remain the default for other callers.
 */
export function createOwnedFixtureAcquirer(fixture:string){
  const sourceUrl='https://github.com/fixture/gauntlet-settlement';
  return async (url:string,destination:string,options:{signal?:AbortSignal})=>{
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
}

async function main(){
 const args=process.argv.slice(2),run=args.includes('--run'),preview=args.includes('--prepare'),smoke=args.includes('--smoke');
 if(Number(run)+Number(preview)+Number(smoke)!==1)throw new Error('Specify exactly one: --prepare, --smoke, or --run');
 const level=Number((args.find(x=>x.startsWith('--level='))||'--level=4').split('=')[1]);
 if(level!==6)throw new Error('Crucible requires --level=6');
 const requestedLanguage=(args.find(x=>x.startsWith('--language='))||'--language=random').split('=')[1];
 const selectedSeed=(args.find(x=>x.startsWith('--seed='))||'').split('=').slice(1).join('=')||randomBytes(16).toString('hex');
 if(selectedSeed.length>128 || !/^[A-Za-z0-9._-]+$/.test(selectedSeed))throw Error('Invalid replay seed');
 const language=chooseLanguage(selectedSeed,requestedLanguage);
 const root=(args.find(x=>x.startsWith('--output='))||'').split('=').slice(1).join('=')||
    await mkdtemp(join(tmpdir(),'lotus-gauntlet-'));
 await mkdir(root,{recursive:true,mode:0o700});
 try {await readFile(join(root,'manifest.json'));throw Error('Gauntlet output directory already contains a challenge');}
 catch(e:any){if(e?.code!=='ENOENT')throw e;}
 const {fixture,answer}=await prepare(root,level,language,selectedSeed,args.includes('--clean'));
 if(preview){console.log('Gauntlet prepared (NO model or tests run): '+root);return;}
 if(smoke){
   const cloned=join(root,'acquired-smoke');
   try {
     await createOwnedFixtureAcquirer(fixture)('https://github.com/fixture/gauntlet-settlement',cloned,{});
     const {inspectSourceCapability}=await import('../packages/security-solver/src/source-capability');
     const capability=await inspectSourceCapability(cloned);
     if(capability.blocked||capability.sourcePaths.length<LEVELS[level])
       throw Error('Owned source capability check failed: '+JSON.stringify(capability).slice(0,500));
     console.log('Gauntlet source acquisition smoke PASSED for '+language+' with '+capability.sourcePaths.length+' source files');
   }finally{await rm(cloned,{recursive:true,force:true});}
   return;
 }
 const app=join(root,'work');await mkdir(app);
 // Owned fixture cloning is an explicit test dependency, not a PATH shim.
 // All downstream capability, source-map, controller, probe, and review stages
 // run through the same implementation as the authorized real-program path.
 const sourceAcquirer=createOwnedFixtureAcquirer(fixture);
 const old={PROJECT_ROOT:process.env.PROJECT_ROOT,GITHUB_TOKEN:process.env.GITHUB_TOKEN};
 const began=Date.now();
 let result:any={success:false,findings:[],error:'No investigation result'};
 let review:any[]=[];
 let gradePassed=false;
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
   scopeSummary:JSON.stringify({policy:'Owned synthetic application. Inspect source, data flow, authorization, input handling and application behavior. Local reproduction and independent technical review are expressly authorized and expected. A technically supported finding must be recorded and graded locally, regardless of external submission eligibility. External bounty-platform submissions are disabled; do not send reports to third parties.',
    scopes:[{assetType:'SOURCE_CODE',eligibleForBounty:true,assetIdentifier:'https://github.com/fixture/gauntlet-settlement'}]})};
  result=await runLocalProgramHunt(program,undefined,undefined,undefined,false,sourceAcquirer);
  // Independent review each reported case, not just findings[0]. A valid
  // report later in the candidate array must receive the same review gate.
  // Never use the hidden answer key to select or approve a report.
  for(const [index,finding] of (result.findings||[]).entries()){
   if(!finding.reproductionCaseId)continue;
   try {
    const judged=await independentReview({...finding,id:'owned-gauntlet-review-'+index} as any,
      program,finding.reproductionCaseId,new AbortController().signal,sourceAcquirer);
    review.push({verdict:judged.review.verdict,caseId:judged.caseId,
      sourceSha256:judged.sourceSha256});
   }catch(e){
    review.push({verdict:'error',caseId:finding.reproductionCaseId,error:String(e)});
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
  gradePassed=summary.passed;
  await writeFile(join(root,'grade.json'),JSON.stringify(summary,null,2));
  console.log('Gauntlet report: '+JSON.stringify({root,seed:selectedSeed,language,summary},null,2));
 }
 if(!gradePassed)process.exitCode=1;
}
main().catch(e=>{console.error(e);process.exitCode=1});
