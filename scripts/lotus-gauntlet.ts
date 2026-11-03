/** LOTUS Gauntlet: real production hunt against an owned synthetic repository.
 * --prepare creates an isolated fixture only. --run invokes the real controller.
 * The hidden answer key is never delivered to the model or checked into its source.
 */
import 'dotenv/config';
import {execFileSync} from 'node:child_process';
import {mkdir,mkdtemp,writeFile,readFile,copyFile,readdir,chmod} from 'node:fs/promises';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
const LEVELS:Record<number,number>={1:12,2:28,3:48,4:84,5:144};
const SECRET={file:'contracts/settlement/SettlementAuthority.sol',
  function:'rotateOperator',caller:'contracts/settlement/SettlementVault.sol',
  defect:'Unrestricted operator replacement permits subsequent privileged settlement'};
const modules=['Pricing','Settlement','Compliance','SettlementRoute','Reserve','Oracle','Pool','Ledger','Adapter','Gateway'];
const authority=[
'// SPDX-License-Identifier: MIT',
'pragma solidity ^0.8.20;',
'contract SettlementAuthority {',
'  address public administrator;',
'  address public operator;',
'  constructor(){ administrator=msg.sender;operator=msg.sender; }',
'  function rotateOperator(address nextOperator) external {',
'    require(nextOperator!=address(0),"invalid operator");',
'    operator=nextOperator;',
'  }',
'  function isOperator(address who) external view returns(bool){return who==operator;}',
'  function changeAdministrator(address nextAdministrator) external {',
'    require(msg.sender==administrator,"administrator only");',
'    require(nextAdministrator!=address(0),"invalid administrator");',
'    administrator=nextAdministrator;',
'  }',
'}',''].join('\n');
const vault=[
'// SPDX-License-Identifier: MIT',
'pragma solidity ^0.8.20;',
'import "./SettlementAuthority.sol";',
'import "../../lib/settlement-utils/src/AmountMath.sol";',
'contract SettlementVault is SettlementAuthority {',
'  using AmountMath for uint256;',
'  mapping(address=>uint256) public credit;',
'  uint256 public totalCredit;',
'  function fund(address recipient,uint256 amount) external {',
'    uint256 approved=amount.bounded(type(uint128).max);',
'    credit[recipient]+=approved;totalCredit+=approved;',
'  }',
'  function settle(address recipient,uint256 amount) external {',
'    require(msg.sender==operator,"operator only");',
'    require(amount>0 && amount<=totalCredit,"invalid amount");',
'    credit[recipient]+=amount;totalCredit-=amount;',
'  }',
'  function ledgerState(address account) external view returns(uint256,uint256,address){',
'    return(credit[account],totalCredit,operator);',
'  }',
'}',''].join('\n');
function decoy(i:number):string{
 const name=modules[i%modules.length]+'D'+String(i).padStart(3,'0');
 const prior=i>0?'import "./'+modules[(i-1)%modules.length]+'D'+String(i-1).padStart(3,'0')+'.sol";\n':'';
 return ['// SPDX-License-Identifier: MIT','pragma solidity ^0.8.20;',prior,
 'contract '+name+' {',
 '  address public administrator;',
 '  mapping(address=>uint256) private allowances;',
 '  uint256 public configuration;',
 '  constructor(){administrator=msg.sender;configuration='+String(i%17+2)+';}',
 '  function rotateOperator(address next) external {',
 '    require(msg.sender==administrator,"administrator only");',
 '    require(next!=address(0),"invalid address");',
 '    configuration=uint256(uint160(next))%97;',
 '  }',
 '  function reserve(address member,uint256 amount) external {',
 '    require(msg.sender==administrator,"administrator only");',
 '    require(amount<1000000000,"limit");allowances[member]+=amount;',
 '  }',
 '  function inspect(address member) external view returns(uint256){',
 '    return allowances[member]+configuration;',
 '  }',
 '  function settlementPreview(uint256 base) external view returns(uint256){',
 '    return base+configuration;',
 '  }',
 '}',''].join('\n');
}
async function prepare(root:string,level:number){
 const size=LEVELS[level];if(!size)throw new Error('Choose a level from 1 to 5');
 const fixture=join(root,'fixture');
 async function put(path:string,content:string){const full=join(fixture,path);
   await mkdir(dirname(full),{recursive:true});await writeFile(full,content);}
 await put('contracts/settlement/SettlementAuthority.sol',authority);
 await put('contracts/settlement/SettlementVault.sol',vault);
 await put('lib/settlement-utils/src/AmountMath.sol',[
   '// SPDX-License-Identifier: MIT','pragma solidity ^0.8.20;',
   'library AmountMath {',
   ' function bounded(uint256 value,uint256 upper) internal pure returns(uint256){',
   '  require(value<=upper,"limit exceeded");return value;',
   ' }','}',''].join('\n'));
 await put('foundry.toml','[profile.default]\nsrc = "contracts"\nlibs = ["lib"]\nsolc_version = "0.8.30"\noptimizer = true\noptimizer_runs = 200\n');
 await put('README.md','Settlement platform. Investigate privileged settlement operations, authorization, and ledger transitions using isolated local EVM tests.\n');
 for(let i=0;i<size-3;i++)await put('contracts/modules/'+modules[i%modules.length]+'D'+String(i).padStart(3,'0')+'.sol',decoy(i));
 execFileSync('git',['init','-q',fixture]);execFileSync('git',['-C',fixture,'add','.']);
 execFileSync('git',['-C',fixture,'-c','user.name=Gauntlet','-c','user.email=fixture@example.invalid','commit','-qm','Synthetic settlement repository']);
 const commit=execFileSync('git',['-C',fixture,'rev-parse','HEAD'],{encoding:'utf8'}).trim();
 await writeFile(join(root,'answer-key.private.json'),JSON.stringify(SECRET,null,2),{mode:0o600});
 await writeFile(join(root,'manifest.json'),JSON.stringify({challenge:'settlement-authority-v1',level,sourceFiles:size,commit,mode:'owned-synthetic'},null,2));
 return fixture;
}
function grade(log:string,result:any,elapsed:number,review:any){
 const count=(s:string)=>(log.split(s).length-1);
 const modelActions=log.split('\n').filter(line=>line.includes('[MODEL_ACTION]'));
 const targetRead=modelActions.some(line=>line.includes('SettlementAuthority.sol') &&
   (line.includes('read_file')||line.includes('read_solidity')||line.includes('outline_solidity')));
 const targetProbe=modelActions.some(line=>line.includes('rotateOperator') &&
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
     (String(f.reportBody||'')+' '+String(f.title||'')).includes(SECRET.function) &&
     (String(f.reportBody||'')+' '+String(f.title||'')).includes('SettlementAuthority'))
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
 return {version:1,level:result.level??4,challenge:'settlement-authority-v1',
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
 const root=(args.find(x=>x.startsWith('--output='))||'').split('=').slice(1).join('=')||
    await mkdtemp(join(tmpdir(),'lotus-gauntlet-'));
 await mkdir(root,{recursive:true,mode:0o700});
 const fixture=await prepare(root,level);
 if(preview){console.log('Gauntlet prepared (NO model or tests run): '+root);return;}
 const app=join(root,'work');await mkdir(app);
 const bin=join(root,'shim-bin');await mkdir(bin);
 const git=execFileSync('which',['git'],{encoding:'utf8'}).trim();
 const shim=join(bin,'git');
 // Preserve original clone verification and acquisition behavior, replacing
 // only the remote clone with this exact owned Git repository.
 await writeFile(shim,[
 '#!/usr/bin/python3','import os,sys,shutil,subprocess','args=sys.argv[1:]',
 'if "clone" in args:',' shutil.copytree('+JSON.stringify(fixture)+',args[-1])',
 'elif "fetch" in args:',' subprocess.run(['+JSON.stringify(git)+',"cat-file","-e",args[-1]+"^{commit}"],check=True)',
 'else:',' os.execv('+JSON.stringify(git)+',['+JSON.stringify(git)+']+args)',
 ''].join('\n'));
 await chmod(shim,0o700);
 const old={PATH:process.env.PATH,PROJECT_ROOT:process.env.PROJECT_ROOT,GITHUB_TOKEN:process.env.GITHUB_TOKEN};
 const began=Date.now();
 let result:any={success:false,findings:[],error:'No investigation result'};
 let review:any=null;
 try{
  process.env.PATH=bin+':'+old.PATH;
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
  const program:any={id:'owned-gauntlet-'+level,provider:'immunefi',name:'Controlled settlement authority benchmark',
   scopeSummary:JSON.stringify({policy:'Owned synthetic application. Inspect authorization and ledger behavior. Local reproduction and diagnostics only. No submissions.',
    scopes:[{assetType:'SOURCE_CODE',eligibleForBounty:true,assetIdentifier:'https://github.com/fixture/gauntlet-settlement'}]})};
  result=await runLocalProgramHunt(program);
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
  if(old.PATH===undefined)delete process.env.PATH;else process.env.PATH=old.PATH;
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
  const summary=grade(content,{...result,level},Date.now()-began,review);
  await writeFile(join(root,'grade.json'),JSON.stringify(summary,null,2));
  console.log('Gauntlet report: '+JSON.stringify({root,summary},null,2));
 }
 if(!result.success)process.exitCode=1;
}
main().catch(e=>{console.error(e);process.exitCode=1});
