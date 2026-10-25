/** Blind owned-fixture check. The expected classifications stay outside model context. */
import 'dotenv/config';
import {randomBytes,randomInt} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createServer} from 'node:http';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';
import {getConfig} from '../packages/core/src/config';
import {hostModelTimeout} from './model-check-settings';
import {validateReasoningEvidence} from './reasoning-evidence';
const execute=promisify(execFile), mock=process.argv.includes('--mock');
const premature=process.argv.includes('--premature-final');
if(premature&&!mock)throw new Error('--premature-final is a mock-harness check only');
const deliberatelyWrong=process.argv.includes('--wrong-answer');
if(deliberatelyWrong&&!mock)throw new Error('--wrong-answer is a mock-harness check only');
const root=await mkdtemp(join(tmpdir(),'reasoning-fixture-'));
const evidence=resolve('data/reasoning-diagnostics',new Date().toISOString().replaceAll(':','-'));
await mkdir(evidence,{recursive:true,mode:0o700});
const fixtures=[true,false].map(raw=>({raw,path:'component_'+randomBytes(4).toString('hex')+'.py',fn:'compose_'+randomBytes(4).toString('hex')}));
if(randomInt(2))fixtures.reverse();
const server=createServer();let mockTurn=0;
const probes:Array<{path:string;fn:string;kind:string;status:string;observed:boolean;detail?:unknown}>=[];
let final:any,failure:string|undefined;
const model=mock?'scripted-harness':process.env.LOCAL_OLLAMA_MODEL||'qwen3:4b';
const started=Date.now();
try {
 for(const f of fixtures)await writeFile(join(root,f.path),`def utility(value):\n    return value.upper()\n\ndef ${f.fn}(value):\n    return "<p>" + ${f.raw?'value':'value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")'} + "</p>"\n`);
 await writeFile(join(root,'README.txt'),'These modules format untrusted user text for insertion into an HTML page. The required behavior is to display that text without allowing it to introduce HTML markup. Each module also contains an unrelated utility. Inspect and test whether each module meets the requirement.');
 if(mock) {
  server.on('request',async(req,res)=>{
   for await(const _ of req){};
   const turn=mockTurn++;
   // First omit tests, then contradict measured results, then recover.
   const early= premature && (turn===1 || turn===5);
   const i=premature ? turn-(turn>1?1:0)-(turn>5?1:0) : turn;
   const f=fixtures[Math.floor(i/2)];
   const action=early ? {action:'final',path:'',query:'',answer:JSON.stringify({files:fixtures.map(f=>({path:f.path,rawMarkup:!f.raw,reason:'Unsupported initial conclusion.'}))})} : i<4?(i%2===0?{action:'read_file',path:f.path,query:'',answer:''}:
    {action:'verify_source',path:f.path,query:f.fn,answer:'html_reflection',hypothesis:'Untrusted markup may pass through formatting unchanged; escaping would disprove this.'}):
    {action:'final',path:'',query:'',answer:JSON.stringify({files:fixtures.map(f=>({path:f.path,rawMarkup:deliberatelyWrong?!f.raw:f.raw,reason:'Measured owned fixture behavior.'}))})};
   res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify(action)}}));
  });
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${(server.address() as any).port}/api/chat`;
 }
 process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';
 const answer=await runLocalAudit('Read README.txt and investigate the Python modules in this owned workspace. Determine whether each meets the stated requirement. Choose relevant functions and tests yourself. Return JSON with files:[{path,rawMarkup:boolean,reason:string}], where rawMarkup says whether untrusted HTML markup survives the formatting function. Base the result on source and actual test observations; do not submit a report.',
  join(evidence,'audit.log'),mock?30000:hostModelTimeout(),root,model,undefined,{
   maxTurns:32,numCtx:8192,numPredict:getConfig().LOCAL_HUNT_NUM_PREDICT,numThreads:4,
   verifyPython:async(path,fn,kind)=>{
    if(!fixtures.some(f=>f.path===path)||!['html_reflection','path_construction'].includes(kind))throw new Error('Unsupported fixture request');
    const spec=join(root,'probe-spec.json');
    await writeFile(spec,JSON.stringify({file:path,function:fn,kind,nonce:randomBytes(16).toString('hex')}));
    let stdout:string;
    try {stdout=(await execute('python3',['scripts/source-reproduction.py','--repository',root,'--spec',spec],{timeout:30000,maxBuffer:128000})).stdout;}
    catch(error:any){if(typeof error.stdout!=='string'||!error.stdout.trim())throw error;stdout=error.stdout;}
    const result=JSON.parse(stdout);probes.push({path,fn,kind,status:result.status,observed:result.behavior_observed,detail:result});return stdout;
   },
   validateFinal:text=>validateReasoningEvidence(text,fixtures.map(f=>f.path),probes)
  });
 final=JSON.parse(answer);
 if(premature) {
  const log=await readFile(join(evidence,'audit.log'),'utf8');
  if(!log.includes('no completed markup observation')||!log.includes('contradicts the recorded observation'))throw new Error('Expected corrective feedback was not exercised');
 }
 for(const f of fixtures) {
  const answers=final.files.filter((x:any)=>x.path===f.path);
  if(answers.length!==1||answers[0].rawMarkup!==f.raw||typeof answers[0].reason!=='string'||!answers[0].reason.trim())throw new Error('Incorrect or missing fixture classification');
  if(!probes.some(p=>p.path===f.path&&p.fn===f.fn&&p.kind==='html_reflection'&&['behavior_observed','behavior_not_observed'].includes(p.status)&&p.observed===f.raw))throw new Error('Correct classification lacks a completed relevant test');
 }
 if(final.files.length!==fixtures.length)throw new Error('Unexpected extra fixture classifications');
} catch(error){failure=String(error);process.exitCode=1;}
finally {
 server.closeAllConnections();server.close();
 const summary={model,mocked:mock,passed:!failure,claim:mock?'Harness validation only; not evidence of model reasoning':'Owned-fixture result; not proof of general vulnerability discovery',elapsedSeconds:Math.round((Date.now()-started)/1000),expected:fixtures,probes,final,failure,evidence,validation:'Final answers require completed markup probes and consistency with observations; hidden fixture grading remains separate'};
 await writeFile(join(evidence,'summary.json'),JSON.stringify(summary,null,2),{mode:0o600});
 console.log(JSON.stringify(summary,null,2));await rm(root,{recursive:true,force:true});
}
