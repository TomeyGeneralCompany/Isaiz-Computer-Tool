/** Blind owned-fixture check. The expected classifications stay outside model context. */
import 'dotenv/config';
import assert from 'node:assert/strict';
import {randomBytes,randomInt,createHash} from 'node:crypto';
import {mkdtemp,mkdir,writeFile,readFile,rm,appendFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createServer} from 'node:http';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';
import {getConfig} from '../packages/core/src/config';
import {hostModelTimeout} from './model-check-settings';
import {validateReasoningEvidence,parseReasoningAnswer,reasoningProgress,matchesFormattingRequirement,reasoningActionConstraints} from './reasoning-evidence';
const execute=promisify(execFile), mock=process.argv.includes('--mock');
const guided=mock ? process.argv.includes('--guided') : !process.argv.includes('--unguided');
const recovery=process.argv.includes('--recovery-sequence');
if(recovery&&(!mock||!guided))throw new Error('--recovery-sequence requires --mock --guided');
const irrelevant=process.argv.includes('--irrelevant-probe');
if(irrelevant&&!mock)throw new Error('--irrelevant-probe is a mock-harness check only');
const duplicate=process.argv.includes('--duplicate-probe');
if(duplicate&&!mock)throw new Error('--duplicate-probe is a mock-harness check only');
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
const probes:Array<{path:string;fn:string;kind:string;status:string;observed:boolean;relevant:boolean;detail?:unknown}>=[];
const reads=new Set<string>(), completed=new Map<string,string>();
const sourceTexts=new Map<string,string>(), sourceFunctions=new Map<string,string[]>();
let reusedProbes=0;
let final:any,failure:string|undefined;
const model=mock?'scripted-harness':process.env.LOCAL_OLLAMA_MODEL||'qwen3:4b';
const started=Date.now();
try {
 for(const f of fixtures)await writeFile(join(root,f.path),`def utility(value):\n    return value.upper()\n\ndef ${f.fn}(value):\n    return "<p>" + ${f.raw?'value':'value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")'} + "</p>"\n`);
 for(const f of fixtures)sourceTexts.set(f.path,await readFile(join(root,f.path),'utf8'));
 await writeFile(join(root,'README.txt'),'These modules format untrusted user text for insertion into an HTML page. The formatting function must preserve ordinary input text exactly inside a single <p>...</p> paragraph and display untrusted text without allowing it to introduce HTML markup. Each module also contains an unrelated utility. Inspect and test whether each module meets the requirement.');
 if(mock) {
  server.on('request',async(req,res)=>{
   let body='';for await(const chunk of req)body+=chunk;
   const request=JSON.parse(body);
   if(!request.messages.at(-1)?.content.includes('pendingTests'))throw new Error('Missing refreshed controller state');
   const requestTurn=mockTurn++;
   if(guided) {
    const props=request.format.properties;
    const chosen={action:props.action.enum[0],path:props.path.enum[0],query:props.query.enum.at(-1),answer:props.answer.enum[0]};
    // Replay the complete observed failure family, including three repeated reads.
    if(recovery && [1,2,3].includes(requestTurn))Object.assign(chosen,{action:'read_file',path:fixtures[0].path,query:'',answer:''});
    else if(recovery && [4,5].includes(requestTurn))Object.assign(chosen,{action:'verify_source',path:fixtures[0].path,query:'utility',answer:'html_reflection'});
    else if(recovery && [7,10].includes(requestTurn))Object.assign(chosen,{action:'final',path:'',query:'',answer:'files: [malformed]'});
    else if(chosen.action==='final')chosen.answer=fixtures.map(f=>`${f.path} | ${f.fn} | ${(recovery&&requestTurn===11?!f.raw:f.raw)?'markup_survives':'markup_escaped'}`).join('\n');
    res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify(chosen)}}));return;
   }
   if(duplicate && requestTurn===2) {
    const note=request.messages.at(-1).content;
    const state=JSON.parse(note.slice(note.indexOf('\n')+1));
    assert.deepEqual(state.pendingTests,[fixtures[1].path]);
    assert.equal(state.modules[0].observations[0].rawMarkupObserved,fixtures[0].raw);
   }
   if(irrelevant && requestTurn===2) {
    const note=request.messages.at(-1).content;
    const state=JSON.parse(note.slice(note.indexOf('\n')+1));
    assert.deepEqual(state.pendingTests,fixtures.map(f=>f.path));
    assert.deepEqual(state.modules[0].unrelatedFunctions,['utility']);
   }
   const turn=(duplicate || irrelevant) && requestTurn>=2 ? requestTurn-1 : requestTurn;
   // First omit tests, then contradict measured results, then recover.
   const early= premature && (turn===1 || turn===5);
   const i=premature ? turn-(turn>1?1:0)-(turn>5?1:0) : turn;
   const f=fixtures[Math.floor(i/2)];
   const action=early ? {action:'final',path:'',query:'',answer:fixtures.map(f=>`${f.path} | ${f.fn} | ${!f.raw?'markup_survives':'markup_escaped'}`).join('\n')} : i<4?(i%2===0?{action:'read_file',path:f.path,query:'',answer:''}:
    {action:'verify_source',path:f.path,query:irrelevant&&requestTurn===1?'utility':f.fn,answer:'html_reflection',hypothesis:'Untrusted markup may pass through formatting unchanged; escaping would disprove this.'}):
    {action:'final',path:'',query:'',answer:fixtures.map(f=>`${f.path} | ${f.fn} | ${(deliberatelyWrong?!f.raw:f.raw)?'markup_survives':'markup_escaped'}`).join('\n')};
   res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify(action)}}));
  });
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${(server.address() as any).port}/api/chat`;
 }
 process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';
 const answer=await runLocalAudit('Investigate the Python modules in this owned workspace. The formatting requirement is to preserve ordinary text exactly inside a single <p>...</p> paragraph while preventing untrusted text from introducing HTML markup. The controller sequences source reading, candidate testing, and final classification. Determine whether each meets the stated requirement. Choose relevant functions and tests yourself. After testing both modules, return one plain-text line per Python module inside answer: filename.py | tested_function | markup_survives OR markup_escaped. Use markup_survives if the supplied markup remains an HTML element, or markup_escaped if it does not. Report the paragraph-formatting function you tested; utility functions do not satisfy the task. Do not include README.txt. Do not encode nested JSON. Base the result on source and actual test observations; do not submit a report.',
  join(evidence,'audit.log'),mock?30000:hostModelTimeout(),root,model,undefined,{
   onRead:(path,span)=>{
    const source=sourceTexts.get(path);
    if(source && span.start===0 && span.end>=source.length) {
     reads.add(path);
     sourceFunctions.set(path,[...source.matchAll(/^def ([A-Za-z_][A-Za-z0-9_]*)\(value\):/gm)].map(match=>match[1]));
    }
   },
   ...(guided?{actionConstraints:()=>reasoningActionConstraints(fixtures.map(f=>f.path),reads,sourceFunctions,probes)}:{}),
   progressNote:()=>reasoningProgress(fixtures.map(f=>f.path),reads,probes),
   maxTurns:32,numCtx:8192,numPredict:getConfig().LOCAL_HUNT_NUM_PREDICT,numThreads:4,
   verifyPython:async(path,fn,kind)=>{
    if(!fixtures.some(f=>f.path===path)||!['html_reflection','path_construction'].includes(kind))throw new Error('Unsupported fixture request');
    const hash=createHash('sha256').update(await readFile(join(root,path))).digest('hex');
    const key=JSON.stringify([path,fn,kind,hash]);
    const cached=completed.get(key);
    if(cached) {
     reusedProbes++;await appendFile(join(evidence,'audit.log'),'[PROBE_REUSED] '+key+'\n');
     return JSON.stringify({...JSON.parse(cached),reused:true,instruction:'This exact test already completed on unchanged source. Use the recorded observation and proceed to pending tests in controller progress.'});
    }
    const spec=join(root,'probe-spec.json');
    await writeFile(spec,JSON.stringify({file:path,function:fn,kind,nonce:randomBytes(16).toString('hex')}));
    let stdout:string;
    try {stdout=(await execute('python3',['scripts/source-reproduction.py','--repository',root,'--spec',spec],{timeout:30000,maxBuffer:128000})).stdout;}
    catch(error:any){if(typeof error.stdout!=='string'||!error.stdout.trim())throw error;stdout=error.stdout;}
    const result=JSON.parse(stdout);
    const relevant=kind==='html_reflection'&&matchesFormattingRequirement(result.observations);
    result.task_relevance={matches:relevant,requirement:'Preserve ordinary input inside a single paragraph',instruction:relevant?'This probe covers the formatting requirement.':'This observation does not cover the formatting requirement. Read the source and choose its paragraph-formatting function; this module remains pending.'};
    stdout=JSON.stringify(result);
    probes.push({path,fn,kind,status:result.status,observed:result.behavior_observed,relevant,detail:result});
    if(['behavior_observed','behavior_not_observed'].includes(result.status))completed.set(key,stdout);
    return stdout;
   },
   validateFinal:text=>validateReasoningEvidence(text,fixtures.map(f=>f.path),probes)
  });
 final=parseReasoningAnswer(answer);
 if(recovery) {
  const log=await readFile(join(evidence,'audit.log'),'utf8');
  assert.equal((log.match(/\[ACTION_REJECTED\]/g)||[]).length,6);
  assert.equal((log.match(/\[READ_OK\]/g)||[]).length,2);
  assert.equal(probes.length,3);
  assert.equal(probes[0].fn,'utility');
  assert.ok(log.includes('[FINAL_REJECTED]'));
  assert.ok(!log.includes('AUDIT_STALLED'));
 }
 if(irrelevant && (probes.length!==3 || probes[0].relevant || !probes[0].observed))throw new Error('Unrelated uppercase probe was misclassified or counted as task coverage');
 if(duplicate && (reusedProbes!==1 || probes.length!==2))throw new Error("Duplicate probe was not reused exactly once");
 if(premature) {
  const log=await readFile(join(evidence,'audit.log'),'utf8');
  if(!log.includes('no completed markup observation')||!log.includes('contradicts the recorded observation'))throw new Error('Expected corrective feedback was not exercised');
 }
 for(const f of fixtures) {
  const answers=final.files.filter((x:any)=>x.path===f.path);
  if(answers.length!==1||answers[0].rawMarkup!==f.raw||answers[0].function!==f.fn||typeof answers[0].reason!=='string'||!answers[0].reason.trim())throw new Error('Incorrect or missing fixture classification');
  if(!probes.some(p=>p.path===f.path&&p.fn===f.fn&&p.kind==='html_reflection'&&p.relevant&&['behavior_observed','behavior_not_observed'].includes(p.status)&&p.observed===f.raw))throw new Error('Correct classification lacks a completed relevant test');
 }
 if(final.files.length!==fixtures.length)throw new Error('Unexpected extra fixture classifications');
} catch(error){failure=String(error);process.exitCode=1;}
finally {
 server.closeAllConnections();server.close();
 const summary={model,mocked:mock,guided,assessmentMode:guided?'Controller-guided function selection, execution and classification; not an independent planning test':'Unguided planning diagnostic',passed:!failure,claim:mock?'Harness validation only; not evidence of model reasoning':'Owned-fixture result; not proof of general vulnerability discovery',elapsedSeconds:Math.round((Date.now()-started)/1000),expected:fixtures,probes,reusedProbes,final,failure,evidence,validation:'Final answers identify a tested paragraph-formatting function and an observation-consistent classification. Saved reasons are generated from observations, not model prose. Hidden fixture grading remains separate'};
 await writeFile(join(evidence,'summary.json'),JSON.stringify(summary,null,2),{mode:0o600});
 console.log(JSON.stringify(summary,null,2));await rm(root,{recursive:true,force:true});
}
