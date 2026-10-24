/** Exercise actual read -> isolated Python probe -> finish with the configured model.
 * Only generated local fixtures are used; no programs, findings or submissions are changed.
 */
import 'dotenv/config';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp,mkdir,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {randomBytes} from 'node:crypto';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';
import {getConfig} from '../packages/core/src/config';
import {hostModelTimeout} from './model-check-settings';
const mock=process.argv.includes('--mock');
const root=await mkdtemp(join(tmpdir(),'local-controller-'));
const evidence=resolve('data/controller-diagnostics',new Date().toISOString().replaceAll(':','-'));
await mkdir(evidence,{recursive:true,mode:0o700});
const log=join(evidence,'audit.log');
const execute=promisify(execFile);
const server=createServer();
let turns=0,reads=0,probes=0;
const started=Date.now();
const model=mock?'mock':process.env.LOCAL_OLLAMA_MODEL || 'qwen3:4b';
let failure:string|undefined;
try {
 await writeFile(join(root,'fixture.py'),'def render(value):\n    return value.replace("<", "&lt;")\n');
 if(mock) {
  server.on('request',async(req,res)=>{
   let body='';for await(const chunk of req)body+=chunk;
   const request=JSON.parse(body);turns++;
   assert.equal(request.options.num_ctx,8192);
   assert.ok(request.format.properties.action.enum.includes('verify_source'));
   const action=turns===1?{action:'read_file',path:'fixture.py',query:'',answer:''}:
    turns===2?{action:'verify_source',path:'fixture.py',query:'render',answer:'html_reflection'}:
    {action:'final',path:'',query:'',answer:'DONE'};
   res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify(action)}}));
  });
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${(server.address() as any).port}/api/chat`;
 }
 process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';
 await runLocalAudit('Inspect fixture.py with read_file. Then use verify_source on render with html_reflection. Use the actual result to decide whether raw HTML is preserved. After the completed test, return a final answer of DONE. This owned fixture is a controller test; do not produce a vulnerability report.',
  log,mock?30000:hostModelTimeout(),root,model,undefined,{
   maxTurns:12,numCtx:8192,numPredict:getConfig().LOCAL_HUNT_NUM_PREDICT,numThreads:4,
   onRead:()=>reads++,
   verifyPython:async(path,fn,kind)=>{
    if(path!=='fixture.py'||fn!=='render'||kind!=='html_reflection')throw new Error('Use fixture.py, render, html_reflection');
    const spec=join(root,'spec.json');
    await writeFile(spec,JSON.stringify({file:path,function:fn,kind,nonce:randomBytes(16).toString('hex')}));
    let stdout:string;
    try {stdout=(await execute('python3',['scripts/source-reproduction.py','--repository',root,'--spec',spec],{timeout:30000,maxBuffer:128000})).stdout;}
    catch(error:any) {if(typeof error.stdout!=='string'||!error.stdout.trim())throw error;stdout=error.stdout;}
    const result=JSON.parse(stdout);
    if(['behavior_observed','behavior_not_observed'].includes(result.status)) {
      assert.equal(result.behavior_observed,false,'Owned fixture must escape the test markup');probes++;
    }
    return stdout;
   },
   validateFinal:answer=>reads && probes && answer.trim()==='DONE'?null:
    'Read fixture.py, complete verify_source for render/html_reflection, then return DONE. A blocked or failed probe is not a completed test.'
  });
} catch(error) {failure=String(error);process.exitCode=1;}
finally {
 server.closeAllConnections();server.close();
 const transcript=await readFile(log,'utf8').catch(()=>'');
 const summary={model,mocked:mock,passed:!failure,elapsedSeconds:Math.round((Date.now()-started)/1000),
  reads,completedProbes:probes,turns:(transcript.match(/request started/g)||[]).length,
  contextRereads:(transcript.match(/\[CONTEXT_REREAD\]/g)||[]).length,
  duplicateRequests:(transcript.match(/\[NO_PROGRESS\]/g)||[]).length,failure};
 await writeFile(join(evidence,'summary.json'),JSON.stringify(summary,null,2),{mode:0o600});
 console.log(JSON.stringify({...summary,evidence},null,2));
 await rm(root,{recursive:true,force:true});
}
