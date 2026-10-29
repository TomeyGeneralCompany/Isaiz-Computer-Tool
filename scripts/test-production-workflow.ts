/** Shared production controller + real owned Python probes. Mock model by default. */
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {randomBytes} from 'node:crypto';
import {mkdtemp,writeFile,readFile,mkdir,rm} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {runLocalAudit} from '../packages/security-solver/src/local-ollama-runner';
import {InvestigationWorkflow} from '../packages/security-solver/src/investigation-workflow';
const variant=Number(process.argv.find(a=>a.startsWith('--variant='))?.split('=')[1]||0);
if(!Number.isInteger(variant)||variant<0||variant>2)throw new Error('Variant must be 0, 1 or 2');
const largeContext=process.argv.includes('--large-context');
const emptySequence=process.argv.includes('--empty-sequence');
const live=process.argv.includes('--real-model'),mockProbes=process.argv.includes('--mock-probes'),prefetch=process.argv.includes('--prefetch'),execute=promisify(execFile);
if(live&&mockProbes)throw new Error('Real model check requires real probes');
const root=await mkdtemp(join(tmpdir(),'production-workflow-'));
const evidence=resolve('data/production-workflow-tests',new Date().toISOString().replaceAll(':','-'));
await mkdir(evidence,{recursive:true,mode:0o700});
const fixtures=[true,false].map(raw=>({raw,path:randomBytes(5).toString('hex')+'.py',fn:'render_'+randomBytes(5).toString('hex')}));
let calls=0;const observations=new Map<string,boolean>();const server=createServer();
const action=(name:string,path='',query='',answer='')=>({action:name,path,query,answer});
try {
  // The same routing implementation production uses: errors never become observations.
  const routing=new InvestigationWorkflow();
  for(let i=0;i<6;i++)routing.observe(action('read_file','a.py'),JSON.stringify({nextOffset:100+i}));
  assert.ok((await routing.constraints()).action.includes('read_file'));
  for(let i=0;i<6;i++)routing.observe(action('search_files'),JSON.stringify({results:[]}));
  assert.deepEqual((await routing.constraints()).action,['plan_probe','continue_inspection','final']);
  assert.match(routing.validate({...action('plan_probe','missing.py','x','html_reflection'),hypothesis:'test'})!,/Read/);
  routing.read('a.py');const planned={...action('plan_probe','a.py','f','html_reflection'),hypothesis:'Markup may survive; escaping disproves it.'};
  assert.equal(routing.validate(planned),null);routing.plan(planned);
  assert.deepEqual((await routing.constraints()).action,['verify_source']);
  routing.observe({...planned,action:'verify_source'},'Tool error: unsupported');
  assert.match(routing.validate(planned)!,/already/);
  assert.equal(routing.snapshot().observations[0].status,'tool_error');
  for(const f of fixtures) {
    const escaped=variant===1?"html.escape(value, quote=False)":"value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')";
    const expression=variant===2?`'<p>{}</p>'.format(${f.raw?'value':escaped})`:`'<p>' + ${f.raw?'value':escaped} + '</p>'`;
    await writeFile(join(root,f.path),`${variant===1?'import html\n':''}def unrelated(value):\n    return value.upper()\n\ndef ${f.fn}(value):\n    return ${expression}\n`);
  }
  if(!live) {
    server.on('request',async(req,res)=>{
      let body='';for await(const chunk of req)body+=chunk;
      const request=JSON.parse(body);const i=calls++;
      assert.equal(request.options.num_thread,4);assert.equal(request.options.num_ctx,8192);
      assert.ok(JSON.stringify(request.messages).length+JSON.stringify(request.format).length <= (8192-request.options.num_predict-512)*3);
      const f=fixtures[Math.floor(i/3)];
      let chosen:any;
      if(prefetch) {
        if(i===0) {
          const delivered=request.messages.some((m:any)=>m.role==='assistant' && m.content.includes(fixtures[0].path) && m.content.includes('"action":"read_file"')) &&
            request.messages.some((m:any)=>m.content.startsWith('TOOL_RESULT ') && m.content.includes('\\\"text\\\"'));
          if(!delivered) {
            const diagnostic=await readFile(join(evidence,'audit.log'),'utf8');
            throw new Error('Seeded source missing from first model context. Initial source diagnostic: '+
              diagnostic.split('\\n').filter(line=>line.includes('INITIAL_SOURCE')).join(' | ')+
              '; roles='+JSON.stringify(request.messages.map((m:any)=>({role:m.role,head:m.content.slice(0,120)}))));
          }
        }
        const current=i<2?fixtures[0]:fixtures[1];
        if(i===0||i===3)chosen={...action('plan_probe',current.path,current.fn,'html_reflection'),hypothesis:'Markup survives interpolation; escaping disproves it.'};
        else if(i===1||i===4)chosen=action('verify_source',current.path,current.fn,'html_reflection');
        else if(i===2)chosen=action('read_file',current.path);
        else chosen=action('final','','',JSON.stringify({files:fixtures.map(f=>({path:f.path,rawMarkup:f.raw}))}));
      } else if(i<6)chosen=i%3===0?action('read_file',f.path):i%3===1?
        {...action('plan_probe',f.path,f.fn,'html_reflection'),hypothesis:'Markup survives interpolation; escaped marker would disprove it.'}:
        action('verify_source',f.path,f.fn,'html_reflection');
      else chosen=action('final','','',JSON.stringify({files:fixtures.map(f=>({path:f.path,rawMarkup:f.raw}))}));
      if(emptySequence && chosen.action==='plan_probe' && chosen.answer!=='solidity_sequence')chosen.sequence={};
      assert.ok(request.format.properties.action.enum.includes(chosen.action));
      assert.ok(request.messages.at(-1).content.includes('Controller progress'));
      assert.equal(request.stream,true);
      const output=JSON.stringify(chosen),split=Math.floor(output.length/2);
      res.setHeader('Content-Type','application/x-ndjson');
      res.write(JSON.stringify({message:{role:'assistant',content:output.slice(0,split)},done:false})+'\n');
      res.end(JSON.stringify({message:{role:'assistant',content:output.slice(split)},done:true})+'\n');
    });
    await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
    process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${(server.address() as any).port}/api/chat`;
  }
  process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';
  if(!live)process.env.AUTOHACK_GUIDED_SOURCE_PROBES='false'; // Scripted actions test the normal model-driven transition.
  const checkpointPath=join(root,'prior-checkpoint.json');
  if(largeContext)await writeFile(checkpointPath,JSON.stringify({notes:'previous navigation '.repeat(145)}));
  const answer=await runLocalAudit((largeContext?'Owned production-sized instructions. '.repeat(160):'')+`Inspect these owned Python modules: ${fixtures.map(f=>f.path).join(', ')}. They should put ordinary user text inside a paragraph while escaping supplied HTML. Choose each function from source, formulate a disprovable hypothesis, test it, and classify whether user markup survives. Return JSON {"files":[{"path":"...","rawMarkup":true or false}]}. This is an owned fixture, not a real vulnerability report.`,
    join(evidence,'audit.log'),live?1800000:30000,root,live?(process.env.LOCAL_OLLAMA_MODEL||'qwen3:4b'):'mock',undefined,{
      checkpointPath:largeContext?checkpointPath:undefined,productionWorkflow:true,
      initialSourcePaths:prefetch?(live?fixtures.map(f=>f.path):[fixtures[0].path]):undefined,
      initialSourceLocations:prefetch?(live?fixtures.map(f=>({path:f.path,offset:0})):[{path:fixtures[0].path,offset:0}]):undefined,numCtx:8192,numThreads:4,numPredict:largeContext?4096:1024,maxTurns:40,
      verifyPython:async(path,fn,kind)=>{
        assert.ok(fixtures.some(f=>f.path===path));assert.equal(kind,'html_reflection');
        if(mockProbes){const f=fixtures.find(f=>f.path===path&&f.fn===fn)!;assert.ok(f);observations.set(path,f.raw);return JSON.stringify({status:f.raw?'behavior_observed':'behavior_not_observed',behavior_observed:f.raw,diagnostic:'owned fixture output '.repeat(2000)});}
        const spec=join(root,'spec.json');await writeFile(spec,JSON.stringify({file:path,function:fn,kind,nonce:randomBytes(16).toString('hex')}));
        let stdout:string;
        try {stdout=(await execute('python3',['scripts/source-reproduction.py','--repository',root,'--spec',spec],{timeout:30000,maxBuffer:128000})).stdout;}
        catch(error:any) {
          // The probe CLI exits 1 for a valid negative observation too.
          if(typeof error.stdout!=='string'||!error.stdout.trim())throw error;
          stdout=error.stdout;
        }
        const result=JSON.parse(stdout);
        if(['behavior_observed','behavior_not_observed'].includes(result.status))observations.set(path,result.behavior_observed);
        return stdout;
      },
      validateFinal:text=>{
        try {
          const value=JSON.parse(text);
          if(observations.size!==2)return 'Test both inspected modules before classifying them.';
          if(value.files.length!==2 || fixtures.some(f=>value.files.filter((v:any)=>v.path===f.path).length!==1))return 'Return one result per module.';
          if(value.files.some((f:any)=>observations.get(f.path)!==f.rawMarkup))return 'Classification contradicts recorded observations.';
          return null;
        } catch{return 'Return the requested JSON.';}
      }
    });
  const result=JSON.parse(answer);
  for(const f of fixtures)assert.equal(result.files.find((r:any)=>r.path===f.path).rawMarkup,f.raw);
  const summary=JSON.parse(await readFile(join(evidence,'audit.log.summary.json'),'utf8'));
  assert.equal(summary.workflow.observations.length,2);
  for(const observation of summary.workflow.observations) {
    assert.ok(observation.evidenceFile);
    const saved=JSON.parse(await readFile(join(root,observation.evidenceFile),'utf8'));
    assert.equal(saved.result.behavior_observed,observations.get(observation.path));
  }
  await writeFile(join(evidence,'result.json'),JSON.stringify({passed:true,mocked:!live,mockedProbes:mockProbes,productionWorkflow:true,variant,profile:process.env.LOCAL_MODEL_PROFILE||'deterministic',result},null,2));
  console.log(`Production workflow passed (${live?'real model':(mockProbes?'scripted model and probes':'scripted model; real Python probes')}). Evidence: ${evidence}`);
} finally {server.close();await rm(root,{recursive:true,force:true});}
