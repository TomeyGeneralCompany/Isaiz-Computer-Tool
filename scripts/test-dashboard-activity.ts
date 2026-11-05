import assert from "node:assert/strict";
import {mkdtemp,mkdir,writeFile,readFile,rm,utimes} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {readLocalActivity,describeHuntFailure,parseWorkEvents} from "../packages/dashboard/src/server/activity";

const root=await mkdtemp(join(tmpdir(),"tomey-activity-"));
try {
  await mkdir(join(root,"logs"));
  const old=join(root,"logs","local-hunt-aa.log");
  await writeFile(old,"[READ_OK] stale.sol\n");
  await utimes(old,new Date(0),new Date(0));
  const startedAt=new Date(Date.now()-1000).toISOString();
  assert.equal((await readLocalActivity(root,{active:true,startedAt})).lastProgressAt,null);
  const path=join(root,"logs","local-hunt-bb.log");
  const content="[OLLAMA] turn 1/20: request started; model=local\nTARGET SOURCE SECRET\n[TOOL] read_file\n[READ_OK] source-1/render.sol\n";
  await writeFile(path,content);
  let result=await readLocalActivity(root,{active:true,startedAt});
  assert.equal(result.task,"Inspecting source");
  assert.equal(result.language,"Solidity");
  assert.equal(result.detail,"source-1/render.sol");
  assert.ok(result.lastProgressAt);
  assert.equal(JSON.stringify(result).includes("SECRET"),false);
  assert.equal(await readFile(path,"utf8"),content,"Status polling never modifies audit logs");
  await writeFile(path,content+"[TOOL] verify_source\n");
  result=await readLocalActivity(root,{active:true,startedAt});
  assert.equal(result.task,"Running isolated reproduction");
  assert.equal(result.language,null,"Do not infer probe language from a previously read caller");
  await writeFile(path,content+'[MODEL_PROGRESS] '+JSON.stringify({turn:3,contentCharacters:120,thinkingCharacters:40})+'\n');
  result=await readLocalActivity(root,{active:true,startedAt});
  assert.equal(result.task,'Local model generating');assert.match(result.detail,/120 response/);
  assert.equal(result.counts.filesRead,1,'Generation does not add to the one recorded source read');
  assert.equal((await readLocalActivity(root,{active:false,startedAt})).task,"No active source hunt");
  assert.equal(describeHuntFailure("No supported function reproduction completed").stage,"Source reproduction");
  assert.equal(describeHuntFailure("Ollama audit timed out").stage,"Model inspection");
  assert.match(describeHuntFailure(null).reason,/not retained/);
  assert.equal(describeHuntFailure("Bearer secret-value").reason.includes("secret-value"),false);
  const event=(value:Record<string,unknown>)=>"[ACTIVITY] "+JSON.stringify({at:new Date().toISOString(),...value});
  assert.equal(describeHuntFailure("Latest audit exchange exceeds the context budget; narrow the probe output").stage,"Model context");
  const paged=parseWorkEvents(event({phase:"completed",tool:"read_file",path:"source/file.js",offset:128,end:256,nextOffset:256}));
  assert.match(paged.events[0].detail,/offset 128–256.*next 256/);
  const eof=parseWorkEvents(event({phase:"completed",tool:"read_file",path:"source/file.js",offset:256,end:300,nextOffset:null}));
  assert.match(eof.events[0].detail,/end of file/);
  const trail=parseWorkEvents([
    "[READ_OK] source-1/example.sol",
    event({phase:"completed",tool:"read_file",path:"source-1/example.sol",durationMs:20}),
    event({phase:"completed",tool:"search_files",query:"withdraw",count:4}),
    event({phase:"completed",tool:"verify_source",path:"source-1/example.sol",query:"Contract.render",kind:"html_reflection",status:"behavior_not_observed",durationMs:1250}),
    event({phase:"completed",tool:"verify_source",path:"source-1/example.sol",query:"missing",status:"probe_failed"}),
    event({phase:"failed",tool:"read_file",path:"missing.sol",error:"Tool error: File missing"}),
    "[ACTIVITY] broken json",
    "Unstructured model commentary must not be displayed"
  ].join("\n"));
  assert.equal(trail.counts.filesRead,1,"Legacy and structured read markers must not double count");
  assert.equal(trail.counts.searches,1);
  assert.equal(trail.counts.tests,2);
  assert.ok(trail.events.some(e=>e.detail.includes("4 matches")));
  assert.ok(trail.events.some(e=>e.status==="Behavior not reproduced"));
  assert.ok(trail.events.some(e=>e.status==="Test could not run successfully"));
  assert.equal(trail.events[0].phase,"failed");
  assert.equal(JSON.stringify(trail).includes("model commentary"),false);
  assert.equal(parseWorkEvents(Array(100).fill(event({phase:"completed",tool:"read_file",path:"a.py"})).join("\n")).events.length,30);
  const live=parseWorkEvents([
    event({phase:"started",tool:"model_generation",turn:11,model:"qwen3:4b"}),
    event({phase:"completed",tool:"model_generation",turn:11,model:"qwen3:4b",generatedTokens:230,durationMs:800}),
    event({phase:"completed",tool:"controller_action",selectedAction:"read_file",path:"source-1/src/renderer.cjs",turn:12,origin:"controller"}),
    event({phase:"completed",tool:"probe_plan",path:"source-1/contracts/Vault.sol",query:"Vault.settle",kind:"solidity_sequence",origin:"controller"}),
    event({phase:"completed",tool:"verify_source",path:"source-1/contracts/Vault.sol",query:"Vault.settle",kind:"solidity_sequence",status:"observation_only"})
  ].join("\n"));
  assert.ok(live.events.some(e=>e.title==="Qwen generating"));
  assert.ok(live.events.some(e=>e.title==="Qwen responded"&&e.detail.includes("230 tokens")));
  assert.ok(live.events.some(e=>e.title.includes("Controller → read_file")&&e.detail.includes("renderer.cjs")));
  assert.ok(live.events.some(e=>e.title==="Accepted probe plan"&&e.detail.includes("Vault.settle")));
  assert.ok(live.events.some(e=>e.tool==="verify_source"&&e.detail.includes("Vault.settle")));
  assert.equal(live.counts.tests,1);
  assert.equal(JSON.stringify(live).includes("secret_token"),false);
  console.log("Read-only live progress, stale log exclusion, failure explanations and redaction PASSED");
}finally{await rm(root,{recursive:true,force:true});}
