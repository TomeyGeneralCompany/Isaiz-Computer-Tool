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
  assert.equal((await readLocalActivity(root,{active:false,startedAt})).task,"No active source hunt");
  assert.equal(describeHuntFailure("No supported function reproduction completed").stage,"Source reproduction");
  assert.equal(describeHuntFailure("Ollama audit timed out").stage,"Model inspection");
  assert.match(describeHuntFailure(null).reason,/not retained/);
  assert.equal(describeHuntFailure("Bearer secret-value").reason.includes("secret-value"),false);
  const event=(value:Record<string,unknown>)=>"[ACTIVITY] "+JSON.stringify({at:new Date().toISOString(),...value});
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
  assert.equal(parseWorkEvents(Array(100).fill(event({phase:"completed",tool:"read_file",path:"a.py"})).join("\n")).events.length,16);
  console.log("Read-only live progress, stale log exclusion, failure explanations and redaction PASSED");
}finally{await rm(root,{recursive:true,force:true});}
