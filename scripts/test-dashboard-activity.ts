import assert from "node:assert/strict";
import {mkdtemp,mkdir,writeFile,readFile,rm,utimes} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {readLocalActivity,describeHuntFailure} from "../packages/dashboard/src/server/activity";

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
  console.log("Read-only live progress, stale log exclusion, failure explanations and redaction PASSED");
}finally{await rm(root,{recursive:true,force:true});}
