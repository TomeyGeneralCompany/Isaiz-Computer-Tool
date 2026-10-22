/** Exercise the actual dashboard queue with an owned DB and a gated mock model. */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
const root=mkdtempSync(join(tmpdir(),"autohack-analysis-scheduling-"));
Object.assign(process.env,{PROJECT_ROOT:root,DB_PATH:join(root,"fixture.sqlite"),GITHUB_TOKEN:"owned-fixture",
  CLAUDE_BACKEND:"cli",OLLAMA_DISCOVERY_DIRECT:"true",OLLAMA_MODEL:"mock",OLLAMA_ASSESSMENT_TIMEOUT_MS:"5000"});
let respond:(()=>void)|undefined;
let calls=0;
const server=createServer(async(req,res)=>{
  for await (const _ of req) { /* consume request */ }
  calls++;
  respond=()=>res.end(JSON.stringify({done:true,done_reason:"stop",message:{content:JSON.stringify({
    rubric:{sourceCodeQuality:3,webApiSurface:0,techStackMatch:3,scopeBreadth:0,rewardEfficiency:2},
    topTargets:[{scopeId:1,reasoning:"Owned fixture",strategy:"code_review"}],techStack:["TypeScript"],
    attackSurface:"Owned source",recommendedApproach:"code_review"})}}));
});
async function until(check:()=>boolean) {
  const end=Date.now()+10000;
  while(!check()) {assert.ok(Date.now()<end,"Timed out waiting for fixture");await new Promise(r=>setTimeout(r,10));}
}
try {
  await new Promise<void>(r=>server.listen(0,"127.0.0.1",r));
  const address=server.address();assert.ok(address && typeof address!=="string");
  process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${address.port}/api/chat`;
  execFileSync(process.execPath,["--import","tsx","scripts/initialize-db.ts"],{stdio:"pipe"});
  const {getDb,schema}=await import("../packages/core/src/db/index");
  const {appRouter}=await import("../packages/dashboard/src/server/router");
  const {securityAnalyzeState:state}=await import("../packages/dashboard/src/server/job-state");
  const db=getDb();
  for(let i=0;i<5;i++) db.insert(schema.securityPrograms).values({id:`fixture-${i}`,name:`Fixture ${i}`,
    provider:"fixture",status:"active",rewardMaxCents:100000-i,discoveredAt:new Date(),updatedAt:new Date(),
    scopeSummary:JSON.stringify({scopes:[{assetType:"SOURCE_CODE",assetIdentifier:"https://github.com/fixture/owned",eligibleForBounty:true}]})}).run();
  const caller=appRouter.createCaller({});
  assert.equal((await caller.securityAnalyzePrograms()).total,5);
  await until(()=>calls===1);
  assert.equal(state.currentName,"Fixture 0","Local dashboard must dispatch one program, not five");
  state.startedAt=Date.now()-600000;state.lastActivityAt=Date.now()-600000;
  assert.equal((await caller.securityAnalyzePrograms()).reason,"already running","Slow inference is not stale");
  await caller.securityStopAnalyze();
  assert.equal((await caller.securityAnalyzePrograms()).reason,"already running","Stop must drain before restart");
  respond!();await until(()=>!state.running);
  assert.equal(calls,1,"Cancellation must not start the remaining programs");
  assert.equal((await caller.securityAnalyzePrograms()).total,4);
  for(let i=2;i<=5;i++) {
    await until(()=>calls===i);
    assert.equal(state.completed,i-2,"Each local result must finish before dispatching the next");
    respond!();
  }
  await until(()=>!state.running);
  assert.equal(state.completed,4);assert.deepEqual(state.errors,[]);
  console.log("Dashboard local serialization, slow-job guard, stop/restart and completion PASSED");
} finally {server.closeAllConnections();server.close();rmSync(root,{recursive:true,force:true});}
