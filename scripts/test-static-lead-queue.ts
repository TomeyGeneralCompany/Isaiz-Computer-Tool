/** Owned temporary database; injected investigation; no target requests or submissions. */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { eq } from "drizzle-orm";
const root=mkdtempSync(join(tmpdir(),"autohack-static-queue-"));
process.env.PROJECT_ROOT=root;
process.env.DB_PATH=join(root,"data","fixture.db");
process.env.GITHUB_TOKEN="owned-fixture";
process.env.LOCAL_OLLAMA_MODEL="owned-mock";
process.env.SECURITY_AUTO_HUNT_ENABLED="true";
process.env.SECURITY_AUTO_SUBMIT="false";
process.env.IMMUNEFI_ENABLED="true";
process.env.SKIP_PREVIOUSLY_HUNTED="true";
let networkCalls=0;
const fetchBefore=globalThis.fetch;
globalThis.fetch=(async()=>{networkCalls++;throw new Error("No network allowed in owned queue test");}) as typeof fetch;
try {
  execFileSync(process.execPath,["--import","tsx","scripts/initialize-db.ts"],{stdio:"pipe"});
  const {getDb,schema}=await import("../packages/core/src/index");
  const {processStaticLeadQueue}=await import("../packages/security-solver/src/static-leads");
  const {solveSecurityFinding}=await import("../packages/security-solver/src/index");
  const {analyzeAndRankFinding}=await import("../packages/security-analyzer/src/ranker");
  const db=getDb();const now=new Date();
  db.insert(schema.securityPrograms).values({id:"owned",provider:"immunefi",name:"Owned fixture",status:"active",rewardMaxCents:100000,
    discoveredAt:now,updatedAt:now,lastHuntedAt:now,scopeSummary:JSON.stringify({scopes:[{assetIdentifier:"https://github.com/fixture/owned",assetType:"SOURCE_CODE",eligibleForBounty:true}]})}).run();
  const insert=(id:string,file:string,more:Record<string,unknown>={})=>db.insert(schema.securityFindings).values({id,programId:"owned",title:"Unverified static lead",status:"validated",discoveredAt:now,updatedAt:now,
    analysisNotes:JSON.stringify({source:"offline_static_triage",repository:"fixture/owned",commit:"a".repeat(40),lead:{file,line:3,rule:"OWNED_FIXTURE"},...more})}).run();
  const get=(id:string)=>db.select().from(schema.securityFindings).where(eq(schema.securityFindings.id,id)).get()!;
  const notes=(id:string)=>JSON.parse(get(id).analysisNotes!);
  let dispatches=0;
  const inspect=async(_p:unknown,focus:any)=>{dispatches++;assert.equal(focus.commit,"a".repeat(40));return {findingsCreated:1};};
  for (const [id,file,legacy] of [
    ["offline-js","case.js",true],["offline-mjs","case.mjs",false],
    ["offline-cjs","case.cjs",false],["offline-sol","Case.sol",true],
    ["offline-python","case.py",false],
  ] as const) {
    insert(id,file,legacy ? {staticInvestigation:{state:"unsupported",detail:"Old Python-only gate"}} : {});
    let seen="";
    assert.equal(await processStaticLeadQueue(async(p,focus)=>{seen=focus.file;return inspect(p,focus);}),true);
    assert.equal(seen,file);
    assert.equal(notes(id).staticInvestigation.state,"completed");
    assert.equal(get(id).status,"discovered","The lead is never promoted without evidence");
  }
  assert.equal(dispatches,5);
  await processStaticLeadQueue(inspect);assert.equal(dispatches,5,"Completed leads must not repeat");
  insert("offline-other","case.rs");
  await processStaticLeadQueue(inspect);
  assert.equal(notes("offline-other").staticInvestigation.state,"unsupported");
  insert("offline-retry","case.py");
  await processStaticLeadQueue(async()=>{throw new Error("Owned model interruption");});
  assert.equal(notes("offline-retry").staticInvestigation.state,"retry");
  assert.equal(get("offline-retry").status,"discovered");
  await processStaticLeadQueue(inspect);assert.equal(dispatches,5,"Retry backoff must be respected");
  insert("offline-bad","../case.py");
  await processStaticLeadQueue(inspect);assert.equal(notes("offline-bad").staticInvestigation.state,"invalid");
  insert("offline-outside","case.py",{repository:"fixture/outside"});
  await processStaticLeadQueue(inspect);assert.equal(notes("offline-outside").staticInvestigation.state,"blocked");
  const {appRouter}=await import("../packages/dashboard/src/server/router");
  const caller=appRouter.createCaller({});
  assert.equal((await caller.securityAccept("offline-python")).success,false);
  assert.equal((await caller.securityApproveReport("offline-python")).success,false);
  await assert.rejects(solveSecurityFinding(get("offline-python")),/automatic evidence queue/);
  const before=get("offline-python").analysisNotes;
  await analyzeAndRankFinding(get("offline-python"));
  assert.equal(get("offline-python").analysisNotes,before,"Generic ranker must preserve static provenance");
  assert.equal(networkCalls,0);
  console.log("Static lead routing, recorded commit, unsupported classification, no manual promotion, idempotency, retry and scope boundary: PASSED");
} finally {globalThis.fetch=fetchBefore;rmSync(root,{recursive:true,force:true});}
