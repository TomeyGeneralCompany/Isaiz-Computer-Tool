import assert from "node:assert/strict";
import {mkdtempSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {execFileSync} from "node:child_process";
import {eq} from "drizzle-orm";
const root=mkdtempSync(join(tmpdir(),"poller-recovery-"));
process.env.PROJECT_ROOT=root;process.env.DB_PATH=join(root,"fixture.db");
process.env.GITHUB_TOKEN="fixture";process.env.HACKERONE_ENABLED="true";
process.env.HACKERONE_USERNAME="fixture";process.env.HACKERONE_API_TOKEN="fixture";
const originalFetch=globalThis.fetch;
try {
  execFileSync(process.execPath,["--import","tsx","scripts/initialize-db.ts"],{stdio:"pipe"});
  const {getDb,schema}=await import("../packages/core/src/index");
  const {pollHackerOne,pollSubmissionStatuses}=await import("../packages/security-discovery/src/poller");
  const db=getDb(),now=new Date();
  const summary={scopes:[],assessment:{opportunityScore:0.8},huntFailure:{attempts:2},inspectionPass:7};
  db.insert(schema.securityPrograms).values({id:"h1-fixture",provider:"hackerone",providerProgramId:"fixture",name:"Fixture",status:"archived",rewardMaxCents:10000,
    scopeSummary:JSON.stringify(summary),discoveredAt:now,updatedAt:now}).run();
  let scopeFailure=true,scopeCalls=0;
  let reportState="resolved",bounty:number|null=null;
  globalThis.fetch=async(input)=>{
    const url=new URL(String(input));
    if(url.pathname.endsWith("/hackers/programs"))return Response.json({data:[{id:"1",attributes:{handle:"fixture",name:"Fixture",offers_bounties:true,submission_state:"open",top_bounty_upper_amount:100}}]});
    if(url.pathname.endsWith("/structured_scopes")) {
      scopeCalls++;if(scopeFailure)throw new Error("Fixture scope outage");
      // Simulate an assessment finishing while the scope request is in flight.
      db.update(schema.securityPrograms).set({scopeSummary:JSON.stringify({...summary,inspectionPass:8})})
        .where(eq(schema.securityPrograms.id,"h1-fixture")).run();
      return Response.json({data:[{id:"scope",attributes:{asset_type:"SOURCE_CODE",asset_identifier:"https://github.com/fixture/owned",eligible_for_bounty:true}}]});
    }
    if(url.pathname.endsWith("/reports/42"))return Response.json({data:{attributes:{state:reportState,bounty_amount:bounty}}});
    throw new Error("Unexpected fixture URL: "+url);
  };
  const program=()=>db.select().from(schema.securityPrograms).get()!;
  await pollHackerOne();
  assert.equal(program().status,"active");assert.deepEqual(JSON.parse(program().scopeSummary!).scopes,[]);
  scopeFailure=false;await pollHackerOne();
  const recovered=JSON.parse(program().scopeSummary!);
  assert.equal(recovered.scopes.length,1);assert.deepEqual(recovered.assessment,summary.assessment);
  assert.deepEqual(recovered.huntFailure,summary.huntFailure);assert.equal(recovered.inspectionPass,8);
  assert.equal(scopeCalls,2);await pollHackerOne();assert.equal(scopeCalls,2,"Fresh populated scopes need no redundant refresh");
  db.update(schema.securityPrograms).set({status:"paused"}).where(eq(schema.securityPrograms.id,"h1-fixture")).run();
  await pollHackerOne();assert.equal(program().status,"paused","Preserve operator pause");
  db.insert(schema.securityFindings).values({id:"finding",programId:"h1-fixture",title:"Owned fixture",status:"submitted",reportId:"42",discoveredAt:now,updatedAt:now}).run();
  const finding=()=>db.select().from(schema.securityFindings).get()!;
  await pollSubmissionStatuses();assert.equal(finding().status,"accepted");assert.equal(finding().rewardedCents,null);
  bounty=50;await pollSubmissionStatuses();assert.equal(finding().status,"rewarded");assert.equal(finding().rewardedCents,5000);
  bounty=75;await pollSubmissionStatuses();assert.equal(finding().rewardedCents,7500);
  assert.equal(await pollSubmissionStatuses(),0,"Unchanged award must not produce repeated updates");
  bounty=null;await pollSubmissionStatuses();assert.equal(finding().status,"rewarded");assert.equal(finding().rewardedCents,7500);
  db.update(schema.securityFindings).set({status:"triaged",rewardedCents:null}).where(eq(schema.securityFindings.id,"finding")).run();
  reportState="triaged";bounty=25;await pollSubmissionStatuses();assert.equal(finding().rewardedCents,2500);assert.equal(finding().status,"triaged");
  reportState="resolved";await pollSubmissionStatuses();assert.equal(finding().status,"rewarded");
  console.log("Scope outage recovery, archive reactivation, pause preservation, metadata preservation and late/unchanged-state bounty awards: PASSED");
} finally {globalThis.fetch=originalFetch;rmSync(root,{recursive:true,force:true});}
