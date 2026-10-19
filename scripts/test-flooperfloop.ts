/** Entirely owned fictional fixture. All provider traffic is intercepted. */
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
const root = mkdtempSync(join(tmpdir(), "flooperfloop-"));
const repository = join(root, "owned-repository");
const repoUrl = "https://github.com/flooperfloop-fictional/owned";
const handle = "flooperfloop-fictional";
const policy = "FICTIONAL ONLY: Flooperfloop offers 100 GLIFNARKS for missing encoding in its owned Python sample. No real service or payment exists. Only the explicitly supplied source repository is in scope. Reproduce locally; do not contact targets.";
Object.assign(process.env, {PROJECT_ROOT:root,DB_PATH:join(root,"data","fixture.sqlite"),
  GITHUB_TOKEN:"fictional-only",HACKERONE_USERNAME:"fictional-only",HACKERONE_API_TOKEN:"fictional-only",
  HACKERONE_ENABLED:"true",SECURITY_AUTO_HUNT_ENABLED:"true",SECURITY_AUTO_SUBMIT:"true",
  IMMUNEFI_ENABLED:"false",HUNTR_ENABLED:"false",AGGREGATOR_ENABLED:"false",
  LOCAL_OLLAMA_MODEL:"fictional-model",LOCAL_OLLAMA_TOOL_PROTOCOL:"json",OLLAMA_DISCOVERY_DIRECT:"true",
  SECURITY_MIN_REWARD_CENTS:"1",SECURITY_MIN_CONFIDENCE:"0.65",SECURITY_MIN_RUBRIC_SCORE:"8"});
const originalFetch=globalThis.fetch;
let submitted=0, assessments=0, huntTurns=0, reviewTurns=0, prepared=0;
let reportPayload:any;
const json=(value:unknown)=>Response.json(value);
const model=createServer(async(req,res)=>{
  try {
    let raw="";for await(const chunk of req)raw+=String(chunk);
    const data=JSON.parse(raw);
    let content:string;
    if(data.format?.properties?.action) {
      const reviewing=data.messages.some((m:any)=>m.content.includes("Independently review this report"));
      if(reviewing)reviewTurns++;else huntTurns++;
      const results=data.messages.filter((m:any)=>m.content.startsWith("TOOL_RESULT ")).map((m:any)=>{
        const value=JSON.parse(m.content.slice(12).split("\nChoose the next JSON action.")[0]);
        return value;
      });
      const sourceRead=results.some((r:any)=>r.name==="read_file" && r.output.includes("def render("));
      const callerRead=results.some((r:any)=>r.name==="read_file" && r.output.includes("def endpoint("));
      let action:any;
      const prefix=reviewing?"source":"source-1";
      if(!sourceRead)action={action:"read_file",path:prefix+"/renderer.py",query:"",answer:""};
      else if(!callerRead)action={action:"read_file",path:prefix+"/app.py",query:"",answer:""};
      else if(reviewing)action={action:"final",path:"",query:"",answer:JSON.stringify({
        verdict:"approve",recommendation:"submit",severity:"medium",confidence:0.9,
        ratingReason:"The owned caller passes input directly to the observed unescaped HTML renderer; severity and confidence apply only to this controlled fictional example.",
        bet100:true,rubric:{exploitability:3,impactSeverity:2,evidenceQuality:3,novelty:2,scopeAlignment:3},issues:[],
        reasoning:"The source and caller were read, and the production review replayed the recorded commit and exact observations. This approval is synthetic fixture data only."})};
      else {
        const probe=results.find((r:any)=>r.name==="verify_python");
        if(!probe)action={action:"verify_python",path:"source-1/renderer.py",query:"render",answer:"html_reflection"};
        else {
          const evidence=JSON.parse(probe.output);
          assert.ok(["behavior_observed","behavior_not_observed"].includes(evidence.status),probe.output);
          action={action:"final",path:"",query:"",answer:JSON.stringify({findings:evidence.caseId?[{
            caseId:evidence.caseId,title:"Flooperfloop owned renderer omits HTML encoding",severity:"medium",confidence:0.9,
            ratingReason:"The fixed function probe shows exact marker reflection, and the owned caller passes its argument directly to render. No live exploitation is claimed.",
            impact:"In this fictional application, the owned caller returns unescaped user text inside HTML. This report concerns only the controlled source fixture, not a live service.",
            callerFile:"source-1/app.py",callerLine:4,
            falsification:"Read both the renderer and its caller: no encoder or sanitizer appears in either owned file. Replay confirms reflection only; browser execution and live impact are not asserted."
          }]:[]})};
        }
      }
      content=JSON.stringify(action);
    } else if(data.format?.properties?.rubric) {
      assessments++;
      content=JSON.stringify({rubric:{sourceCodeQuality:3,webApiSurface:0,techStackMatch:3,scopeBreadth:1,rewardEfficiency:2},
        targetCount:1,topTargets:[{asset:repoUrl,type:"SOURCE_CODE",reasoning:"Owned fictional Python source",strategy:"code_review"}],
        techStack:["Python"],attackSurface:"Owned renderer and its caller",recommendedApproach:"code_review"});
    } else {
      prepared++;
      content=JSON.stringify({policyExcluded:false,fields:{weakness_id:116,weakness_name:"CWE-116",structured_scope_id:"flooper-scope",
        cvss:{attack_vector:"network",attack_complexity:"low",privileges_required:"none",user_interaction:"required",scope:"unchanged",confidentiality:"none",integrity:"low",availability:"none"}}});
    }
    res.setHeader("content-type","application/json");res.end(JSON.stringify({done:true,done_reason:"stop",message:{role:"assistant",content}}));
  }catch(error){res.statusCode=500;res.end(String(error));}
});
try {
  mkdirSync(repository);
  const git=(args:string[])=>execFileSync("/usr/bin/git",args,{cwd:repository,encoding:"utf8"});
  git(["init","-q"]);git(["config","user.name","Flooperfloop fictional fixture"]);git(["config","user.email","fixture@example.invalid"]);
  writeFileSync(join(repository,"renderer.py"),'def render(value):\n    return "<h1>" + value + "</h1>"\n');
  writeFileSync(join(repository,"app.py"),'from renderer import render\n\ndef endpoint(value):\n    return render(value)\n');
  git(["add","."]);git(["commit","-qm","Owned fictional source"]);
  const recordedCommit=git(["rev-parse","HEAD"]).trim();
  const bin=join(root,"bin");mkdirSync(bin);
  const transport=join(bin,"git");
  writeFileSync(transport,`#!/usr/bin/env python3
import os, sys
args=sys.argv[1:]
if "clone" in args:
    if args[-2] != ${JSON.stringify(repoUrl)}: raise SystemExit("Unowned clone blocked")
    args[-2]=${JSON.stringify(repository)}
elif "fetch" not in args and "checkout" not in args and "rev-parse" not in args:
    raise SystemExit("Unexpected Git operation blocked")
os.execv("/usr/bin/git",["git","-c","protocol.file.allow=always"]+args)
`);chmodSync(transport,0o700);
  process.env.PATH=bin+":"+process.env.PATH;
  execFileSync(process.execPath,["--import","tsx","scripts/initialize-db.ts"],{stdio:"pipe"});
  await new Promise<void>(resolve=>model.listen(0,"127.0.0.1",resolve));
  const address=model.address();assert.ok(address && typeof address!=="string");
  const modelUrl=`http://127.0.0.1:${address.port}/api/chat`;process.env.AUTOHACK_OLLAMA_URL=modelUrl;
  globalThis.fetch=(async(input,init)=>{
    const url=String(input);
    if(url===modelUrl)return originalFetch(input,init);
    if(url==="https://hackerone.com/graphql")return json({data:{team:{policy,
      hacktivity_items:{total_count:0,edges:[]},response_efficiency_percentage:90,signal_requirements_setting:{target_signal:null}}}});
    if(url.startsWith("https://api.hackerone.com/v1/hackers/programs?"))return json({data:[{id:handle,type:"program",attributes:{
      handle,name:"Flooperfloop — 100 fictional GLIFNARKS",offers_bounties:true,submission_state:"open",state:"public",
      top_bounty_lower_amount:100,top_bounty_upper_amount:100}}]});
    if(url.startsWith(`https://api.hackerone.com/v1/hackers/programs/${handle}/structured_scopes?`))return json({data:[{
      id:"flooper-scope",attributes:{asset_type:"SOURCE_CODE",asset_identifier:repoUrl,eligible_for_bounty:true,max_severity:"medium"}}]});
    if(url.startsWith(`https://api.hackerone.com/v1/hackers/programs/${handle}/weaknesses?`))return json({data:[{
      id:"116",attributes:{external_id:"CWE-116",name:"Improper Encoding"}}]});
    if(url==="https://api.hackerone.com/v1/hackers/reports" && init?.method==="POST") {
      submitted++;reportPayload=JSON.parse(String(init.body));
      assert.equal(reportPayload.data.attributes.team_handle,handle);
      assert.match(reportPayload.data.attributes.vulnerability_information,/Flooperfloop/);
      assert.match(reportPayload.data.attributes.vulnerability_information,/Reproduction case: [a-f0-9]{64}/);
      return json({data:{id:"flooperfloop-mock-receipt",attributes:{url:"https://reports.example.invalid/flooperfloop"}}});
    }
    throw new Error("All unexpected network traffic blocked: "+url);
  }) as typeof fetch;
  const {getDb,schema}=await import("../packages/core/src/db/index");
  const {eq}=await import("drizzle-orm");
  const {pollHackerOne}=await import("../packages/security-discovery/src/poller");
  const {processSecurityProgramQueue}=await import("../packages/security-analyzer/src/ranker");
  const {huntProgram,pickBestProgram,processAdversarialQueue}=await import("../packages/security-solver/src/index");
  assert.equal(await pollHackerOne(),1);
  const db=getDb();db.update(schema.securityPrograms).set({currency:"GLIFNARK"}).run();
  assert.equal(await processSecurityProgramQueue(),1);
  assert.equal(assessments,1);
  const program=pickBestProgram();assert.ok(program);assert.equal(program.providerProgramId,handle);
  assert.deepEqual(await huntProgram(program),{findingsCreated:1});
  const finding=db.select().from(schema.securityFindings).get()!;assert.ok(finding);
  assert.equal(finding.status,"report_ready");assert.match(finding.reportBody!,new RegExp(recordedCommit));
  const caseId=JSON.parse(finding.analysisNotes!).reproductionCaseId;
  const proof=JSON.parse(readFileSync(join(root,"data","reproduction",caseId+".json"),"utf8"));
  assert.equal(proof.result.status,"behavior_observed");assert.equal(proof.commit,recordedCommit);
  // The source moves forward: review must still acquire the recorded revision.
  writeFileSync(join(repository,"README.md"),"Flooperfloop fictional revision after finding\n");git(["add","."]);git(["commit","-qm","Advance fictional source revision"]);
  assert.notEqual(git(["rev-parse","HEAD"]).trim(),recordedCommit);
  await processAdversarialQueue();
  let stored=db.select().from(schema.securityFindings).get()!;
  assert.equal(stored.status,"submitted");assert.equal(submitted,1);assert.equal(prepared,1);
  const {readSubmissionOutbox}=await import("../packages/core/src/submission-outbox");
  assert.equal(readSubmissionOutbox()[finding.id].state,"confirmed");
  await processAdversarialQueue();assert.equal(submitted,1);
  db.update(schema.securityFindings).set({status:"reviewing",reportId:null,reportUrl:null}).where(eq(schema.securityFindings.id,finding.id)).run();
  await processAdversarialQueue();stored=db.select().from(schema.securityFindings).get()!;
  assert.equal(stored.status,"submitted");assert.equal(submitted,1,"Recovery must never duplicate a mock report");
  // Same owned program, now fixed: a completed negative probe yields no new report.
  writeFileSync(join(repository,"renderer.py"),'import html\n\ndef render(value):\n    return "<h1>" + html.escape(value) + "</h1>"\n');
  git(["add","."]);git(["commit","-qm","Encode fictional sample"]);
  const current=db.select().from(schema.securityPrograms).get()!;
  assert.deepEqual(await huntProgram(current),{findingsCreated:0});
  assert.equal(submitted,1);
  assert.ok(huntTurns>=8);assert.ok(reviewTurns>=3);
  console.log("FLOOPERFLOOP A -> B -> C -> D PASSED: fictional discovery/assessment -> actual isolated source reproduction -> report/independent replay -> intercepted submission/recovery; fixed-source negative control passed; zero real target/report requests.");
}finally{
  globalThis.fetch=originalFetch;model.closeAllConnections();await new Promise<void>(resolve=>model.close(()=>resolve()));
  rmSync(root,{recursive:true,force:true});
}
