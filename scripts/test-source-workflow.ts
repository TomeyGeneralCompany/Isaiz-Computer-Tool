/** Real owned Git source + model actions + sandbox + report + evidence replay. */
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {execFileSync} from "node:child_process";
import {mkdtemp,writeFile,readFile,mkdir,rm,chmod} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
const root=await mkdtemp(join(tmpdir(),"tomey-workflow-"));
const originalPath=process.env.PATH;
process.env.PROJECT_ROOT=root;
process.env.GITHUB_TOKEN="owned-fixture";
process.env.LOCAL_OLLAMA_MODEL="mock";
process.env.LOCAL_OLLAMA_TOOL_PROTOCOL="json";
// This scripted fixture expects to drive the first read itself; the separate
// seeded-source fixture exercises production's automatic first read.
process.env.AUTOHACK_AUTO_SOURCE_PREFETCH="false";
process.env.LOCAL_HUNT_NUM_PREDICT="4096";
const controllerText=await readFile(join(process.cwd(),"packages/security-solver/src/local-ollama-runner.ts"),"utf8");
assert.ok(controllerText.includes("requiredNextSource"),"coverage rejection must enforce a fresh eligible source read");
assert.ok(controllerText.includes("[EMPTY_FINAL_RECOVER]"),"repeated empty finals must reopen source investigation");
assert.ok(controllerText.includes("requireInvestigationAfterEmpty"),"recovery must require a tool action rather than another empty final");
assert.ok(!controllerText.includes("recentActions.clear();stalledActions=0"),"final rejection must preserve read history");
const server=createServer();
try {
  const fixture=join(root,"fixture");await mkdir(fixture);
  await writeFile(join(fixture,"Render.java"),'public class Render { public static String render(String x) { return "<p>"+x+"</p>"; }}');
  await writeFile(join(fixture,"Caller.java"),'Render.render(input);');
  await writeFile(join(fixture,"render.cjs"),'exports.render = x => "<p>"+x+"</p>";');
  await writeFile(join(fixture,"Render.sol"),'pragma solidity ^0.8.20; contract Render { function render(string memory x) public pure returns(string memory) { return string.concat("<p>",x,"</p>"); }}');
  await writeFile(join(fixture,"Store.sol"),'pragma solidity ^0.8.20; contract Store { uint256 public value; constructor(uint256 initial) {value=initial;} function set(uint256 x) external {value=x;} }');
  await writeFile(join(fixture,"StoreCaller.sol"),'store.set(input);');
  await writeFile(join(fixture,"caller.js"),'renderer.render(input);');
  await writeFile(join(fixture,"Caller.sol"),'renderer.render(input);');
  for(let i=0;i<35;i++)await writeFile(join(fixture,"incompatible_"+String(i).padStart(3,"0")+"_"+"x".repeat(100)+".sol"),"pragma solidity 0.6.0; contract Old {} ");
  execFileSync("git",["init","-q",fixture]);
  execFileSync("git",["-C",fixture,"add","."]);
  execFileSync("git",["-C",fixture,"-c","user.name=Fixture","-c","user.email=fixture@example.test","commit","-qm","Owned fixture"]);
  const realGit=execFileSync("which",["git"],{encoding:"utf8"}).trim();
  const bin=join(root,"bin");await mkdir(bin);
  await writeFile(join(bin,"git"),'#!/usr/bin/python3\nimport os,sys,shutil,subprocess\nargs=sys.argv[1:]\nif "clone" in args:\n    shutil.copytree('+JSON.stringify(fixture)+',args[-1])\nelif \"fetch\" in args:\n    subprocess.run(['+JSON.stringify(realGit)+',\"cat-file\",\"-e\",args[-1]+\"^{commit}\"],check=True)\nelse:\n    os.execv('+JSON.stringify(realGit)+',['+JSON.stringify(realGit)+']+args)\n');
  await chmod(join(bin,"git"),0o700);process.env.PATH=bin+":"+originalPath;
  let policyOffset=0,policyDone=false;
  let turn=0, caseId="", source="", caller="", selector="", stateful=false,reviewMode=false,reviewIndex=0,reviewOffset=0;
  const reviewFiles=["source/Store.sol","evidence/report.txt","evidence/replay.json","evidence/policy.txt"];
  const sequence={constructorArgs:["5"],steps:[
    {operation:"call",function:"value()",args:[],expect:"5"},
    {operation:"send",function:"set(uint256)",args:["7"]},
    {operation:"call",function:"value()",args:[],expect:"8"},
  ]};
  server.on("request",async(req,res)=>{
    let raw="";for await(const chunk of req)raw+=chunk;
    const request=JSON.parse(raw);
    // Production progress is appended separately; inspect the last actual tool result.
    const latestTool=()=>[...request.messages].reverse().find((m:any)=>m.content?.startsWith("TOOL_RESULT "));
    assert.ok(JSON.stringify(request.messages).length+JSON.stringify(request.format).length <= (8192-request.options.num_predict-512)*3,'Every production request fits its declared budget');
    if(!reviewMode && !policyDone) {
      const last=latestTool();
      if(last) {const page=JSON.parse(JSON.parse(last.content.split('\n')[0].slice(12)).output);policyDone=page.nextOffset===null;policyOffset=page.nextOffset;}
      if(!policyDone) {res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify({action:'read_file',path:'audit-policy.txt',offset:policyOffset,query:'',answer:''})}}));return;}
    }
    if(!reviewMode && request.format.properties.action.enum.length===1 && request.format.properties.action.enum[0]==='verify_source') {
      const planned=[...request.messages].reverse().map((m:any)=>{try{return JSON.parse(m.content);}catch{return null;}}).find((a:any)=>a?.action==='plan_probe');
      assert.ok(planned);
      res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify({...planned,action:'verify_source'})}}));return;
    }
    // Finish the current read before advancing the scripted investigation stage.
    // Output-token reservations may change page size; evidence must stay complete.
    if(!reviewMode && turn>0) {
      const last=latestTool()?.content || request.messages.at(-1).content;
      if(last.startsWith("TOOL_RESULT ")) {
        const result=JSON.parse(last.split("\n")[0].slice(12));
        if(result.name==="read_file") {
          const page=JSON.parse(result.output);
          if(page.nextOffset!=null) {
            const previous=[...request.messages].reverse().map((m:any)=>{try{return JSON.parse(m.content);}catch{return null;}}).find((a:any)=>a?.action==='read_file');
            res.end(JSON.stringify({message:{role:"assistant",content:JSON.stringify({
              action:"read_file",path:previous.path,offset:page.nextOffset,query:"",answer:""})}}));
            return;
          }
        }
      }
    }
    turn++;
    if(reviewMode) {
      assert.ok(request.messages[1].content.length<7000,"Review prompt must not embed large policy/report");
      const last=latestTool()?.content || request.messages.at(-1).content;
      if(last.startsWith("TOOL_RESULT ")) {
        const page=JSON.parse(JSON.parse(last.split("\n")[0].slice(12)).output);
        if(page.nextOffset===null) {reviewIndex++;reviewOffset=0;}else reviewOffset=page.nextOffset;
      }
      const action=reviewIndex<reviewFiles.length
        ? {action:"read_file",path:reviewFiles[reviewIndex],offset:reviewOffset,query:"",answer:""}
        : {action:"final",path:"",query:"",answer:JSON.stringify({verdict:"reject",recommendation:"dont_submit",severity:"informational",confidence:0.9,
          ratingReason:"This synthetic fixture deliberately uses an incorrect expected value; it is not a vulnerability.",bet100:false,
          rubric:{exploitability:0,impactSeverity:0,evidenceQuality:3,novelty:0,scopeAlignment:3},issues:[],reasoning:"The supplied expectation is deliberately wrong; only report plumbing is under test."})};
      res.end(JSON.stringify({message:{role:"assistant",content:JSON.stringify(action)}}));return;
    }
    assert.ok(request.format.properties.action.enum.includes("plan_probe"));
    assert.ok(request.messages.some((m:any)=>m.content.includes("exported JavaScript")));
    const action=(name:string,path:string,query="",answer="")=>({action:name,path,query,answer});
    let next;
    if(turn===1)next=action("read_file","source-1/"+source);
    else if(turn===2 && stateful)next=action("final","","",JSON.stringify({findings:[]}));
    else if(turn===2)next=action("read_file","source-1/"+caller);
    else if(turn===3 && stateful) {assert.ok(JSON.stringify(request.messages).includes("No supported probe"));next={...action("verify_source","source-1/"+source,selector,"solidity_sequence"),sequence};}
    else if(turn===3)next=action("verify_source","source-1/"+source,source.endsWith(".java")?"Render.missing":"missing","html_reflection");
    else if(turn===4 && !stateful) {
      const previous=JSON.parse((latestTool()?.content || "").split("\n")[0].slice("TOOL_RESULT ".length));
      assert.equal(JSON.parse(previous.output).status,source.endsWith(".java")?"invalid_probe":"probe_failed");
      next=action("verify_source","source-1/"+source,selector,"html_reflection");
    } else {
      const previous=JSON.parse((latestTool()?.content || "").split("\n")[0].slice("TOOL_RESULT ".length));
      caseId=JSON.parse(previous.output).caseId;assert.ok(caseId);
      next=action("final","","",JSON.stringify({findings:[{
        caseId,severity:"medium",confidence:0.7,title:stateful?"Owned fixture assertion discrepancy":"Owned fixture reflection",
        ratingReason:"Owned fixture preserves input; this test checks report plumbing only.",
        impact:stateful?"Owned fixture returns 7 while the supplied test expects 8; no vulnerability claimed.":"Owned fixture returns raw markup to its caller.",
        callerFile:"source-1/"+(stateful?source:caller),callerLine:1,...(stateful?{reachability:"direct_transaction"}:{}),
        falsification:"No production exploitability is claimed; only owned fixture behavior was measured."
      }]}));
    }
    if(next.action==='verify_source')next={...next,action:'plan_probe',hypothesis:'Owned fixture behavior may violate the stated requirement; an escaped value or matching assertion would disprove it.'};
    res.setHeader("Content-Type","application/json");
    res.end(JSON.stringify({message:{role:"assistant",content:JSON.stringify(next)}}));
  });
  await new Promise<void>(r=>server.listen(0,"127.0.0.1",r));
  const address=server.address();assert.ok(address&&typeof address!=="string");
  process.env.AUTOHACK_OLLAMA_URL="http://127.0.0.1:"+address.port+"/api/chat";
  const {runLocalProgramHunt,independentReview}=await import("../packages/security-solver/src/local-program-flow");
  const {readSourceCase,replaySourceCase}=await import("../packages/security-solver/src/source-reproduction");
  const {referencesProbedFunction}=await import("../packages/security-solver/src/source-function-reference");
  assert.equal(referencesProbedFunction("renderer.render(input)","Render.render"),true);
  assert.equal(referencesProbedFunction("renderer.prerender(input)","Render.render"),false);
  assert.equal(referencesProbedFunction("// render is declared here","Render.render"),false);
  const program:any={id:"owned",provider:"immunefi",name:"Owned fixture",scopeSummary:JSON.stringify({policy:"Owned fixture policy; local tests only. ".repeat(300),scopes:[
    {assetType:"SOURCE_CODE",eligibleForBounty:true,assetIdentifier:"https://github.com/fixture/owned"}
  ]})};
  for(const language of ["javascript","java","solidity","stateful_solidity"]) {
    turn=0;policyOffset=0;policyDone=false;caseId="";stateful=language==="stateful_solidity";
    source=language==="javascript"?"render.cjs":language==="java"?"Render.java":"Render.sol";
    caller=language==="javascript"?"caller.js":language==="java"?"Caller.java":"Caller.sol";
    selector=language==="javascript"?"render":"Render.render";
    if(stateful) {source="Store.sol";caller="StoreCaller.sol";selector="Store.set";}
    const result=await runLocalProgramHunt(program);
    if(!result.success && result.auditRecord)console.error(await readFile(join(root,"data/logs",result.auditRecord),"utf8"));
    assert.equal(result.success,true,JSON.stringify(result));
    assert.equal(result.findings.length,1);
    if(!stateful)assert.ok(result.coverageDetail?.includes(language==="java"?"1 unsupported probes":"1 failed probes"));
    else assert.equal(result.findings[0].vulnerabilityType,"State assertion discrepancy");
    const record=await readSourceCase(caseId,program);
    assert.equal((await replaySourceCase(record,fixture)).behavior_observed,true);
    if(stateful) {
      assert.deepEqual(record.spec.sequence,sequence);
      assert.match(result.findings[0].reportBody,/Reachability: direct_transaction/);
      reviewMode=true;reviewIndex=0;reviewOffset=0;
      const reviewProgram={...program,scopeSummary:JSON.stringify({...JSON.parse(program.scopeSummary),policy:"Long policy text. ".repeat(1600)})};
      const reviewed=await independentReview({...result.findings[0],id:"owned-review"} as any,reviewProgram,caseId,new AbortController().signal);
      assert.equal(reviewed.review.verdict,"reject");assert.equal(reviewIndex,reviewFiles.length);
      reviewMode=false;
      assert.ok(result.findings[0].reportBody.includes(JSON.stringify(sequence,null,2)));
    }
  }
  console.log("JavaScript/Java/Solidity model action -> failed probe recovery -> sandbox -> caller -> report -> persisted evidence -> replay PASSED");
} finally {
  process.env.PATH=originalPath;
  await new Promise<void>(r=>server.close(()=>r()));
  await rm(root,{recursive:true,force:true});
}

// Integration regression: compaction may discard model-visible pages but must not
// discard pagination cursors, and the 2,000-character source chunk cap remains.
assert.ok(controllerText.includes('sourceReadCounts'), 'repeated source reads must survive compaction');
assert.ok(controllerText.includes('Keep the cursor even if the previous message was compacted away'), 'evicted pages must preserve pagination');
assert.ok(controllerText.includes('[PROBE_RESULT]'), 'probe outcomes must be observable in hunt logs');
assert.ok(controllerText.includes('Math.min(2000'), 'CPU-friendly file chunking must remain active');
