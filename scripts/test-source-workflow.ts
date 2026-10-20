/** Real owned Git source + model actions + sandbox + report + evidence replay. */
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {execFileSync} from "node:child_process";
import {mkdtemp,writeFile,mkdir,rm,chmod} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
const root=await mkdtemp(join(tmpdir(),"tomey-workflow-"));
const originalPath=process.env.PATH;
process.env.PROJECT_ROOT=root;
process.env.GITHUB_TOKEN="owned-fixture";
process.env.LOCAL_OLLAMA_MODEL="mock";
process.env.LOCAL_OLLAMA_TOOL_PROTOCOL="json";
const server=createServer();
try {
  const fixture=join(root,"fixture");await mkdir(fixture);
  await writeFile(join(fixture,"render.cjs"),'exports.render = x => "<p>"+x+"</p>";');
  await writeFile(join(fixture,"Render.sol"),'pragma solidity ^0.8.20; contract Render { function render(string memory x) public pure returns(string memory) { return string.concat("<p>",x,"</p>"); }}');
  await writeFile(join(fixture,"caller.js"),'renderer.render(input);');
  await writeFile(join(fixture,"Caller.sol"),'renderer.render(input);');
  execFileSync("git",["init","-q",fixture]);
  execFileSync("git",["-C",fixture,"add","."]);
  execFileSync("git",["-C",fixture,"-c","user.name=Fixture","-c","user.email=fixture@example.test","commit","-qm","Owned fixture"]);
  const realGit=execFileSync("which",["git"],{encoding:"utf8"}).trim();
  const bin=join(root,"bin");await mkdir(bin);
  await writeFile(join(bin,"git"),'#!/usr/bin/python3\nimport os,sys,shutil\nargs=sys.argv[1:]\nif "clone" in args:\n    shutil.copytree('+JSON.stringify(fixture)+',args[-1])\nelse:\n    os.execv('+JSON.stringify(realGit)+',['+JSON.stringify(realGit)+']+args)\n');
  await chmod(join(bin,"git"),0o700);process.env.PATH=bin+":"+originalPath;
  let turn=0, caseId="", source="", caller="", selector="";
  server.on("request",async(req,res)=>{
    let raw="";for await(const chunk of req)raw+=chunk;
    const request=JSON.parse(raw);turn++;
    assert.ok(request.format.properties.action.enum.includes("verify_source"));
    assert.ok(request.messages.some((m:any)=>m.content.includes("exported JavaScript")));
    const action=(name:string,path:string,query="",answer="")=>({action:name,path,query,answer});
    let next;
    if(turn===1)next=action("read_file","source-1/"+source);
    else if(turn===2)next=action("read_file","source-1/"+caller);
    else if(turn===3)next=action("verify_source","source-1/"+source,"missing","html_reflection");
    else if(turn===4) {
      const previous=JSON.parse(request.messages.at(-1).content.split("\n")[0].slice("TOOL_RESULT ".length));
      assert.equal(JSON.parse(previous.output).status,"probe_failed");
      next=action("verify_source","source-1/"+source,selector,"html_reflection");
    } else {
      const previous=JSON.parse(request.messages.at(-1).content.split("\n")[0].slice("TOOL_RESULT ".length));
      caseId=JSON.parse(previous.output).caseId;assert.ok(caseId);
      next=action("final","","",JSON.stringify({findings:[{
        caseId,severity:"medium",confidence:0.7,title:"Owned fixture reflection",
        ratingReason:"Owned fixture preserves input; this test checks report plumbing only.",
        impact:"Owned fixture returns raw markup to its caller.",
        callerFile:"source-1/"+caller,callerLine:1,
        falsification:"No production exploitability is claimed; only owned fixture behavior was measured."
      }]}));
    }
    res.setHeader("Content-Type","application/json");
    res.end(JSON.stringify({message:{role:"assistant",content:JSON.stringify(next)}}));
  });
  await new Promise<void>(r=>server.listen(0,"127.0.0.1",r));
  const address=server.address();assert.ok(address&&typeof address!=="string");
  process.env.AUTOHACK_OLLAMA_URL="http://127.0.0.1:"+address.port+"/api/chat";
  const {runLocalProgramHunt}=await import("../packages/security-solver/src/local-program-flow");
  const {readSourceCase,replaySourceCase}=await import("../packages/security-solver/src/source-reproduction");
  const {referencesProbedFunction}=await import("../packages/security-solver/src/source-function-reference");
  assert.equal(referencesProbedFunction("renderer.render(input)","Render.render"),true);
  assert.equal(referencesProbedFunction("renderer.prerender(input)","Render.render"),false);
  assert.equal(referencesProbedFunction("// render is declared here","Render.render"),false);
  const program:any={id:"owned",provider:"immunefi",name:"Owned fixture",scopeSummary:JSON.stringify({scopes:[
    {assetType:"SOURCE_CODE",eligibleForBounty:true,assetIdentifier:"https://github.com/fixture/owned"}
  ]})};
  for(const language of ["javascript","solidity"]) {
    turn=0;caseId="";
    source=language==="javascript"?"render.cjs":"Render.sol";
    caller=language==="javascript"?"caller.js":"Caller.sol";
    selector=language==="javascript"?"render":"Render.render";
    const result=await runLocalProgramHunt(program);
    assert.equal(result.success,true,JSON.stringify(result));
    assert.equal(result.findings.length,1);
    assert.ok(result.coverageDetail?.includes("1 failed probes"));
    const record=await readSourceCase(caseId,program);
    assert.equal((await replaySourceCase(record,fixture)).behavior_observed,true);
  }
  console.log("JavaScript/Solidity model action -> failed probe recovery -> sandbox -> caller -> report -> persisted evidence -> replay PASSED");
} finally {
  process.env.PATH=originalPath;
  await new Promise<void>(r=>server.close(()=>r()));
  await rm(root,{recursive:true,force:true});
}
