import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "node:http";
import { readSourcePage, searchSourcePage, SourceReads } from "../packages/security-solver/src/source-inspection";
import { selectSourceBatch, incompleteProbeCoverage } from "../packages/security-solver/src/inspection-coverage";
import { runLocalAudit, activeLocalAuditCount } from "../packages/security-solver/src/local-ollama-runner";
const root=await mkdtemp(join(tmpdir(),"inspection-regression-"));
const server=createServer();
try {
  const text="padding\n".repeat(5000)+"renderer.render(input);\n";
  await writeFile(join(root,"large.js"),text);
  const reads=new SourceReads();
  let offset:number|null=0, assembled="";
  while(offset!==null) {
    const page=await readSourcePage(join(root,"large.js"),offset);
    reads.add("large.js",page);
    if(offset===0)assert.equal(reads.sawLine("large.js",text,5001),false);
    assembled+=page.text;offset=page.nextOffset;
  }
  assert.equal(assembled,text);
  assert.ok(reads.sawLine("large.js",text,5001));
  assert.equal(reads.sawLine("large.js",text,9999),false);
  const split=new SourceReads();split.add("file",{start:0,end:5});
  assert.equal(split.sawLine("file","long caller();",1),false);
  split.add("file",{start:5,end:14});assert.ok(split.sawLine("file","long caller();",1));
  await mkdir(join(root,"scoped"));
  for(let i=0;i<305;i++)await writeFile(join(root,"scoped",String(i).padStart(3,"0")+".js"),"// ordinary source");
  await writeFile(join(root,"scoped","304.js"),"// LAST_NEEDLE");
  const first=await searchSourcePage(root,join(root,"scoped"),"LAST_NEEDLE");
  assert.equal(first.complete,false);assert.equal(first.nextOffset,300);assert.deepEqual(first.results,[]);
  const second=await searchSourcePage(root,join(root,"scoped"),"LAST_NEEDLE",first.nextOffset!);
  assert.equal(second.complete,true);assert.equal(second.results.length,1);
  const deep=join(root,"deep/a/b/c/d/e/f/g");await mkdir(deep,{recursive:true});
  await writeFile(join(deep,"module.mjs"),"// MODULE_NEEDLE");await writeFile(join(deep,"module.cjs"),"// MODULE_NEEDLE");
  assert.equal((await searchSourcePage(root,join(root,"deep"),"MODULE_NEEDLE")).results.length,2);
  assert.deepEqual((await searchSourcePage(root,join(root,"scoped"),"MODULE_NEEDLE")).results,[]);
  assert.deepEqual(selectSourceBatch(["a","b","c","d","e"],0),["a","b"]);
  assert.deepEqual(selectSourceBatch(["a","b","c","d","e"],1),["c","d"]);
  assert.deepEqual(selectSourceBatch(["a","b","c","d","e"],2),["e","a"]);
  assert.equal(incompleteProbeCoverage({failedProbes:1,unsupportedProbes:0}),"failed");
  assert.equal(incompleteProbeCoverage({failedProbes:0,unsupportedProbes:0}),"failed");
  assert.equal(incompleteProbeCoverage({failedProbes:0,unsupportedProbes:1}),"unsupported");
  assert.equal(incompleteProbeCoverage({failedProbes:1,unsupportedProbes:1}),"failed");
  // Exercise paging through both model protocols, not only the read helper.
  for(const protocol of ["json","native"]) {
    process.env.LOCAL_OLLAMA_TOOL_PROTOCOL=protocol;
    let calls=0;
    server.removeAllListeners("request");
    server.on("request",async(req,res)=>{
      let raw="";for await(const chunk of req)raw+=chunk;
      const request=JSON.parse(raw);calls++;
      if(calls===2)assert.ok(request.messages.at(-1).content.includes("renderer.render(input)"));
      const action={action:calls===1?"read_file":"final",path:"large.js",query:"",answer:"DONE",offset:40000};
      res.end(JSON.stringify({message:protocol==="json"?{role:"assistant",content:JSON.stringify(action)}:
        calls===1?{role:"assistant",content:"",tool_calls:[{function:{name:"read_file",arguments:{path:"large.js",offset:40000}}}]}:{role:"assistant",content:"DONE"}}));
    });
    if(!server.listening)await new Promise<void>(r=>server.listen(0,"127.0.0.1",r));
    const addr=server.address();assert.ok(addr&&typeof addr!=="string");
    process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${addr.port}/api/chat`;
    const actual=new SourceReads();
    assert.equal(await runLocalAudit("Read caller",join(root,protocol+".log"),10000,root,"fixture",undefined,
      {onRead:(p,s)=>actual.add(p,s),validateFinal:()=>actual.sawLine("large.js",text,5001)?null:"Caller not seen"}),"DONE");
    assert.equal(calls,2);
  }
  // EISDIR during checkpoint loading must also clean up timers and controller state.
  await assert.rejects(runLocalAudit("unused",join(root,"error.log"),10000,root,"fixture",undefined,{checkpointPath:root}));
  assert.equal(activeLocalAuditCount(),0);
  console.log("Paginated reads, caller spans, scoped/deep/mjs/cjs searches, repository rotation, failure classification and checkpoint cleanup: PASSED");
} finally {server.closeAllConnections();server.close();await rm(root,{recursive:true,force:true});}
