import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runLocalAudit } from "../packages/security-solver/src/local-ollama-runner";
import { decodeAuditAction } from "../packages/security-solver/src/local-audit-protocol";

const dir = await mkdtemp(join(tmpdir(), "autohack-mock-"));
const savedProtocol = process.env.LOCAL_OLLAMA_TOOL_PROTOCOL;
const savedUrl = process.env.AUTOHACK_OLLAMA_URL;
let calls = 0;
let expectedCheckpoint = false;
let sawCheckpoint = false;
let stall = false;
let forbidden = false;
let truncated = false;
let repair = false;
const limits = {maxTurns:6,numPredict:128,numCtx:2048,numThreads:4};
const server = createServer(async (req, res) => {
  let body = "";
  for await (const chunk of req) body += chunk.toString();
  const data = JSON.parse(body);
  calls++;
  if (expectedCheckpoint && data.messages.some((m:any)=>m.content?.includes("Previous inspection notes"))) sawCheckpoint=true;
  if (stall) return;
  assert.equal(data.options.num_ctx,limits.numCtx);
  assert.equal(data.options.num_thread,4);
  assert.equal(data.options.num_predict, truncated && calls > 1 ? limits.numPredict * 2 : limits.numPredict);
  const structured = process.env.LOCAL_OLLAMA_TOOL_PROTOCOL !== "native";
  if (structured) {
    assert.equal(data.tools,undefined,"Structured protocol must bypass native tool rendering");
    assert.ok(data.format.properties.action.enum.includes("read_file"));
  } else {
    assert.ok(data.tools.some((x: any)=>x.function.name==="read_file"));
    assert.equal(data.format,undefined);
  }
  res.setHeader("content-type", "application/json");
  if (truncated && calls === 1) {
    res.end(JSON.stringify({done_reason:"length",message:{role:"assistant",content:'{"action":"read_file"'}}));
    return;
  }
  if (calls === (truncated ? 2 : 1) || (repair && calls === 3)) {
    const path = forbidden ? "../outside-secret.ts" : "sample.ts";
    res.end(JSON.stringify({message:{role:"assistant",content:structured ? JSON.stringify({action:"read_file",path,query:"",answer:""}) : "",
      ...(structured ? {} : {tool_calls:[{function:{name:"read_file",arguments:{path}}}]})}}));
  } else {
    const last = data.messages.at(-1);
    if (!forbidden && !(repair && calls === 3)) {
      assert.equal(last.role,structured ? "user" : "tool");
      assert.ok(last.content.includes("return a + b"));
    }
    res.end(JSON.stringify({message:{role:"assistant",content:structured
      ? JSON.stringify({action:"final",path:"",query:"",answer:repair && calls===2 ? "WRONG" : "FUNCTION_FOUND"}) : "FUNCTION_FOUND"}}));
  }
});
try {
  await writeFile(join(dir,"sample.ts"),"export function add(a: number,b: number) { return a + b; }");
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  process.env.AUTOHACK_OLLAMA_URL = `http://127.0.0.1:${address.port}/api/chat`;
  for (const protocol of ["json","native"]) {
    calls = 0;
    process.env.LOCAL_OLLAMA_TOOL_PROTOCOL = protocol;
    const log = join(dir,protocol+".log");
    assert.equal(await runLocalAudit("Inspect sample.ts",log,10000,dir,"mock",undefined,limits),"FUNCTION_FOUND");
    assert.equal(calls,2);
    const transcript = await readFile(log,"utf8");
    assert.match(transcript,/\[READ_OK\] sample.ts/);
    assert.match(transcript,/response received in/);
  }
  process.env.LOCAL_OLLAMA_TOOL_PROTOCOL = "json";
  const checkpointPath=join(dir,"checkpoint.json");
  calls=0;
  await runLocalAudit("Inspect sample.ts",join(dir,"checkpoint.log"),10000,dir,"mock",undefined,{...limits,checkpointPath});
  assert.match(await readFile(checkpointPath,"utf8"),/sample.ts/);
  expectedCheckpoint=true;calls=0;
  await runLocalAudit("Inspect sample.ts",join(dir,"resume.log"),10000,dir,"mock",undefined,{...limits,checkpointPath});
  assert.ok(sawCheckpoint,"A later session must receive prior inspection notes");
  expectedCheckpoint=false;
  calls = 0; truncated = true;
  assert.equal(await runLocalAudit("Inspect sample.ts",join(dir,"truncated.log"),10000,dir,"mock",undefined,limits),"FUNCTION_FOUND");
  assert.equal(calls,3);
  calls=0;limits.numPredict=2048;limits.numCtx=8192;
  assert.equal(await runLocalAudit("Inspect sample.ts",join(dir,"large-truncated.log"),10000,dir,"mock",undefined,limits),"FUNCTION_FOUND");
  assert.equal(calls,3,"Truncated 2048-token JSON retries with 4096 output tokens");
  limits.numPredict=128;limits.numCtx=2048;
  truncated = false; repair = true; calls = 0;
  assert.equal(await runLocalAudit("Inspect sample.ts",join(dir,"repair.log"),10000,dir,"mock",undefined,
    {...limits,validateFinal:answer=>answer==="FUNCTION_FOUND" ? null : "The value is incorrect; read sample.ts again."}),"FUNCTION_FOUND");
  assert.equal(calls,4);
  assert.match(await readFile(join(dir,"repair.log"),"utf8"),/FINAL_REJECTED/);
  repair = false; forbidden = true; calls = 0;
  await assert.rejects(runLocalAudit("Inspect sample.ts",join(dir,"denied.log"),10000,dir,"mock",undefined,limits),/inspection limit|repeated missing source path/);
  assert.ok(!(await readFile(join(dir,"denied.log"),"utf8")).includes("[READ_OK]"));
  assert.throws(()=>decodeAuditAction(JSON.stringify({action:"exec",path:"",query:"",answer:""})),/Invalid read-only/);
  assert.throws(()=>decodeAuditAction("I intend to call read_file"));
  forbidden = false; stall = true;
  await assert.rejects(runLocalAudit("Inspect sample.ts",join(dir,"timeout.log"),50,dir,"mock",undefined,limits),/Ollama audit timed out/);
  console.log("JSON/native tool loops, real read requirement, path denial, truncated JSON recovery and timeout passed");
} finally {
  server.closeAllConnections(); server.close();
  if (savedUrl === undefined) delete process.env.AUTOHACK_OLLAMA_URL; else process.env.AUTOHACK_OLLAMA_URL = savedUrl;
  if (savedProtocol === undefined) delete process.env.LOCAL_OLLAMA_TOOL_PROTOCOL; else process.env.LOCAL_OLLAMA_TOOL_PROTOCOL = savedProtocol;
  await rm(dir,{recursive:true,force:true});
}
