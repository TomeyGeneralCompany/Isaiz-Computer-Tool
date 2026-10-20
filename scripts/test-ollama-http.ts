/** Owned loopback HTTP server only: model header/body waits use one abort deadline. */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { postOllamaJson } from "../packages/core/src/ollama-http";
let mode="delay";let requests=0;
const timers=new Set<ReturnType<typeof setTimeout>>();
const later=(fn:()=>void)=>{const timer=setTimeout(()=>{timers.delete(timer);fn();},80);timers.add(timer);};
const server=createServer(async(req,res)=>{
  for await(const _ of req) {} requests++;
  if(mode==="stall")return;
  if(mode==="body-stall") {res.writeHead(200);res.write('{"ok":');return;}
  if(mode==="http") {res.writeHead(401);res.end("SECRET_PROVIDER_BODY");return;}
  if(mode==="redirect") {res.writeHead(302,{Location:"http://127.0.0.1:1/never-follow"});res.end();return;}
  if(mode==="large") {res.end(JSON.stringify({data:"x".repeat(1048577)}));return;}
  if(mode==="broken") {res.end("not json SECRET_PROVIDER_BODY");return;}
  later(()=>{if(res.destroyed)return;res.writeHead(200);res.write('{"ok":');later(()=>res.end('true}'));});
});
const oldFetch=globalThis.fetch;
try {
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
  const address=server.address();assert.ok(address && typeof address !== "string");
  const endpoint=`http://127.0.0.1:${address.port}/api/chat`;
  // A poisoned fetch proves these calls cannot inherit its separate header timer.
  globalThis.fetch=(async()=>{throw new Error("fetch headers timeout must not govern Ollama");}) as typeof fetch;
  assert.deepEqual(await postOllamaJson(endpoint,{model:"owned-fixture"},AbortSignal.timeout(2000)),{ok:true});
  for(const stalled of ["stall","body-stall"]){
    mode=stalled;
    await assert.rejects(postOllamaJson(endpoint,{},AbortSignal.timeout(40)),error=>error instanceof Error && error.name==="AbortError");
  }
  for(const [next,pattern] of [["http",/^Ollama HTTP 401$/],["redirect",/^Ollama HTTP 302$/],["large",/exceeds 1 MiB/],["broken",/malformed response/]] as const){
    mode=next;const before=requests;
    await assert.rejects(postOllamaJson(endpoint,{},AbortSignal.timeout(2000)),error=>error instanceof Error && pattern.test(error.message) && !error.message.includes("SECRET_PROVIDER_BODY"));
    assert.equal(requests,before+1,"Redirects/rejected requests must not be retried by the transport");
  }
  mode="delay";
  assert.deepEqual(await postOllamaJson(endpoint,{},AbortSignal.timeout(2000)),{ok:true},"Subsequent requests recover after aborted requests");
  console.log("Ollama HTTP: delayed headers/body, shared abort deadline, bounded response, redaction, no redirects and recovery PASSED");
} finally {
  globalThis.fetch=oldFetch;
  for(const timer of timers)clearTimeout(timer);
  server.closeAllConnections();server.close();
}
