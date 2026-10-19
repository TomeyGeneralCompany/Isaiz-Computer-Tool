import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assessmentFixture, checkAssessment } from "./assessment-fixture";

const root = await mkdtemp(join(tmpdir(),"autohack-mock-assessment-"));
process.env.PROJECT_ROOT = root;
process.env.GITHUB_TOKEN = "offline-assessment-fixture";
process.env.CLAUDE_BACKEND = "cli";
process.env.OLLAMA_DISCOVERY_DIRECT = "true";
process.env.OLLAMA_MODEL = "mock-assessment";
let mode = "normal";
let calls = 0;
const requests: any[] = [];
const answer = {
  rubric:{sourceCodeQuality:3,webApiSurface:0,techStackMatch:3,scopeBreadth:0,rewardEfficiency:2},
  targetCount:1,topTargets:[{asset:"https://github.com/example/owned-assessment-fixture",type:"SOURCE_CODE",reasoning:"Review TypeScript source",strategy:"code_review"}],
  techStack:["TypeScript"],attackSurface:"Owned source fixture",recommendedApproach:"code_review",
};
const server = createServer(async (req,res) => {
  let raw = "";
  for await (const part of req) raw += part.toString();
  const data = JSON.parse(raw);
  calls++;
  requests.push(data);
  assert.equal(data.stream,false);
  assert.equal(data.model,"mock-assessment");
  assert.equal(data.options.num_ctx,Math.max(4096,data.options.num_predict + 2048));
  if (mode === "stall") return;
  if (mode === "http") {res.writeHead(401);res.end("SECRET_PROVIDER_BODY");return;}
  if (mode === "truncated" || mode === "recover" && calls === 1) {
    res.end(JSON.stringify({done:true,done_reason:"length",message:{content:'{"rubric":{"sourceCodeQuality":2,"topTarget'}}));
    return;
  }
  const scopedAnswer = mode === "invented" ? {...answer,topTargets:[{...answer.topTargets[0],asset:"https://not-in-scope.example"}]} :
    mode === "wrongType" ? {...answer,topTargets:[{...answer.topTargets[0],type:"URL"}]} :
    mode === "excessCount" ? {...answer,targetCount:5} :
    mode === "duplicates" ? {...answer,topTargets:[answer.topTargets[0],answer.topTargets[0]]} :
    mode === "noTargets" ? {...answer,topTargets:[]} : answer;
  const content = mode === "plain" ? "READY" : mode === "invalid" ? '{"rubric":' :
    JSON.stringify(mode === "array" ? [] : mode === "missing" ? {rubric:{}} : mode === "nested" ?
      {...answer,rubric:{...answer.rubric,targetCount:1}} : scopedAnswer);
  res.end(JSON.stringify({done:mode !== "incomplete",done_reason:"stop",message:{content}}));
});
try {
  await new Promise<void>(resolve => server.listen(0,"127.0.0.1",resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  process.env.AUTOHACK_OLLAMA_URL = `http://127.0.0.1:${address.port}/api/chat`;
  const { assessProgram } = await import("../packages/security-analyzer/src/assessor");
  const { runClaude, runClaudeStructured } = await import("../packages/core/src/claude");
  mode = "recover";
  checkAssessment(await assessProgram(assessmentFixture));
  assert.equal(calls,2);
  assert.deepEqual(requests.map(r => r.options.num_predict),[1024,2048]);
  assert.equal(requests[0].format.properties.topTargets.maxItems,1);
  assert.deepEqual(requests[0].format.properties.targetCount.enum,[1]);
  assert.deepEqual(requests[0].format.properties.topTargets.items.properties.asset.enum,[answer.topTargets[0].asset]);
  assert.deepEqual(requests[0].format.properties.topTargets.items.properties.type.enum,["SOURCE_CODE"]);
  assert.equal(requests[0].format.properties.rubric.additionalProperties,false);
  assert.ok(requests[0].format.required.includes("topTargets"));
  for (const [next,pattern] of [
    ["truncated",/output token budget/], ["invalid",/invalid JSON/],
    ["array",/JSON object/], ["missing",/required fields/],
    ["nested",/required schema/], ["incomplete",/response incomplete/],
    ["http",/HTTP 401/], ["invented",/supplied scope/], ["wrongType",/supplied scope/],
    ["excessCount",/supplied scope/], ["duplicates",/supplied scope/], ["noTargets",/supplied scope/],
  ] as const) {
    mode = next; calls = 0;
    await assert.rejects(assessProgram(assessmentFixture),pattern);
    assert.equal(calls,next === "truncated" ? 2 : 1);
  }
  mode = "plain";
  assert.equal(await runClaude("Reply READY",{maxTokens:37}),"READY");
  assert.equal(requests.at(-1).options.num_predict,37);
  assert.equal(requests.at(-1).format,undefined);
  assert.equal(await runClaude("Reply READY",{maxTokens:8192}),"READY");
  assert.equal(requests.at(-1).options.num_predict,8192);
  mode = "stall";
  const opts = {toolName:"fixture",fallbackKey:"rubric",inputSchema:{type:"object",required:["rubric"]},timeoutMs:50};
  await assert.rejects(runClaudeStructured("fixture",opts),/exceeded 50ms/);
  // Exercise the production assessor, not only a direct adapter call: the old
  // hardcoded 180s option prevented this configured deadline from taking effect.
  const priorTimeout = process.env.OLLAMA_ASSESSMENT_TIMEOUT_MS;
  try {
    process.env.OLLAMA_ASSESSMENT_TIMEOUT_MS = "50";
    await assert.rejects(assessProgram(assessmentFixture), /exceeded 50ms/);
    process.env.OLLAMA_ASSESSMENT_TIMEOUT_MS = "-1";
    await assert.rejects(assessProgram(assessmentFixture), /Invalid Ollama assessment timeout/);
  } finally {
    if (priorTimeout === undefined) delete process.env.OLLAMA_ASSESSMENT_TIMEOUT_MS;
    else process.env.OLLAMA_ASSESSMENT_TIMEOUT_MS = priorTimeout;
  }
  mode = "normal";
  checkAssessment(await assessProgram(assessmentFixture)); // Failed calls must release the queue.
  await Promise.all([assessProgram(assessmentFixture),assessProgram(assessmentFixture)]);
  const before = calls;
  const empty = await assessProgram({...assessmentFixture,scopeSummary:"[]"});
  assert.equal(empty.targetCount,0);
  assert.deepEqual(empty.topTargets,[]);
  assert.equal(calls,before,"Empty scopes must not trigger inference");
  console.log("Production assessment adapter: schema, token budget, truncation recovery, nested validation, deadline, HTTP errors and queue recovery PASSED");
} finally {
  server.closeAllConnections(); server.close();
  await rm(root,{recursive:true,force:true});
}
