/**
 * Exercises the REAL HackerOne report serializer and the durable submission
 * outbox against an intercepted in-process mock; NO network requests are sent.
 */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { submitOnce, readSubmissionOutbox } from "../packages/core/src/submission-outbox";

process.env.GITHUB_TOKEN = "ci-fixture-placeholder";
process.env.HACKERONE_USERNAME = "fixture-only";
process.env.HACKERONE_API_TOKEN = "fixture-only";
const { submitReport } = await import("../packages/security-discovery/src/hackerone-client");

const dir = mkdtempSync(join(tmpdir(), "autohack-mock-provider-"));
const path = join(dir, "outbox.json");
const original = globalThis.fetch;
let requests = 0;
let reject = false;
const payload = {
  title: "Reproducible source issue in authorized fixture",
  vulnerability_information: "Local fixture steps and recorded evidence only",
  impact: "Local fixture impact only",
  severity_rating: "medium" as const,
};
globalThis.fetch = async (url, init) => {
  // Any unexpected request MUST fail without hitting the network.
  assert.equal(String(url), "https://api.hackerone.com/v1/hackers/reports");
  requests++;
  assert.equal(init?.method, "POST");
  assert.equal(init?.redirect, "error");
  assert.ok(init?.signal, "Provider requests must have a deadline");
  const json = JSON.parse(String(init?.body));
  assert.equal(json.data.type, "report");
  assert.equal(json.data.attributes.team_handle, "offline-fixture");
  assert.equal(json.data.attributes.title, payload.title);
  assert.equal(json.data.attributes.vulnerability_information, payload.vulnerability_information);
  return new Response(JSON.stringify(reject
    ? {errors:[{detail:"Mock permission denial"}]}
    : {data:{id:"fixture-report-42",attributes:{url:"https://hackerone.com/reports/fixture-report-42"}}}),
    {status:reject ? 422 : 201, headers:{"Content-Type":"application/json"}});
};
try {
  const result = await submitOnce("finding-one","offline-fixture",payload,
    () => submitReport({teamHandle:"offline-fixture",payload}),path);
  assert.equal(result.reportId,"fixture-report-42");
  assert.equal(requests,1);
  assert.equal(readSubmissionOutbox(path)["finding-one"].state,"confirmed");
  await assert.rejects(() => submitOnce("finding-one","offline-fixture",payload,
    () => submitReport({teamHandle:"offline-fixture",payload}),path),/already attempted/);
  assert.equal(requests,1,"Duplicate dispatch must not happen");
  reject = true;
  await assert.rejects(() => submitOnce("finding-two","offline-fixture",payload,
    () => submitReport({teamHandle:"offline-fixture",payload}),path),/HackerOne API 422/);
  assert.equal(requests,2);
  assert.equal(readSubmissionOutbox(path)["finding-two"].state,"uncertain");
  await assert.rejects(() => submitOnce("finding-two","offline-fixture",payload,
    () => submitReport({teamHandle:"offline-fixture",payload}),path),/already attempted/);
  assert.equal(requests,2);
  console.log("Mocked real serializer, rejection, idempotency, restart outbox passed");
} finally {
  globalThis.fetch = original;
  rmSync(dir,{recursive:true,force:true});
}
