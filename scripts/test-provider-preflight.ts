import assert from "node:assert/strict";
import { checkHackerOneAccess } from "../packages/security-discovery/src/provider-preflight";
const saved = globalThis.fetch;
let calls = 0;
try {
  globalThis.fetch = async(url, init) => {
    calls++;
    assert.equal(String(url), "https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=1");
    assert.equal(init?.method, "GET");
    assert.equal(init?.redirect, "error");
    assert.ok(init?.signal);
    return new Response("private account body must not leak", {status:401});
  };
  assert.equal((await checkHackerOneAccess("", "")).passed, false);
  assert.equal(calls, 0);
  const denied = await checkHackerOneAccess("test-user", "secret-token");
  assert.equal(denied.passed, false);
  assert.match(denied.detail, /401/);
  assert.ok(!JSON.stringify(denied).includes("secret-token"));
  assert.ok(!JSON.stringify(denied).includes("private account"));
  globalThis.fetch = async() => new Response("", {status:200});
  assert.equal((await checkHackerOneAccess("user", "token")).passed, true);
  globalThis.fetch = async() => {throw new Error("secret-token");};
  const failed = await checkHackerOneAccess("user", "secret-token");
  assert.equal(failed.passed, false);
  assert.ok(!failed.detail.includes("secret-token"));
  console.log("Read-only provider preflight: success, rejection, missing credentials and redaction passed");
} finally {globalThis.fetch = saved;}
