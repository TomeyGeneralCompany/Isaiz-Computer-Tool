import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { claimSubmission, finishSubmission, markSubmissionUncertain, readSubmissionOutbox } from "../packages/core/src/submission-outbox";
const dir = mkdtempSync(join(tmpdir(), "autohack-submission-"));
const path = join(dir, "outbox.json");
try {
  const payload = { title: "Owned fixture proof", vulnerability_information:"Locally reproduced", severity_rating:"medium" };
  assert.deepEqual(readSubmissionOutbox(path), {});
  const claim = claimSubmission("sf-123","fixture",payload,path);
  assert.equal(claim.state,"started");
  assert.equal(claim.payloadDigest.length,64);
  assert.throws(() => claimSubmission("sf-123","fixture",payload,path),/already attempted/);
  assert.throws(() => claimSubmission("sf-123","another",payload,path),/already attempted/);
  assert.equal(readSubmissionOutbox(path)["sf-123"].state,"started");
  const result = finishSubmission("sf-123",{reportId:"42",reportUrl:"https://hackerone.com/reports/42"},path);
  assert.equal(result.state,"confirmed");
  assert.equal(result.reportId,"42");
  assert.throws(() => finishSubmission("sf-123",{reportId:"42",reportUrl:"https://hackerone.com/reports/42"},path),/non-pending/);
  const second = claimSubmission("sf-456","fixture",payload,path);
  assert.equal(second.state,"started");
  assert.equal(markSubmissionUncertain("sf-456","HTTP 502 / unknown provider status",path).state,"uncertain");
  assert.throws(() => claimSubmission("sf-456","fixture",payload,path),/already attempted/);
  assert.equal(readSubmissionOutbox(path)["sf-456"].failure,"HTTP 502 / unknown provider status");
  writeFileSync(path,JSON.stringify({broken:{state:"pretend-success"}}));
  assert.throws(()=>readSubmissionOutbox(path),/corrupt/);
  console.log("Mock submission outbox and restart/idempotency checks passed");
} finally { rmSync(dir,{recursive:true,force:true}); }
