import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { earningsProgress, readVerifiedPayouts, recordVerifiedPayout } from "../packages/core/src/earnings-ledger";

const directory = mkdtempSync(join(tmpdir(), "autohack-ledger-"));
const path = join(directory, "payouts.json");
try {
  assert.deepEqual(readVerifiedPayouts(path), []);
  const input = {
    findingId: "f-1", provider: "hackerone", providerTransactionId: "payment-abc",
    amountCents: 125000, paidAt: "2026-10-03T08:00:00.000Z",
    evidenceRef: "provider-receipt-abc",
  };
  const first = recordVerifiedPayout(input, path, new Date("2026-10-04T00:00:00Z"));
  assert.equal(first.amountCents, 125000);
  assert.equal(recordVerifiedPayout(input, path, new Date("2026-10-05T00:00:00Z")).verifiedAt, first.verifiedAt);
  assert.equal(readVerifiedPayouts(path).length, 1);
  assert.throws(() => recordVerifiedPayout({ ...input, amountCents: 500 }, path, new Date("2026-10-04T00:00:00Z")), /Conflicting/);
  assert.throws(() => recordVerifiedPayout({ ...input, providerTransactionId: "x", evidenceRef: "" }, path), /evidence/);
  assert.throws(() => recordVerifiedPayout({ ...input, providerTransactionId: "x", amountCents: -1 }, path), /positive/);
  assert.throws(() => recordVerifiedPayout({ ...input, providerTransactionId: "x", paidAt: "tomorrow" }, path), /ISO/);
  assert.throws(() => recordVerifiedPayout({ ...input, providerTransactionId: "x", paidAt: "2027-01-01T00:00:00.000Z" }, path, new Date("2026-10-04T00:00:00Z")), /after reconciliation/);
  recordVerifiedPayout({ ...input, providerTransactionId: "payment-old", paidAt: "2026-09-30T23:00:00.000Z", amountCents: 60000 }, path, new Date("2026-10-04T00:00:00Z"));
  recordVerifiedPayout({ ...input, providerTransactionId: "payment-new", paidAt: "2026-10-12T23:00:00.000Z", amountCents: 275000 }, path, new Date("2026-10-13T00:00:00Z"));
  const progress = earningsProgress(readVerifiedPayouts(path), 400000, new Date("2026-10-18T00:00:00Z"));
  assert.equal(progress.month, "2026-10");
  assert.equal(progress.verifiedPaidCents, 400000);
  assert.equal(progress.remainingCents, 0);
  assert.equal(progress.progressPercent, 100);
  assert.equal(progress.verifiedPayoutCount, 2);
  assert.equal(progress.allTimeVerifiedCents, 460000);
  assert.equal(earningsProgress([], 400000).verifiedPaidCents, 0);
  assert.equal(earningsProgress([], 0).progressPercent, 100);
  assert.throws(() => earningsProgress([], -100), /Invalid/);
  writeFileSync(path, JSON.stringify([first, first]));
  assert.throws(() => readVerifiedPayouts(path), /duplicate/);
  writeFileSync(path, "{invalid");
  assert.throws(() => readVerifiedPayouts(path), /Unexpected|property|JSON/);
  console.log("Verified payout ledger: 17 assertions passed");
} finally {
  rmSync(directory, { recursive: true, force: true });
}
