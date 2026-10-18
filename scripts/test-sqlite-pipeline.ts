/**
 * Actual better-sqlite3 + Drizzle + dashboard tRPC integration, using
 * a TEMPORARY, intentionally fictitious database and payout ledger.
 * Never accesses real programs, credentials, or user payout records.
 *
 * CI must first: GITHUB_TOKEN=fixture DB_PATH=<temp.db> npm run db:push
 */
import assert from "node:assert/strict";
import { join, resolve } from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

if (!process.env.CI_SQLITE_INTEGRATION || !process.env.DB_PATH)
  throw new Error("CI_SQLITE_INTEGRATION=1 and an isolated DB_PATH are required");
const root = mkdtempSync(join(tmpdir(), "autohack-native-pipeline-"));
process.env.PROJECT_ROOT = root;
process.env.GITHUB_TOKEN = "offline-ci-dummy";
try {
  const { getDb, schema } = await import("../packages/core/src/db/index");
  const { recordVerifiedPayout } = await import("../packages/core/src/earnings-ledger");
  const { appRouter } = await import("../packages/dashboard/src/server/router");
  const db = getDb();
  const now = new Date("2026-10-18T00:00:00.000Z");
  db.insert(schema.securityPrograms).values({
    id: "h1-offline-fixture", provider: "hackerone",
    providerProgramId: "offline-fixture", name: "Offline fixture (not a real program)",
    scopeSummary: JSON.stringify({scopes:[{assetType:"SOURCE_CODE",
      assetIdentifier:"https://github.com/offline-fixture/sample",eligibleForBounty:true}]}),
    status:"active",rewardMaxCents:500000,
    discoveredAt:now,updatedAt:now,
  }).run();
  db.insert(schema.securityFindings).values([
    {id:"fixture-pending",programId:"h1-offline-fixture",title:"Pending synthetic fixture",
      targetAsset:"https://github.com/offline-fixture/sample",status:"submitted",
      discoveredAt:now,updatedAt:now},
    {id:"fixture-rewarded",programId:"h1-offline-fixture",title:"Paid synthetic fixture",
      targetAsset:"https://github.com/offline-fixture/sample",status:"rewarded",
      rewardedCents:999999,discoveredAt:now,updatedAt:now},
    {id:"fixture-ready",programId:"h1-offline-fixture",title:"Ready synthetic fixture",
      targetAsset:"https://github.com/offline-fixture/sample",status:"report_ready",
      discoveredAt:now,updatedAt:now},
  ]).run();
  const caller = appRouter.createCaller({});
  const before = await caller.securityEarnings();
  assert.equal(before.verifiedPaidCents,0,"Rewarded status MUST NOT imply cash received");
  assert.equal(before.pendingReports,1);
  assert.equal(before.awaitingSubmission,1);
  assert.equal(before.monthlyTargetCents,400000);
  const receipt = recordVerifiedPayout({
    findingId:"fixture-rewarded",provider:"hackerone",
    providerTransactionId:"CI-FICTIONAL-NEVER-REAL",amountCents:125000,
    paidAt:"2026-10-18T05:00:00.000Z",evidenceRef:"synthetic-receipt-only",
  }, join(root,"data","verified-payouts.json"),new Date("2026-10-19T00:00:00.000Z"));
  assert.equal(receipt.amountCents,125000);
  const after = await caller.securityEarnings();
  // The query uses actual CURRENT month, not the fixed fixture month.
  const expected = new Date().toISOString().startsWith("2026-10") ? 125000 : 0;
  assert.equal(after.verifiedPaidCents,expected);
  assert.equal(after.pendingReports,1);
  assert.equal(after.awaitingSubmission,1);
  const stats = await caller.securityStats();
  assert.equal(stats.totalPrograms,1);
  assert.equal(stats.totalFindings,3);
  assert.equal(stats.totalRewardedCents,999999,
    "Legacy awarded field remains separate from actual paid receipts");
  const found = await caller.securityFindings({statuses:["submitted"]});
  assert.equal(found.length,1);
  assert.equal(found[0].id,"fixture-pending");
  console.log("Native SQLite + Drizzle + dashboard tRPC + separate payouts: PASSED");
} finally {
  rmSync(root,{recursive:true,force:true});
}
