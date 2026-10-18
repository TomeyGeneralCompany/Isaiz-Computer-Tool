/**
 * Operator-confirmed reconciliation of actual bounty receipts.
 * Requires a corresponding rewarded finding in the local database.
 * Does not query or submit to any live bounty program.
 *
 * Example:
 * npx tsx scripts/record-verified-payout.ts --finding-id FINDING_ID \
 *   --provider hackerone --transaction PAYOUT_ID --cents 15000 \
 *   --paid-at 2026-10-18T10:00:00.000Z --evidence RECEIPT_REFERENCE
 */
import "dotenv/config";
import { getDb, schema } from "@bounty/core";
import { eq } from "drizzle-orm";
import { recordVerifiedPayout } from "../packages/core/src/earnings-ledger";

const args: Record<string, string> = {};
for (let i = 2; i < process.argv.length; i += 2) {
  if (!process.argv[i]?.startsWith("--") || !process.argv[i+1]) {
    throw new Error("Arguments must be --key value pairs");
  }
  args[process.argv[i].slice(2)] = process.argv[i+1];
}
const id = args["finding-id"];
if (!id) throw new Error("A finding-id is required");
const finding = getDb().select().from(schema.securityFindings)
  .where(eq(schema.securityFindings.id, id)).get();
if (!finding || finding.status !== "rewarded" || !finding.programId)
  throw new Error("Only existing rewarded findings linked to a program can be reconciled");
const program = getDb().select().from(schema.securityPrograms)
  .where(eq(schema.securityPrograms.id, finding.programId)).get();
if (!program || program.provider !== args.provider)
  throw new Error("Payout provider does not match finding program");
const payout = recordVerifiedPayout({
  findingId: id,
  provider: args.provider,
  providerTransactionId: args.transaction,
  amountCents: Number(args.cents),
  paidAt: args["paid-at"],
  evidenceRef: args.evidence,
});
console.log(JSON.stringify({ transaction: payout.providerTransactionId,
  findingId: payout.findingId, verifiedPaidCents: payout.amountCents,
  paidAt: payout.paidAt, verificationMethod: payout.verificationMethod }, null, 2));
