/**
 * Verified payout ledger, independent of finding status. "rewarded" is not proof
 * that cash was received. A human must reconcile a real provider payout record.
 */
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export interface VerifiedPayout {
  findingId: string;
  provider: string;
  providerTransactionId: string;
  amountCents: number;
  currency: "USD";
  paidAt: string; // ISO-8601 UTC, not report updatedAt
  evidenceRef: string; // actual provider receipt or bank reconciliation reference
  verifiedAt: string;
  verificationMethod: "operator-confirmed";
}

export function ledgerFile(): string {
  return join(process.env.PROJECT_ROOT || process.cwd(), "data", "verified-payouts.json");
}

function isValidTime(value: string): boolean {
  return /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(value)
    && Number.isFinite(Date.parse(value))
    && new Date(value).toISOString() === new Date(Date.parse(value)).toISOString();
}

export function validatePayout(p: VerifiedPayout): void {
  if (!p || !["operator-confirmed"].includes(p.verificationMethod)) throw new Error("Payout requires operator confirmation");
  for (const field of [p.findingId, p.provider, p.providerTransactionId, p.evidenceRef]) {
    if (typeof field !== "string" || !field.trim() || field.length > 500 || /[\r\n]/.test(field))
      throw new Error("Payout identification and evidence fields must be nonempty and single-line");
  }
  if (!Number.isSafeInteger(p.amountCents) || p.amountCents <= 0 || p.currency !== "USD")
    throw new Error("Only positive, integer USD-cent payments are accepted");
  if (!isValidTime(p.paidAt) || !isValidTime(p.verifiedAt))
    throw new Error("Payout timestamps must be valid ISO-8601 UTC dates");
  if (Date.parse(p.paidAt) > Date.parse(p.verifiedAt))
    throw new Error("Payment cannot post after reconciliation");
}

export function readVerifiedPayouts(path = ledgerFile()): VerifiedPayout[] {
  if (!existsSync(path)) return [];
  const data: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(data)) throw new Error("Invalid payout ledger: expected an array");
  const seen = new Set<string>();
  for (const item of data) {
    validatePayout(item as VerifiedPayout);
    const payout = item as VerifiedPayout;
    const key = payout.provider + "\u0000" + payout.providerTransactionId;
    if (seen.has(key)) throw new Error("Corrupt payout ledger: duplicate provider transaction");
    seen.add(key);
  }
  return data as VerifiedPayout[];
}

export function recordVerifiedPayout(
  input: Omit<VerifiedPayout, "verifiedAt" | "verificationMethod" | "currency">,
  path = ledgerFile(),
  now = new Date(),
): VerifiedPayout {
  const record: VerifiedPayout = {
    ...input,
    currency: "USD",
    verifiedAt: now.toISOString(),
    verificationMethod: "operator-confirmed",
  };
  validatePayout(record);
  mkdirSync(dirname(path), { recursive: true });
  // A separate lock prevents simultaneous dashboard/CLI writes losing an entry.
  const lock = path + ".lock";
  const fd = openSync(lock, "wx", 0o600);
  try {
    const entries = readVerifiedPayouts(path);
    const duplicate = entries.find(p => p.provider === record.provider
      && p.providerTransactionId === record.providerTransactionId);
    if (duplicate) {
      if (duplicate.findingId !== record.findingId || duplicate.amountCents !== record.amountCents
        || duplicate.paidAt !== record.paidAt) throw new Error("Conflicting duplicate payout transaction");
      return duplicate; // idempotent
    }
    const temp = path + "." + process.pid + ".tmp";
    try {
      writeFileSync(temp, JSON.stringify([...entries, record], null, 2) + "\n", { mode: 0o600 });
      renameSync(temp, path);
    } finally {
      try { unlinkSync(temp); } catch {}
    }
    return record;
  } finally {
    closeSync(fd);
    unlinkSync(lock);
  }
}

export function earningsProgress(payouts: VerifiedPayout[], monthlyTargetCents: number, now = new Date()) {
  if (!Number.isSafeInteger(monthlyTargetCents) || monthlyTargetCents < 0)
    throw new Error("Invalid monthly earnings target");
  const month = now.toISOString().slice(0, 7);
  const thisMonth = payouts.filter(p => {
    validatePayout(p);
    return p.paidAt.slice(0, 7) === month;
  });
  const verifiedPaidCents = thisMonth.reduce((total, p) => total + p.amountCents, 0);
  if (!Number.isSafeInteger(verifiedPaidCents)) throw new Error("Payout total overflow");
  return {
    month,
    monthlyTargetCents,
    verifiedPaidCents,
    remainingCents: Math.max(0, monthlyTargetCents - verifiedPaidCents),
    progressPercent: monthlyTargetCents === 0 ? 100
      : Math.min(100, Math.round(verifiedPaidCents * 10000 / monthlyTargetCents) / 100),
    verifiedPayoutCount: thisMonth.length,
    allTimeVerifiedCents: payouts.reduce((n, p) => n + p.amountCents, 0),
  };
}
