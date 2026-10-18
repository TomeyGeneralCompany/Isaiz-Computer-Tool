/**
 * Persistent submission outbox: at-most-once dispatch attempts per finding.
 * "uncertain" means a network timeout might have created a report; never
 * automatically retry until the provider confirms the result.
 */
import { createHash } from "node:crypto";
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export type SubmissionState = "started" | "confirmed" | "uncertain";
export interface SubmissionRecord {
  findingId: string;
  programHandle: string;
  payloadDigest: string;
  state: SubmissionState;
  startedAt: string;
  updatedAt: string;
  reportId?: string;
  reportUrl?: string;
  failure?: string;
}
type Store = Record<string, SubmissionRecord>;

export function submissionOutboxFile(): string {
  return join(process.env.PROJECT_ROOT || process.cwd(), "data", "submission-outbox.json");
}

function load(path: string): Store {
  if (!existsSync(path)) return {};
  const data: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!data || Array.isArray(data) || typeof data !== "object")
    throw new Error("Submission outbox corrupt: expected object");
  for (const [id, item] of Object.entries(data)) {
    const r = item as SubmissionRecord;
    if (!r || r.findingId !== id || !["started", "confirmed", "uncertain"].includes(r.state)
      || typeof r.payloadDigest !== "string" || typeof r.programHandle !== "string")
      throw new Error("Submission outbox corrupt: invalid entry");
  }
  return data as Store;
}
export function readSubmissionOutbox(path = submissionOutboxFile()): Store {
  return load(path);
}

function mutate<T>(path: string, action: (entries: Store) => T): T {
  mkdirSync(dirname(path), { recursive: true });
  const lock = path + ".lock";
  const fd = openSync(lock, "wx", 0o600);
  try {
    const entries = load(path);
    const result = action(entries);
    const temp = path + "." + process.pid + ".tmp";
    try {
      writeFileSync(temp, JSON.stringify(entries, null, 2) + "\n", { mode: 0o600 });
      renameSync(temp, path);
    } finally {
      try { unlinkSync(temp); } catch {}
    }
    return result;
  } finally {
    closeSync(fd);
    unlinkSync(lock);
  }
}

export function claimSubmission(
  findingId: string, programHandle: string, payload: unknown,
  path = submissionOutboxFile(), now = new Date(),
): SubmissionRecord {
  if (!/^[a-zA-Z0-9_-]{1,100}$/.test(findingId)
    || !/^[a-zA-Z0-9_-]{1,100}$/.test(programHandle))
    throw new Error("Invalid submission identifiers");
  const digest = createHash("sha256").update(JSON.stringify(payload)).digest("hex");
  return mutate(path, entries => {
    const existing = entries[findingId];
    if (existing) throw new Error("Submission already attempted; reconcile with provider before retrying");
    const stamp = now.toISOString();
    const record: SubmissionRecord = { findingId, programHandle,
      payloadDigest: digest, state: "started", startedAt: stamp, updatedAt: stamp };
    entries[findingId] = record;
    return record;
  });
}

export function finishSubmission(
  findingId: string, result: { reportId: string; reportUrl: string },
  path = submissionOutboxFile(), now = new Date(),
): SubmissionRecord {
  if (!result.reportId || !result.reportUrl.startsWith("https://hackerone.com/reports/"))
    throw new Error("Invalid confirmed submission receipt");
  return mutate(path, entries => {
    const entry = entries[findingId];
    if (!entry || entry.state !== "started") throw new Error("Unknown or non-pending submission");
    Object.assign(entry, { state: "confirmed", reportId: result.reportId,
      reportUrl: result.reportUrl, updatedAt: now.toISOString() });
    return entry;
  });
}

export function markSubmissionUncertain(
  findingId: string, reason: string,
  path = submissionOutboxFile(), now = new Date(),
): SubmissionRecord {
  return mutate(path, entries => {
    const entry = entries[findingId];
    if (!entry || entry.state !== "started") throw new Error("Unknown or non-pending submission");
    Object.assign(entry, { state: "uncertain", failure: reason.slice(0, 500),
      updatedAt: now.toISOString() });
    return entry;
  });
}
