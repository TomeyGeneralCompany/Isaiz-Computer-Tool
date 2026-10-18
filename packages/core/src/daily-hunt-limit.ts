/**
 * Crash-consistent, fail-closed daily dispatch quota.
 * Claim BEFORE starting a hunt. Failed/crashed starts still consume one slot.
 * UTC days prevent DST ambiguity. An existing lock is not silently ignored.
 */
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export function dailyQuotaFile(): string {
  return join(process.env.PROJECT_ROOT || process.cwd(), "data", "hunt-daily-quota.json");
}
export interface DailyQuotaState { day: string; dispatched: number }

export function readDailyQuota(path = dailyQuotaFile()): DailyQuotaState | null {
  if (!existsSync(path)) return null;
  const state: DailyQuotaState = JSON.parse(readFileSync(path, "utf8"));
  if (!state || !/^\d{4}-\d\d-\d\d$/.test(state.day)
    || !Number.isSafeInteger(state.dispatched) || state.dispatched < 0)
    throw new Error("Invalid daily hunt quota file (failing closed)");
  return state;
}

export function claimDailyHuntSlot(maxDaily: number, path = dailyQuotaFile(), now = new Date()): boolean {
  if (!Number.isSafeInteger(maxDaily) || maxDaily < 0)
    throw new Error("Invalid SECURITY_MAX_DAILY_HUNTS");
  if (maxDaily === 0) return false;
  mkdirSync(dirname(path), { recursive: true });
  const lock = path + ".lock";
  const fd = openSync(lock, "wx", 0o600);
  try {
    const day = now.toISOString().slice(0, 10);
    const existing = readDailyQuota(path);
    const dispatched = existing?.day === day ? existing.dispatched : 0;
    if (dispatched >= maxDaily) return false;
    const temp = path + "." + process.pid + ".tmp";
    try {
      writeFileSync(temp, JSON.stringify({ day, dispatched: dispatched + 1 }) + "\n", { mode: 0o600 });
      renameSync(temp, path);
    } finally {
      try { unlinkSync(temp); } catch {}
    }
    return true;
  } finally {
    closeSync(fd);
    unlinkSync(lock);
  }
}
