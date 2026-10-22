import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { claimDailyHuntSlot, readDailyQuota, dailyHuntQuotaStatus } from "../packages/core/src/daily-hunt-limit";
const dir = mkdtempSync(join(tmpdir(), "autohack-quota-"));
const path = join(dir, "nested", "limit.json");
try {
  const first = new Date("2026-10-18T01:00:00Z");
  assert.equal(readDailyQuota(path), null);
  assert.equal(claimDailyHuntSlot(2, path, first), true);
  assert.equal(claimDailyHuntSlot(2, path, first), true);
  assert.equal(claimDailyHuntSlot(2, path, first), false);
  assert.deepEqual(dailyHuntQuotaStatus(2,path,first), {day:"2026-10-18",dispatched:2,limit:2,available:false,resetsAt:"2026-10-19T00:00:00.000Z"});
  assert.equal(dailyHuntQuotaStatus(2,path,new Date("2026-10-19T00:00:00Z")).available,true);
  assert.equal(dailyHuntQuotaStatus(0,path,first).available,false);
  assert.deepEqual(readDailyQuota(path), { day:"2026-10-18", dispatched: 2 });
  assert.equal(claimDailyHuntSlot(2, path, new Date("2026-10-19T01:00:00Z")), true);
  assert.deepEqual(readDailyQuota(path), { day:"2026-10-19", dispatched: 1 });
  assert.equal(claimDailyHuntSlot(0, path, first), false);
  assert.throws(() => claimDailyHuntSlot(-1, path, first), /Invalid/);
  writeFileSync(path, '{"day":"2026-10-19","dispatched":-1}');
  assert.throws(() => claimDailyHuntSlot(2, path, first), /Invalid/);
  console.log("Durable daily quota tests passed");
} finally { rmSync(dir,{recursive:true,force:true}); }
