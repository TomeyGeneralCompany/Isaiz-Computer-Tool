import { readFile } from "node:fs/promises";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const jobs = new Set<AbortController>();
const root = () => process.env.PROJECT_ROOT || process.cwd();
export function activeLocalJobCount(): number { return jobs.size; }
export function abortLocalJobs(): boolean {
  const active = jobs.size > 0;
  for (const controller of jobs) controller.abort("operator_cancelled");
  return active;
}
export function requestLocalJobCancellation(): boolean {
  const local = abortLocalJobs();
  try {
    const lock = JSON.parse(readFileSync(join(root(), "data", "security-hunt.lock"), "utf8"));
    if (!Number.isSafeInteger(lock.pid) || lock.pid < 1) return local;
    process.kill(lock.pid, 0);
    writeFileSync(join(root(), "data", "cancel-local-" + lock.pid + ".json"),
      JSON.stringify({ requestedAt: Date.now(), token: lock.token }), { mode: 0o600 });
    return true;
  } catch { return local; }
}
/** One cancellation lifetime spans acquisition, probes, inference and review. */
export function beginLocalJob() {
  const controller = new AbortController();
  const startedAt = Date.now();
  let token: string | undefined;
  try { token = JSON.parse(readFileSync(join(root(), "data", "security-hunt.lock"), "utf8")).token; } catch {}
  jobs.add(controller);
  let checking = false;
  const timer = setInterval(async () => {
    if (checking || controller.signal.aborted) return;
    checking = true;
    try {
      const request = JSON.parse(await readFile(join(root(), "data", "cancel-local-" + process.pid + ".json"), "utf8"));
      if (request.requestedAt >= startedAt && (!request.token || request.token === token))
        controller.abort("operator_cancelled");
    } catch {} finally { checking = false; }
  }, 100);
  return { signal: controller.signal, dispose() { clearInterval(timer); jobs.delete(controller); } };
}
