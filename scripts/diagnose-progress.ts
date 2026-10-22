/** Local read-only snapshot. Does not run discovery, models, hunts or submissions. */
import "dotenv/config";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";
import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";

process.env.PROJECT_ROOT ||= fileURLToPath(new URL("../", import.meta.url));
const { loadConfig, getConfig } = await import("../packages/core/src/config");
const schema = await import("../packages/core/src/db/schema");
const { summarizeProgramSelection } = await import("../packages/security-solver/src/program-selection");
loadConfig();
const config = getConfig();
// Match the orchestrator's local-model default, without starting any inference.
const localModel = !!(process.env.LOCAL_OLLAMA_MODEL ?? "qwen3:4b");
const sqlite = new Database(resolve(process.env.PROJECT_ROOT, config.DB_PATH), { readonly: true, fileMustExist: true });
const count = (map: Record<string, number>, key: string) => { map[key] = (map[key] || 0) + 1; };
try {
  const snapshot = sqlite.transaction(() => {
    const db = drizzle(sqlite, { schema });
    const programs = db.select().from(schema.securityPrograms).all();
    const findings = db.select().from(schema.securityFindings).all();
    const coverage: Record<string, number> = {};
    const findingsByStatus: Record<string, number> = {};
    const staticInvestigations: Record<string, number> = {};
    let malformedSummaries = 0;
    for (const program of programs) {
      try {
        const parsed = JSON.parse(program.scopeSummary || "{}");
        count(coverage, parsed.huntCoverage?.status || "not_recorded");
      } catch { malformedSummaries++; }
    }
    for (const finding of findings) {
      count(findingsByStatus, finding.status);
      if (finding.id.startsWith("offline-")) {
        try { count(staticInvestigations, JSON.parse(finding.analysisNotes || "{}").staticInvestigation?.state || "not_routed"); }
        catch { count(staticInvestigations, "invalid_metadata"); }
      }
    }
    return { selection: summarizeProgramSelection(programs, config, localModel), coverage, malformedSummaries, findingsByStatus, staticInvestigations };
  })();
  let dailyQuota: unknown = "not_present";
  try {
    const saved = JSON.parse(readFileSync(resolve(process.env.PROJECT_ROOT, "data/hunt-daily-quota.json"), "utf8"));
    dailyQuota = { day: saved.day, dispatched: saved.dispatched };
  } catch (error: any) { if (error.code !== "ENOENT") dailyQuota = "unreadable_or_invalid"; }
  console.log(JSON.stringify({
    checkedAt: new Date().toISOString(),
    settings: {
      autoHunt: config.SECURITY_AUTO_HUNT_ENABLED,
      autoSubmit: config.SECURITY_AUTO_SUBMIT,
      hackerone: config.HACKERONE_ENABLED, immunefi: config.IMMUNEFI_ENABLED, aggregator: config.AGGREGATOR_ENABLED,
      skipSignalRequired: config.SKIP_SIGNAL_REQUIRED, skipPreviouslyHunted: config.SKIP_PREVIOUSLY_HUNTED,
      minRewardCents: config.SECURITY_MIN_REWARD_CENTS, cooldownHours: config.SECURITY_HUNT_COOLDOWN_HOURS,
      maxDailyHunts: config.SECURITY_MAX_DAILY_HUNTS,
    }, dailyQuota,
    localReproductionSupport: "Python/JavaScript/Solidity string probes; bounded Solidity constructor/transaction sequences on a local EVM using solc 0.8.30. Other compiler versions, general multi-contract scenarios and Go reproduction are unsupported.",
    ...snapshot,
  }, null, 2));
} finally { sqlite.close(); }
