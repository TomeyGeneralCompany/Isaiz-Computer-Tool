import type { Config } from "./config";
import type { SecurityProgram } from "./db/schema";
import { assertAuthorizedProgram } from "./scope-authorization";
import { authorizedSourceUrls } from "./source-repository";

/** Version of coverage semantics; older completion records are not exhaustive. */
export const LOCAL_REPRODUCTION_CAPABILITY_VERSION = 4;

/** Shared pre-assessment and pre-dispatch filters. Assessment itself is separate. */
export function programCandidateBlocker(program: SecurityProgram, config: Config, localModel: boolean, now = Date.now()): string | null {
  if (program.status !== "active") return "inactive";
  const enabled = program.provider === "hackerone" ? config.HACKERONE_ENABLED :
    program.provider === "immunefi" ? config.IMMUNEFI_ENABLED :
    ["bugcrowd","intigriti","yeswehack"].includes(program.provider) ? config.AGGREGATOR_ENABLED : false;
  // Huntr's former repository feed is retired. Arbitrary GitHub links are not scope.
  if (!enabled) return "provider_disabled_or_unsupported";
  try {assertAuthorizedProgram(program.scopeSummary);} catch {return "no_explicit_scope";}
  if (program.providerProgramId && config.EXCLUDE_SECURITY_PROGRAMS.some(h => h.toLowerCase() === program.providerProgramId!.toLowerCase())) return "excluded";
  // A submission threshold does not prevent an offline source inspection.
  // The local review/submission path checks fresh Signal requirements again
  // before any report is sent. Nonlocal hunting keeps the legacy skip policy.
  if (!localModel && program.requiresSignal && config.SKIP_SIGNAL_REQUIRED) return "signal_required";
  if ((program.rewardMaxCents ?? 0) < config.SECURITY_MIN_REWARD_CENTS) return "below_reward_threshold";
  // Imported installations may have marked regex scans/incomplete attempts as
  // "hunted". In the local engine, only recorded completed coverage establishes
  // completion. Keep legacy timestamps intact for history and cooldowns.
  let completedCoverage = false;
  try { const coverage = JSON.parse(program.scopeSummary || "{}").huntCoverage; completedCoverage = coverage?.status === "completed" && coverage?.capabilityVersion === LOCAL_REPRODUCTION_CAPABILITY_VERSION; } catch {}
  if (program.lastHuntedAt && config.SKIP_PREVIOUSLY_HUNTED && (!localModel || completedCoverage)) return "previously_hunted";
  if (program.lastHuntedAt) {
    const verifiedMissStreak = localModel && !completedCoverage ? 0 : (program.huntMissStreak ?? 0);
    const cooldown = config.SECURITY_HUNT_COOLDOWN_HOURS * 3600000 * 2 ** Math.min(verifiedMissStreak,6);
    if (now - program.lastHuntedAt.getTime() < cooldown) return "cooldown";
  }
  let scopes: unknown;
  try {
    const tracking = JSON.parse(program.scopeSummary || "{}");
    // A handful of unsupported functions cannot establish whole-program incompatibility.
    // Failed and unsupported passes both retry through bounded huntFailure backoff.
    const failure = tracking.huntFailure;
    if (failure && Number.isFinite(Date.parse(failure.retryAfter)) && Date.parse(failure.retryAfter) > now) return "failed_hunt_backoff";
  } catch {}
  try {const parsed = JSON.parse(program.scopeSummary || "{}"); scopes = Array.isArray(parsed) ? parsed : parsed.scopes;} catch {return "invalid_scope";}
  if ((localModel || config.SKIP_WEB_ONLY_PROGRAMS) && !authorizedSourceUrls(scopes).length) return "no_supported_source_repository";
  return null;
}


/** Failed/incomplete runs are retryable, rather than permanently "already hunted". */
export function recordHuntAttempt(summary: string | null, success: boolean, now = Date.now()): string {
  let parsed: Record<string,any> = {};
  try {const value = JSON.parse(summary || "{}"); parsed = Array.isArray(value) ? {scopes:value} : value || {};} catch {}
  if (success) delete parsed.huntFailure;
  else {
    const attempts = Math.min(10, Math.max(0,Number(parsed.huntFailure?.attempts) || 0) + 1);
    parsed.huntFailure = {attempts,failedAt:new Date(now).toISOString(),
      retryAfter:new Date(now + Math.min(3600000,60000 * 2 ** (attempts - 1))).toISOString()};
  }
  return JSON.stringify(parsed);
}
