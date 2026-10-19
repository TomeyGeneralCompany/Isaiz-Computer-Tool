import type { Config } from "./config";
import type { SecurityProgram } from "./db/schema";
import { assertAuthorizedProgram } from "./scope-authorization";
import { authorizedSourceUrls } from "./source-repository";

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
  if (program.requiresSignal && config.SKIP_SIGNAL_REQUIRED) return "signal_required";
  if ((program.rewardMaxCents ?? 0) < config.SECURITY_MIN_REWARD_CENTS) return "below_reward_threshold";
  if (program.lastHuntedAt && config.SKIP_PREVIOUSLY_HUNTED) return "previously_hunted";
  if (program.lastHuntedAt) {
    const cooldown = config.SECURITY_HUNT_COOLDOWN_HOURS * 3600000 * 2 ** Math.min(program.huntMissStreak ?? 0,6);
    if (now - program.lastHuntedAt.getTime() < cooldown) return "cooldown";
  }
  let scopes: unknown;
  try {
    const failure = JSON.parse(program.scopeSummary || "{}").huntFailure;
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
