/** Pure fictional programs and intercepted provider responses; no network or database. */
import assert from "node:assert/strict";
import { loadConfig } from "../packages/core/src/config";
import type { SecurityProgram } from "../packages/core/src/db/schema";
import { programSelectionDecision, summarizeProgramSelection } from "../packages/security-solver/src/program-selection";
import { fetchProgramSignalRequirement } from "../packages/security-discovery/src/hackerone-client";
process.env.GITHUB_TOKEN = "fictional-only";
const config = { ...loadConfig(), IMMUNEFI_ENABLED: true, HACKERONE_ENABLED: true, SKIP_SIGNAL_REQUIRED: true, SKIP_PREVIOUSLY_HUNTED: true, SECURITY_MIN_REWARD_CENTS: 10000 };
const summary = (assessment: unknown = { opportunityScore: 0.8 }) => JSON.stringify({ scopes: [{ assetIdentifier: "https://github.com/fictional/flooperfloop", assetType: "SOURCE_CODE", eligibleForBounty: true }], assessment });
const base = { id: "fictional", provider: "immunefi", name: "Flooperfloop", status: "active", rewardMaxCents: 100000, scopeSummary: summary() } as SecurityProgram;
const variants = [
  base,
  { ...base, provider: "hackerone", requiresSignal: true },
  { ...base, lastHuntedAt: new Date(), scopeSummary: JSON.stringify({ ...JSON.parse(summary()), huntCoverage: { status: "completed" } }) },
  { ...base, scopeSummary: summary(null) },
  { ...base, scopeSummary: summary({ opportunityScore: 0 }) },
  { ...base, responseEfficiency: 0 },
  { ...base, status: "archived" } as SecurityProgram,
  { ...base, scopeSummary: summary({ opportunityScore: "broken" }) },
];
const report = summarizeProgramSelection(variants, config, true);
assert.equal(report.total, 8);
assert.equal(report.eligible, 2);
assert.equal(Object.values(report.firstBlockingReasonCounts).reduce((a,b) => a+b, 0), 8);
for (const reason of ["previously_hunted", "assessment_missing", "assessment_zero_opportunity", "ranking_zero_reward_or_efficiency", "inactive", "invalid_ranking_score"]) assert.equal(report.firstBlockingReasonCounts[reason], 1, reason);
assert.equal(programSelectionDecision({ ...base, requiresSignal: true, provider: "hackerone" }, { ...config, SKIP_SIGNAL_REQUIRED: false }, true).reason, "eligible", "Operator preference is preserved");
assert.equal(report.providers.hackerone.eligible, 1);
assert.equal(programSelectionDecision({ ...base, requiresSignal: true, provider: "hackerone" }, config, false).reason, "signal_required", "Nonlocal skip policy remains intact");
assert.equal(programSelectionDecision({ ...base, requiresSignal: true, provider: "hackerone", scopeSummary: JSON.stringify({scopes: []}) }, config, true).reason, "no_explicit_scope", "Signal inspection change must not admit unscoped programs");
const legacy = { ...base, lastHuntedAt: new Date(Date.now() - 48 * 3600000), huntCount: 7, huntMissStreak: 6 };
assert.equal(programSelectionDecision(legacy, config, true).reason, "eligible", "Legacy timestamps without completed coverage cannot permanently exclude local work");
assert.equal(legacy.huntCount, 7, "Selection must preserve history");
assert.equal(programSelectionDecision(legacy, config, false).reason, "previously_hunted", "Nonlocal completed-hunt policy remains intact");
assert.equal(programSelectionDecision({ ...legacy, lastHuntedAt: new Date() }, config, true).reason, "cooldown", "Legacy history still respects cooldown");
assert.equal(programSelectionDecision({ ...legacy, scopeSummary: JSON.stringify({ ...JSON.parse(summary()), huntCoverage: {status: "unsupported"}, huntFailure: {retryAfter: new Date(Date.now() + 60000).toISOString()} }) }, config, true).reason, "failed_hunt_backoff", "Incomplete attempts remain bounded by retry backoff");
const saved = globalThis.fetch;
try {
  const cases: [unknown, boolean | null][] = [
    [{ data: { team: { signal_requirements_setting: { target_signal: 0 } } } }, true],
    [{ data: { team: { signal_requirements_setting: { target_signal: -1 } } } }, true],
    [{ data: { team: { signal_requirements_setting: { target_signal: 1 } } } }, true],
    [{ data: { team: { signal_requirements_setting: { target_signal: null } } } }, false],
    [{ data: { team: { signal_requirements_setting: null } } }, false],
    [{ data: { team: {} } }, null],
    [{ data: { team: { signal_requirements_setting: {} } } }, null],
    [{ data: { team: { signal_requirements_setting: { target_signal: "0" } } } }, null],
    [{ errors: [{ message: "partial response" }], data: { team: { signal_requirements_setting: null } } }, null],
  ];
  for (const [body, expected] of cases) {
    globalThis.fetch = async () => new Response(JSON.stringify(body), { status: 200 });
    assert.equal(await fetchProgramSignalRequirement("fictional-flooperfloop"), expected);
  }
} finally { globalThis.fetch = saved; }
console.log("Dispatch exclusion accounting, zero/missing assessment distinction and incomplete Signal responses: PASSED");

const { LOCAL_REPRODUCTION_CAPABILITY_VERSION } = await import("../packages/core/src/program-eligibility");
const held = {...base,scopeSummary:JSON.stringify({...JSON.parse(summary()),huntCoverage:{status:"unsupported",capabilityVersion:LOCAL_REPRODUCTION_CAPABILITY_VERSION}})};
assert.equal(programSelectionDecision(held,config,true).reason,"unsupported_reproduction");
assert.equal(programSelectionDecision({...held,scopeSummary:JSON.stringify({...JSON.parse(summary()),huntCoverage:{status:"unsupported",capabilityVersion:LOCAL_REPRODUCTION_CAPABILITY_VERSION-1}})},config,true).reason,"eligible");
