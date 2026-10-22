import { getConfig, type Config } from "../../core/src/config";
import type { SecurityProgram } from "../../core/src/db/schema";
import { programCandidateBlocker } from "../../core/src/program-eligibility";

/**
 * Score a single program for hunt priority using saturation-aware scoring.
 *
 * Score = opportunityScore² × log₁₀(reward+1) × responseEfficiency × sourceCodeBoost
 *         × freshnessMult × saturationMult / (1 + missStreak)
 *
 * Returns the score, or null if the program can't be scored (no assessment).
 */
export function scoreProgram(p: SecurityProgram): number | null {
  const now = Date.now();
  try {
    const parsed = JSON.parse(p.scopeSummary || "{}");
    const opportunityScore = parsed.assessment?.opportunityScore ?? 0;
    if (opportunityScore === 0) return null; // zero opportunity is not huntable

    const rewardMaxDollars = (p.rewardMaxCents ?? 0) / 100;
    const efficiency = p.responseEfficiency ?? 0.5;
    const missStreak = p.huntMissStreak ?? 0;

    // Boost programs with source code in scope
    const scopes = parsed.scopes ?? [];
    const hasSourceCode = scopes.some(
      (s: any) =>
        s.assetType === "SOURCE_CODE" ||
        (s.assetIdentifier?.includes("github.com")) ||
        (s.assetIdentifier?.includes("gitlab.com")),
    );
    const sourceCodeBoost = hasSourceCode ? 1.5 : 1.0;

    // Boost low-barrier platforms (no ID verification, no reputation gate)
    const lowBarrierBoost = p.provider === "huntr" ? 1.5 : 1.0;

    // Freshness: newer programs = less picked over
    let freshnessMult = 1.0;
    if (p.launchedAt) {
      const ageMonths = (now - p.launchedAt.getTime()) / (30.44 * 24 * 60 * 60 * 1000);
      if (ageMonths < 6) freshnessMult = 2.0;
      else if (ageMonths < 12) freshnessMult = 1.5;
      else if (ageMonths < 24) freshnessMult = 1.0;
      else if (ageMonths < 48) freshnessMult = 0.7;
      else freshnessMult = 0.5;
    }

    // Saturation: fewer disclosed reports = more low-hanging fruit
    let saturationMult = 1.0;
    const reportCount = p.disclosedReportCount;
    if (reportCount != null) {
      if (reportCount <= 5) saturationMult = 2.0;
      else if (reportCount <= 20) saturationMult = 1.5;
      else if (reportCount <= 50) saturationMult = 1.0;
      else if (reportCount <= 100) saturationMult = 0.7;
      else saturationMult = 0.4;
    }

    return 100
      * opportunityScore * opportunityScore
      * Math.log10(rewardMaxDollars + 1)
      * efficiency
      * sourceCodeBoost
      * lowBarrierBoost
      * freshnessMult
      * saturationMult
      / (1 + missStreak);
  } catch {
    return null;
  }
}


/** Same first-blocking gate used by dispatch; counts are mutually exclusive. */
export function programSelectionDecision(program: SecurityProgram, config: Config, localModel: boolean) {
  const blocker = programCandidateBlocker(program, config, localModel);
  if (blocker) return { reason: blocker, score: null };
  let assessment: any;
  try { assessment = JSON.parse(program.scopeSummary || "{}").assessment; } catch {}
  if (assessment?.opportunityScore == null) return { reason: "assessment_missing", score: null };
  if (assessment.opportunityScore === 0) return { reason: "assessment_zero_opportunity", score: null };
  const score = scoreProgram(program);
  if (score === null || !Number.isFinite(score) || score < 0) return { reason: "invalid_ranking_score", score: null };
  if (score === 0) return { reason: "ranking_zero_reward_or_efficiency", score: null };
  return { reason: "eligible", score };
}

export function summarizeProgramSelection(programs: SecurityProgram[], config = getConfig(), localModel = !!process.env.LOCAL_OLLAMA_MODEL) {
  const counts: Record<string, number> = {};
  const providers: Record<string, Record<string, number>> = {};
  for (const program of programs) {
    const { reason } = programSelectionDecision(program, config, localModel);
    counts[reason] = (counts[reason] || 0) + 1;
    const group = providers[program.provider] ||= {};
    group[reason] = (group[reason] || 0) + 1;
  }
  return { total: programs.length, eligible: counts.eligible || 0, firstBlockingReasonCounts: counts, providers };
}

/** Metadata estimate, not a promise of vulnerability difficulty or payout. */
export function estimateProgramDifficulty(program:SecurityProgram):number {
  try {
    const data=JSON.parse(program.scopeSummary || "{}");
    const a=data.assessment || {};const r=a.rubric || {};
    const value=(x:unknown,fallback:number)=>typeof x === "number" && Number.isFinite(x) ? Math.max(0,Math.min(3,x)) : fallback;
    const sources=(Array.isArray(data.scopes)?data.scopes:[]).filter((s:any)=>s.assetType === "SOURCE_CODE" || /github\.com|gitlab\.com/.test(s.assetIdentifier || "")).length;
    // Stack fit and source access matter more than monetary reward. Unknown
    // metadata is assigned a middle value rather than treated as easy.
    return Math.min(100,Math.round(20 + (3-value(r.techStackMatch,1.5))*15 +
      (3-value(r.sourceCodeQuality,1.5))*7 + value(r.scopeBreadth,1.5)*5 + Math.min(15,Math.max(0,sources-1)*3)));
  } catch {return 75;}
}
export function compareProgramDifficulty(a:SecurityProgram,b:SecurityProgram):number {
  return estimateProgramDifficulty(a)-estimateProgramDifficulty(b) ||
    (a.rewardMaxCents ?? Number.MAX_SAFE_INTEGER)-(b.rewardMaxCents ?? Number.MAX_SAFE_INTEGER) || a.id.localeCompare(b.id);
}
