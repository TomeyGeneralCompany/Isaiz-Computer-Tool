import assert from "node:assert/strict";
import type { SecurityProgram } from "../packages/core/src/db/schema";
import type { ProgramAssessmentResult } from "../packages/security-analyzer/src/assessor";

// Data only: the assessor never clones or contacts this fictional repository.
export const assessmentFixture = {
  id:"owned-assessment-fixture", provider:"hackerone", providerProgramId:null,
  name:"Owned offline assessment fixture", url:null,
  scopeSummary:JSON.stringify({scopes:[{
    assetType:"SOURCE_CODE", assetIdentifier:"https://github.com/example/owned-assessment-fixture",
    instruction:"TypeScript source review only. This is fictional fixture data.",
  }]}),
  rewardMinCents:10000, rewardMaxCents:100000, currency:"USD",
  responseEfficiency:0.8, status:"active", launchedAt:null,
  disclosedReportCount:0, requiresSignal:false, huntCount:0, huntMissStreak:0,
  lastHuntedAt:null, discoveredAt:new Date(0), updatedAt:new Date(0),
} satisfies SecurityProgram;

export function checkAssessment(result: ProgramAssessmentResult): void {
  assert.equal(result.hasSourceCode,true);
  assert.ok(result.opportunityScore >= 0 && result.opportunityScore <= 1);
  assert.ok(result.rubric.sourceCodeQuality >= 1);
  assert.ok(result.topTargets.length > 0 && result.topTargets.length <= 5);
  assert.ok(result.topTargets.every(target => target.asset === "https://github.com/example/owned-assessment-fixture"));
}
