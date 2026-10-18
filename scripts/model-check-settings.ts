import type { LocalAuditLimits } from "../packages/security-solver/src/local-ollama-runner";
export function hostModelTimeout(): number {
  const value = Number(process.env.LOCAL_AGENT_TEST_TIMEOUT_MS || 600_000);
  if (!Number.isSafeInteger(value) || value < 1000 || value > 1_800_000)
    throw new Error("LOCAL_AGENT_TEST_TIMEOUT_MS must be between 1000 and 1800000");
  return value;
}
export const fixtureAuditLimits: LocalAuditLimits = {
  maxTurns:6, numPredict:128, numCtx:2048, numThreads:4,
};
