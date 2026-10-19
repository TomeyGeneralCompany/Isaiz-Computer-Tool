import "dotenv/config";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assessmentFixture, checkAssessment } from "./assessment-fixture";

const root = await mkdtemp(join(tmpdir(),"autohack-assessment-"));
try {
  process.env.PROJECT_ROOT = root;
  process.env.GITHUB_TOKEN = "offline-assessment-fixture";
  process.env.CLAUDE_BACKEND = "cli";
  process.env.OLLAMA_DISCOVERY_DIRECT = "true";
  const { assessProgram } = await import("../packages/security-analyzer/src/assessor");
  const result = await assessProgram(assessmentFixture);
  checkAssessment(result);
  console.log("REAL LOCAL MODEL -> production program assessor -> validated structured ranking: PASSED (fixture only; no target requests or submissions)");
} finally {
  await rm(root,{recursive:true,force:true});
}
