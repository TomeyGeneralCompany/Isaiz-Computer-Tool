import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runLocalAudit } from "../packages/security-solver/src/local-ollama-runner";

const dir = await mkdtemp(join(tmpdir(), "autohack-agent-"));
try {
  await writeFile(join(dir, "sample.ts"), "export function add(a: number, b: number) { return a + b; }\n");
  const answer = await runLocalAudit(
    "Use read_file to inspect sample.ts. Then answer exactly: FUNCTION_FOUND",
    join(dir, "agent.log"), 120_000, dir,
    process.env.LOCAL_OLLAMA_MODEL || "qwen3:4b",
  );
  if (!answer.includes("FUNCTION_FOUND")) throw new Error("Agent did not complete fixture: " + answer.slice(0, 300));
  process.stdout.write("Direct Ollama tool-using agent passed local source fixture\n");
} finally {
  await rm(dir, { recursive: true, force: true });
}
