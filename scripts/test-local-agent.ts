import "dotenv/config";
import { randomBytes } from "node:crypto";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runLocalAudit } from "../packages/security-solver/src/local-ollama-runner";

const dir = await mkdtemp(join(tmpdir(), "autohack-agent-"));
try {
  const marker = randomBytes(12).toString("hex");
  await writeFile(join(dir, "sample.ts"), `export const acceptanceMarker = "${marker}";\n`);
  const answer = await runLocalAudit(
    "Use read_file to inspect sample.ts. Return the exact value of acceptanceMarker from that file.",
    join(dir, "agent.log"), 120_000, dir,
    process.env.LOCAL_OLLAMA_MODEL || "qwen3:4b",
  );
  if (!answer.includes(marker)) throw new Error("Agent did not complete fixture: " + answer.slice(0, 300));
  const transcript = await readFile(join(dir, "agent.log"), "utf8");
  if (!transcript.includes("[TOOL] read_file")) throw new Error("Agent never used read_file; fixture answer alone is insufficient");
  process.stdout.write("Direct Ollama tool-using agent passed local source fixture\n");
} finally {
  await rm(dir, { recursive: true, force: true });
}
