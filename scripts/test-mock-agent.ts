import { createServer } from "node:http";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runLocalAudit } from "../packages/security-solver/src/local-ollama-runner";

const dir = await mkdtemp(join(tmpdir(), "autohack-mock-"));
let calls = 0;
const server = createServer(async (req, res) => {
  let body = "";
  for await (const chunk of req) body += chunk.toString();
  const data = JSON.parse(body);
  calls++;
  res.setHeader("content-type", "application/json");
  if (calls === 1) {
    if (!Array.isArray(data.tools) || !data.tools.some((x: any) => x.function.name === "read_file"))
      throw new Error("Missing read_file tool");
    res.end(JSON.stringify({ message: { role: "assistant", content: "", tool_calls: [
      { function: { name: "read_file", arguments: { path: "sample.ts" } } }
    ] } }));
  } else {
    const result = data.messages.at(-1);
    if (result.role !== "tool" || result.tool_name !== "read_file" || !result.content.includes("return a + b"))
      throw new Error("Tool response missing source content");
    res.end(JSON.stringify({ message: { role: "assistant", content: "FUNCTION_FOUND" } }));
  }
});
try {
  await writeFile(join(dir, "sample.ts"), "export function add(a: number, b: number) { return a + b; }");
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("Invalid server address");
  process.env.AUTOHACK_OLLAMA_URL = `http://127.0.0.1:${addr.port}/api/chat`;
  const answer = await runLocalAudit("Inspect sample.ts", join(dir, "agent.log"), 10000, dir, "mock");
  const transcript = await readFile(join(dir, "agent.log"), "utf8");
  if (answer !== "FUNCTION_FOUND" || calls !== 2 || !transcript.includes("[TOOL] read_file"))
    throw new Error("Agent did not complete real tool loop");
  process.stdout.write("Mocked Ollama tool loop passed\n");
} finally {
  server.close();
  delete process.env.AUTOHACK_OLLAMA_URL;
  await rm(dir, { recursive: true, force: true });
}
