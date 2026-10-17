import { readdir, readFile, realpath, stat, appendFile } from "node:fs/promises";
import { resolve, relative, sep } from "node:path";

type Message = { role: string; content: string; tool_calls?: Array<{ function: { name: string; arguments: Record<string, unknown> } }> };
const tools = [
  { type: "function", function: { name: "list_files", description: "List files in the authorized local audit workspace", parameters: { type: "object", properties: { path: { type: "string" } }, required: ["path"] } } },
  { type: "function", function: { name: "read_file", description: "Read a source file in the authorized local audit workspace", parameters: { type: "object", properties: { path: { type: "string" } }, required: ["path"] } } },
];
export async function runLocalAudit(
  prompt: string, logFile: string, timeoutMs: number, cwd: string,
  model: string, systemPrompt?: string,
): Promise<string> {
  const root = await realpath(cwd);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const messages: Message[] = [
    { role: "system", content: (systemPrompt || "") + "\nYou are performing an OFFLINE, READ-ONLY source audit. Use tools to inspect actual source. Never invent findings or claim runtime verification. No network access or execution is available. Return only evidence-supported results." },
    { role: "user", content: "/no_think\n" + prompt },
  ];
  async function safePath(path: string): Promise<string> {
    const candidate = await realpath(resolve(root, path || "."));
    const rel = relative(root, candidate);
    if (rel === ".." || rel.startsWith(".." + sep) || resolve(root, rel) !== candidate) {
      throw new Error("Path outside authorized workspace");
    }
    return candidate;
  }
  try {
    for (let turn = 0; turn < 20; turn++) {
      const response = await fetch("http://127.0.0.1:11434/api/chat", {
        method: "POST", signal: controller.signal,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model, stream: false, think: false, messages, tools,
          options: { num_predict: 2048, temperature: 0.1 } }),
      });
      if (!response.ok) throw new Error("Ollama HTTP " + response.status);
      const result = await response.json() as { message?: Message };
      const message = result.message;
      if (!message) throw new Error("Ollama returned no assistant message");
      messages.push(message);
      if (message.content) await appendFile(logFile, message.content + "\n");
      if (!message.tool_calls?.length) {
        if (!message.content?.trim()) throw new Error("Ollama returned empty final response");
        return message.content;
      }
      for (const call of message.tool_calls.slice(0, 8)) {
        let output: string;
        try {
          const name = call.function.name;
          const path = String(call.function.arguments?.path ?? ".");
          const full = await safePath(path);
          if (name === "list_files") {
            const entries = await readdir(full, { withFileTypes: true });
            output = entries.filter(e => !e.name.startsWith(".") && e.name !== "node_modules")
              .slice(0, 100).map(e => (e.isDirectory() ? "dir " : "file ") + e.name).join("\n");
          } else if (name === "read_file") {
            const info = await stat(full);
            if (!info.isFile() || info.size > 256_000) throw new Error("Not a readable source file under 256KB");
            output = (await readFile(full, "utf8")).slice(0, 30_000);
          } else throw new Error("Unknown tool");
        } catch (error) {
          output = "Tool error: " + String(error);
        }
        messages.push({ role: "tool", content: output.slice(0, 30_000) });
      }
    }
    throw new Error("Local audit reached its 20-turn inspection limit");
  } finally {
    clearTimeout(timer);
  }
}
