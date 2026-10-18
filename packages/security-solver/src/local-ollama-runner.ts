import { auditActionSchema, auditProtocolPrompt, decodeAuditAction } from "./local-audit-protocol";
import { readdir, readFile, realpath, stat, appendFile } from "node:fs/promises";
import { resolve, relative, sep } from "node:path";

type Message = { role: string; content: string; tool_name?: string; tool_calls?: Array<{ function: { name: string; arguments: Record<string, unknown> } }> };
const tools = [
  { type: "function", function: { name: "list_files", description: "List files in the authorized local audit workspace", parameters: { type: "object", properties: { path: { type: "string" } }, required: ["path"] } } },
  { type: "function", function: { name: "search_files", description: "Search tracked source files for a literal string inside the authorized workspace", parameters: { type: "object", properties: { query: { type: "string" } }, required: ["query"] } } },
  { type: "function", function: { name: "read_file", description: "Read a source file in the authorized local audit workspace", parameters: { type: "object", properties: { path: { type: "string" } }, required: ["path"] } } },
];
export interface LocalAuditLimits {
  maxTurns: number;
  numPredict: number;
  numCtx: number;
  numThreads: number;
}
export async function runLocalAudit(
  prompt: string, logFile: string, timeoutMs: number, cwd: string,
  model: string, systemPrompt?: string, limits: Partial<LocalAuditLimits> = {},
): Promise<string> {
  const settings = {maxTurns:20, numPredict:2048, numCtx:4096, numThreads:4, ...limits};
  for (const [key, low, high] of [["maxTurns",1,20],["numPredict",32,2048],["numCtx",1024,32768],["numThreads",1,32]] as const) {
    if (!Number.isSafeInteger(settings[key]) || settings[key] < low || settings[key] > high)
      throw new Error("Invalid local audit limit: " + key);
  }
  const protocol = process.env.LOCAL_OLLAMA_TOOL_PROTOCOL || "json";
  if (!["json","native"].includes(protocol)) throw new Error("LOCAL_OLLAMA_TOOL_PROTOCOL must be json or native");
  const structured = protocol === "json";
  let successfulReads = 0;
  let generationBudget = settings.numPredict;
  const root = await realpath(cwd);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const messages: Message[] = [
    { role: "system", content: (systemPrompt || "") + "\nYou are performing an OFFLINE, READ-ONLY source audit. Use tools to inspect actual source. Never invent findings or claim runtime verification. No network access or execution is available. Return only evidence-supported results." + (structured ? auditProtocolPrompt : "") },
    { role: "user", content: prompt + "\n/no_think" },
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
    for (let turn = 0; turn < settings.maxTurns; turn++) {
      const started = Date.now();
      await appendFile(logFile, `[OLLAMA] turn ${turn+1}/${settings.maxTurns}: request started; model=${model}; context=${limits.numCtx ?? "server-default"}; generation_limit=${generationBudget}; protocol=${protocol}\n`);
      const response = await fetch(process.env.AUTOHACK_OLLAMA_URL || "http://127.0.0.1:11434/api/chat", {
        method: "POST", signal: controller.signal,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model, stream: false, think: false, messages, ...(structured ? {format:auditActionSchema} : {tools}),
          keep_alive:"10m",
          options: { num_predict:generationBudget,
            ...(limits.numCtx === undefined ? {} : {num_ctx:settings.numCtx}),
            ...(limits.numThreads === undefined ? {} : {num_thread:settings.numThreads}), temperature:0 } }),
      });
      if (!response.ok) throw new Error("Ollama HTTP " + response.status);
      const result = await response.json() as { message?: Message; eval_count?: number; prompt_eval_count?: number; done_reason?: string };
      await appendFile(logFile, `[OLLAMA] turn ${turn+1}: response received in ${Date.now()-started}ms; prompt_tokens=${result.prompt_eval_count ?? "unknown"}; generated_tokens=${result.eval_count ?? "unknown"}\n`);
      let message = result.message;
      if (!message) throw new Error("Ollama returned no assistant message");
      if (structured) {
        let action;
        try {action = decodeAuditAction(message.content);}
        catch {
          if (result.done_reason === "length" && generationBudget < 2048) {
            generationBudget = Math.min(generationBudget*2,2048);
            await appendFile(logFile, `[OLLAMA] truncated JSON action; retrying with generation_limit=${generationBudget}\n`);
            continue;
          }
          throw new Error("Ollama did not return a valid read-only JSON action; no tool was executed");
        }
        messages.push({role:"assistant",content:message.content});
        message = action.action === "final" ? {role:"assistant",content:action.answer} : {
          role:"assistant",content:"",tool_calls:[{function:{name:action.action,arguments:{path:action.path,query:action.query}}}],
        };
      } else {messages.push(message);}
      if (message.content) await appendFile(logFile, message.content + "\n");
      if (!message.tool_calls?.length) {
        if (!successfulReads) {
          messages.push({role:"user",content:"No source file has been successfully read. Choose read_file now; a final answer is not accepted before a successful file read. /no_think"});
          continue;
        }
        if (!message.content?.trim()) throw new Error("Ollama returned empty final response");
        return message.content;
      }
      for (const call of message.tool_calls.slice(0, 8)) {
        await appendFile(logFile, "[TOOL] " + call.function.name + "\n");
        let output: string;
        try {
          const name = call.function.name;
          const path = String(call.function.arguments?.path ?? ".");
          const full = await safePath(path);
          if (name === "list_files") {
            const entries = await readdir(full, { withFileTypes: true });
            output = entries.filter(e => !e.name.startsWith(".") && e.name !== "node_modules")
              .slice(0, 100).map(e => (e.isDirectory() ? "dir " : "file ") + e.name).join("\n");
          } else if (name === "search_files") {
            const query = String(call.function.arguments?.query ?? "").slice(0, 120);
            if (query.length < 3) throw new Error("Search query must be at least three characters");
            const results: string[] = [];
            let visited = 0;
            async function walk(dir: string, depth: number): Promise<void> {
              if (depth > 5 || visited > 300 || results.length >= 40) return;
              for (const entry of await readdir(dir, { withFileTypes: true })) {
                if (entry.name.startsWith(".") || ["node_modules", "dist", "build", "vendor"].includes(entry.name)) continue;
                const target = resolve(dir, entry.name);
                if (entry.isSymbolicLink()) continue;
                if (entry.isDirectory()) { await walk(target, depth + 1); continue; }
                if (!entry.isFile() || !/\.(ts|tsx|js|jsx|py|go|rs|java|php|rb|sol|json|yaml|yml)$/.test(entry.name)) continue;
                visited++;
                const info = await stat(target);
                if (info.size > 128000) continue;
                const lines = (await readFile(target, "utf8")).split("\n");
                for (let i = 0; i < lines.length && results.length < 40; i++) {
                  if (lines[i].includes(query)) results.push(relative(root, target) + ":" + (i + 1) + ": " + lines[i].slice(0, 240));
                }
              }
            }
            await walk(root, 0);
            output = results.join("\n") || "No matches";
          } else if (name === "read_file") {
            const info = await stat(full);
            if (!info.isFile() || info.size > 256_000) throw new Error("Not a readable source file under 256KB");
            output = (await readFile(full, "utf8")).slice(0, 30_000);
            successfulReads++;
            await appendFile(logFile, "[READ_OK] " + relative(root,full) + "\n");
          } else throw new Error("Unknown tool");
        } catch (error) {
          output = "Tool error: " + String(error);
        }
        messages.push(structured
          ? {role:"user",content:"TOOL_RESULT " + JSON.stringify({name:call.function.name,output:output.slice(0,30000)}) + "\nChoose the next JSON action. /no_think"}
          : { role:"tool", tool_name:call.function.name, content:output.slice(0,30000) });
      }
    }
    throw new Error(`Local audit reached its ${settings.maxTurns}-turn inspection limit`);
  } catch (error) {
    if (controller.signal.aborted)
      throw new Error(`Ollama audit timed out after ${Math.round(timeoutMs/1000)} seconds; check model load/CPU contention and the turn timing log`);
    throw error;
  } finally {
    clearTimeout(timer);
  }
}
