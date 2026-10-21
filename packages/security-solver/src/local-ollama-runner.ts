import { postOllamaJson } from "@bounty/core";
import { auditActionSchema, auditProtocolPrompt, decodeAuditAction } from "./local-audit-protocol";
import { readdir, readFile, realpath, stat, appendFile } from "node:fs/promises";
import { resolve, relative, sep, join } from "node:path";

type Message = { role: string; content: string; tool_name?: string; tool_calls?: Array<{ function: { name: string; arguments: Record<string, unknown> } }> };
async function recordToolActivity(logFile:string,event:Record<string,unknown>):Promise<void> {
  try {await appendFile(logFile+".activity.jsonl","[ACTIVITY] "+JSON.stringify({at:new Date().toISOString(),...event})+"\n");}catch{}
}
const activeControllers=new Set<AbortController>();
export function activeLocalAuditCount():number {return activeControllers.size;}
export function abortLocalAudits():boolean {
  const active=activeControllers.size>0;
  for(const controller of activeControllers)controller.abort("operator_cancelled");
  return active;
}
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
  /** Return corrective feedback to reject a final answer, or null to accept. */
  validateFinal?: (answer: string) => string | null;
  signal?: AbortSignal;
  onRead?: (path:string) => void;
  verifyPython?: (path:string,functionName:string,kind:string) => Promise<string>;
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
  const forwardCancellation = () => controller.abort(limits.signal?.reason);
  limits.signal?.throwIfAborted();
  limits.signal?.addEventListener("abort", forwardCancellation, {once:true});
  const auditStartedAt=Date.now();
  activeControllers.add(controller);
  const cancellationPath=join(process.env.PROJECT_ROOT || process.cwd(),"data","cancel-local-"+process.pid+".json");
  let checkingCancellation=false;
  const cancellationTimer=setInterval(async()=>{
    if(checkingCancellation)return;checkingCancellation=true;
    try {const request=JSON.parse(await readFile(cancellationPath,"utf8"));if(request.requestedAt>=auditStartedAt)controller.abort("operator_cancelled");}catch{}
    finally{checkingCancellation=false;}
  },250);
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const actionSchema = limits.verifyPython ? {...auditActionSchema,properties:{...auditActionSchema.properties,
    action:{type:"string",enum:[...auditActionSchema.properties.action.enum,"verify_source","verify_python"]}}} : auditActionSchema;
  const probePrompt = limits.verifyPython ? "\nThe verify_source action invokes a fixed, isolated source function probe. Set path to a .py, .js, .mjs, .cjs or .sol source file, query to its public/exported function name (Contract.function for Solidity), answer to html_reflection or path_construction. The function must take one string and return a string. JavaScript exports may be async. Solidity requires a deployable zero-argument constructor and a public/external view or pure function compatible with installed solc 0.8.30; runs on an in-memory local EVM. Use returned observations honestly; they do not prove full exploitability. No arbitrary commands are available." : "";
  const availableTools = limits.verifyPython ? [...tools,{type:"function",function:{
    name:"verify_source",description:probePrompt,parameters:{type:"object",
      properties:{path:{type:"string"},query:{type:"string"},kind:{type:"string"}},required:["path","query","kind"]},
  }}] : tools;
  const messages: Message[] = [
    { role: "system", content: (systemPrompt || "") + "\nPerform an offline source audit. Inspect actual files. Never invent findings or observations. No target network requests are available." + (limits.verifyPython ? probePrompt : " No source execution is available.") + (structured ? auditProtocolPrompt.replace(JSON.stringify(auditActionSchema),JSON.stringify(actionSchema)) : "") },
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
      controller.signal.throwIfAborted();
      const started = Date.now();
      await appendFile(logFile, `[OLLAMA] turn ${turn+1}/${settings.maxTurns}: request started; model=${model}; context=${limits.numCtx ?? "server-default"}; generation_limit=${generationBudget}; protocol=${protocol}\n`);
      const result = await postOllamaJson(process.env.AUTOHACK_OLLAMA_URL || "http://127.0.0.1:11434/api/chat", { model, stream: false, think: false, messages,
          ...(structured ? {format:actionSchema} : {tools:availableTools}),
          keep_alive:"10m",
          options: { num_predict:generationBudget,
            ...(limits.numCtx === undefined ? {} : {num_ctx:settings.numCtx}),
            ...(limits.numThreads === undefined ? {} : {num_thread:settings.numThreads}), temperature:0 } }, controller.signal) as { message?: Message; eval_count?: number; prompt_eval_count?: number; done_reason?: string };
      await appendFile(logFile, `[OLLAMA] turn ${turn+1}: response received in ${Date.now()-started}ms; prompt_tokens=${result.prompt_eval_count ?? "unknown"}; generated_tokens=${result.eval_count ?? "unknown"}\n`);
      let message = result.message;
      if (!message) throw new Error("Ollama returned no assistant message");
      if (structured) {
        let action;
        try {action = decodeAuditAction(message.content,!!limits.verifyPython);}
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
          role:"assistant",content:"",tool_calls:[{function:{name:action.action,arguments:{path:action.path,query:action.query,kind:action.answer}}}],
        };
      } else {messages.push(message);}
      if (message.content) await appendFile(logFile, message.content + "\n");
      if (!message.tool_calls?.length) {
        if (!successfulReads) {
          messages.push({role:"user",content:"No source file has been successfully read. Choose read_file now; a final answer is not accepted before a successful file read. /no_think"});
          continue;
        }
        if (!message.content?.trim()) throw new Error("Ollama returned empty final response");
        const feedback = limits.validateFinal?.(message.content);
        if (feedback) {
          await appendFile(logFile, "[FINAL_REJECTED] " + feedback + "\n");
          messages.push({role:"user",content:feedback + "\nRe-read the source when necessary. /no_think"});
          continue;
        }
        controller.signal.throwIfAborted();
        return message.content;
      }
      for (const call of message.tool_calls.slice(0, 8)) {
        controller.signal.throwIfAborted();
        await appendFile(logFile, "[TOOL] " + call.function.name + "\n");
        let output: string;
        let activityCount:number|undefined;
        const toolStarted=Date.now();
        await recordToolActivity(logFile,{phase:"started",tool:call.function.name,
          path:String(call.function.arguments?.path ?? ".").slice(0,500),
          query:String(call.function.arguments?.query ?? "").slice(0,120),
          kind:String(call.function.arguments?.kind ?? "").slice(0,80)});
        try {
          const name = call.function.name;
          const path = String(call.function.arguments?.path ?? ".");
          const full = await safePath(path);
          if((name === "verify_source" || name === "verify_python") && limits.verifyPython) {
            output=await limits.verifyPython(path,String(call.function.arguments?.query || ""),String(call.function.arguments?.kind || ""));
          } else if (name === "list_files") {
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
            activityCount=results.length;
            output = results.join("\n") || "No matches";
          } else if (name === "read_file") {
            const info = await stat(full);
            if (!info.isFile() || info.size > 256_000) throw new Error("Not a readable source file under 256KB");
            output = (await readFile(full, "utf8")).slice(0, 30_000);
            activityCount=output.length;
            successfulReads++;
            limits.onRead?.(relative(root,full).split(sep).join("/"));
            await appendFile(logFile, "[READ_OK] " + relative(root,full) + "\n");
          } else throw new Error("Unknown tool");
        } catch (error) {
          controller.signal.throwIfAborted();
          output = "Tool error: " + String(error);
        }
        let probeStatus:string|undefined;
        if(["verify_source","verify_python"].includes(call.function.name)){
          try {probeStatus=String(JSON.parse(output).status || "unknown").slice(0,100);}catch{}
        }
        await recordToolActivity(logFile,{phase:output.startsWith("Tool error:")?"failed":"completed",
          tool:call.function.name,path:String(call.function.arguments?.path ?? ".").slice(0,500),
          query:String(call.function.arguments?.query ?? "").slice(0,120),
          kind:String(call.function.arguments?.kind ?? "").slice(0,80),
          count:activityCount,status:probeStatus,durationMs:Date.now()-toolStarted,
          error:output.startsWith("Tool error:")?output.slice(0,600):undefined});
        messages.push(structured
          ? {role:"user",content:"TOOL_RESULT " + JSON.stringify({name:call.function.name,output:output.slice(0,30000)}) + "\nChoose the next JSON action. /no_think"}
          : { role:"tool", tool_name:call.function.name, content:output.slice(0,30000) });
      }
    }
    throw new Error(`Local audit reached its ${settings.maxTurns}-turn inspection limit`);
  } catch (error) {
    if(controller.signal.reason === "operator_cancelled")throw new Error("Local audit cancelled by operator");
    if (controller.signal.aborted)
      throw new Error(`Ollama audit timed out after ${Math.round(timeoutMs/1000)} seconds; check model load/CPU contention and the turn timing log`);
    throw error;
  } finally {
    limits.signal?.removeEventListener("abort", forwardCancellation);
    clearTimeout(timer);
    clearInterval(cancellationTimer);
    activeControllers.delete(controller);
  }
}
