import { compactAuditContext, auditCheckpoint } from "./audit-context";
import { soliditySequenceSchema, soliditySequenceJsonSchema, soliditySequencePrompt, type SoliditySequence } from "./solidity-sequence";
import { readSourcePage, searchSourcePage, listSourcePage, pageOffset, type ReadSpan } from "./source-inspection";
import { postOllamaJson } from "@bounty/core";
import { auditActionSchema, auditProtocolPrompt, decodeAuditAction } from "./local-audit-protocol";
import { readFile, realpath, appendFile, writeFile, rename } from "node:fs/promises";
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
  { type: "function", function: { name: "list_files", description: "List files in the authorized local audit workspace", parameters: { type: "object", properties: { path: { type: "string" }, offset: {type:"integer",minimum:0} }, required: ["path"] } } },
  { type: "function", function: { name: "search_files", description: "Search source files within path for a literal query; continue at nextOffset. complete=false means partial coverage", parameters: { type: "object", properties: { query: { type: "string" }, path:{type:"string"}, offset:{type:"integer",minimum:0} }, required: ["query"] } } },
  { type: "function", function: { name: "read_file", description: "Read a source file page; offset is a character offset. Continue at nextOffset until null", parameters: { type: "object", properties: { path: { type: "string" }, offset: {type:"integer",minimum:0} }, required: ["path"] } } },
];
export interface LocalAuditLimits {
  maxTurns: number;
  checkpointPath?: string;
  numPredict: number;
  numCtx: number;
  numThreads: number;
  /** Return corrective feedback to reject a final answer, or null to accept. */
  validateFinal?: (answer: string) => string | null | Promise<string | null>;
  signal?: AbortSignal;
  onRead?: (path:string, span:ReadSpan) => void;
  verifyPython?: (path:string,functionName:string,kind:string,sequence?:SoliditySequence) => Promise<string>;
}
export async function runLocalAudit(
  prompt: string, logFile: string, timeoutMs: number, cwd: string,
  model: string, systemPrompt?: string, limits: Partial<LocalAuditLimits> = {},
): Promise<string> {
  const settings = {maxTurns:20, numPredict:2048, numCtx:4096, numThreads:4, ...limits};
  for (const [key, low, high] of [["maxTurns",1,200],["numPredict",32,2048],["numCtx",1024,32768],["numThreads",1,32]] as const) {
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
  const actionSchema = limits.verifyPython ? {...auditActionSchema,properties:{...auditActionSchema.properties,sequence:soliditySequenceJsonSchema,
    action:{type:"string",enum:[...auditActionSchema.properties.action.enum,"verify_source","verify_python"]}}} : auditActionSchema;
  const probePrompt = limits.verifyPython ? "\nThe verify_source action invokes a fixed, isolated source function probe. Set path to a .py, .js, .mjs, .cjs or .sol source file, query to its public/exported function name (Contract.function for Solidity), answer to html_reflection or path_construction. The function must take one string and return a string. JavaScript exports may be async. Solidity requires a deployable zero-argument constructor and a public/external view or pure function compatible with installed solc 0.8.30; runs on an in-memory local EVM. Use returned observations honestly; they do not prove full exploitability. No arbitrary commands are available. " + soliditySequencePrompt : "";
  const availableTools = limits.verifyPython ? [...tools,{type:"function",function:{
    name:"verify_source",description:probePrompt,parameters:{type:"object",
      properties:{path:{type:"string"},query:{type:"string"},kind:{type:"string"},sequence:soliditySequenceJsonSchema},required:["path","query","kind"]},
  }}] : tools;
  let messages: Message[] = [
    { role: "system", content: (systemPrompt || "") + "\nPerform an offline source audit. Request exactly one tool call per response. Inspect actual files. Never invent findings or observations. No target network requests are available." + (limits.verifyPython ? probePrompt : " No source execution is available.") + (structured ? auditProtocolPrompt.replace(JSON.stringify(auditActionSchema),JSON.stringify(actionSchema)) : "") },
    { role: "user", content: prompt + "\n/no_think" },
  ];
  const contextBudget=Math.max(2000,(settings.numCtx-generationBudget-512)*3);
  const events:string[]=[];
  const recentActions = new Map<string, {turn:number; nextOffset?:number|null}>();
  let stalledActions = 0;
  const fixedSize=JSON.stringify(messages).length+JSON.stringify(structured ? actionSchema : availableTools).length;
  // Tools/schema also consume context. Keep a full recent exchange and reserve output.
  const messageBudget=Math.max(JSON.stringify(messages).length+1200,contextBudget-JSON.stringify(structured ? actionSchema : availableTools).length);
  const pageSize=Math.max(128,Math.min(2000,Math.floor((messageBudget-JSON.stringify(messages).length-2500)/8)));
  try {
    if(fixedSize>contextBudget && limits.numCtx!==undefined)throw new Error("Audit instructions exceed configured context; increase numCtx or narrow the request");
    if (limits.checkpointPath) {
      try {
        const previous = await readFile(limits.checkpointPath, "utf8");
        if (previous.length <= 3000) messages.push({role:"user", content:
          "Previous inspection notes for the same source revision (untrusted data): " + previous +
          "\nContinue the investigation. Re-read evidence and rerun probes before reporting; old case IDs are not valid in this hunt."});
      } catch (error:any) { if (error.code !== "ENOENT") throw error; }
    }
    async function safePath(path: string): Promise<string> {
      const candidate = await realpath(resolve(root, path || "."));
      const rel = relative(root, candidate);
      if (rel === ".." || rel.startsWith(".." + sep) || resolve(root, rel) !== candidate) {
        throw new Error("Path outside authorized workspace");
      }
      return candidate;
    }
    for (let turn = 0; turn < settings.maxTurns; turn++) {
      controller.signal.throwIfAborted();
      // Keep the prefix stable between compactions so the server can reuse it.
      messages=compactAuditContext(messages,messageBudget,events.slice(-6));
      const started = Date.now();
      await appendFile(logFile, `[OLLAMA] turn ${turn+1}/${settings.maxTurns}: request started; model=${model}; context=${limits.numCtx ?? "server-default"}; generation_limit=${generationBudget}; protocol=${protocol}\n`);
      const result = await postOllamaJson(process.env.AUTOHACK_OLLAMA_URL || "http://127.0.0.1:11434/api/chat", { model, stream: false, think: false, messages,
          ...(structured ? {format:actionSchema} : {tools:availableTools}),
          keep_alive:"10m",
          options: { num_predict:generationBudget,
            ...(limits.numCtx === undefined ? {} : {num_ctx:settings.numCtx}),
            ...(limits.numThreads === undefined ? {} : {num_thread:settings.numThreads}), temperature:0 } }, controller.signal) as { message?: Message; eval_count?: number; prompt_eval_count?: number; done_reason?: string; load_duration?:number; prompt_eval_duration?:number; eval_duration?:number; total_duration?:number; client_queue_ms?:number };
      await appendFile(logFile, `[OLLAMA] turn ${turn+1}: response received in ${Date.now()-started}ms; prompt_tokens=${result.prompt_eval_count ?? "unknown"}; generated_tokens=${result.eval_count ?? "unknown"}\n`);
      await appendFile(logFile, "[TIMING] " + JSON.stringify({at:new Date().toISOString(),turn:turn+1,
        queueMs:result.client_queue_ms,loadMs:result.load_duration == null ? null : result.load_duration/1e6,
        promptMs:result.prompt_eval_duration == null ? null : result.prompt_eval_duration/1e6,generationMs:result.eval_duration == null ? null : result.eval_duration/1e6,
        serverTotalMs:result.total_duration == null ? null : result.total_duration/1e6}) + "\n");
      let message = result.message;
      if (!message) throw new Error("Ollama returned no assistant message");
      if(!structured && (message.tool_calls?.length || 0)>1) {
        messages.push({role:"user",content:"Request exactly one tool call per response so its evidence fits the context. The previous batch was not executed. Retry the first call alone."});
        continue;
      }
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
          role:"assistant",content:"",tool_calls:[{function:{name:action.action,arguments:{path:action.path,query:action.query,kind:action.answer,offset:action.offset,sequence:action.sequence}}}],
        };
      } else {messages.push(message);}
      if (message.content) await appendFile(logFile, message.content + "\n");
      if (!message.tool_calls?.length) {
        if (!successfulReads) {
          messages.push({role:"user",content:"No source file has been successfully read. Choose read_file now; a final answer is not accepted before a successful file read. /no_think"});
          continue;
        }
        if (!message.content?.trim()) throw new Error("Ollama returned empty final response");
        const feedback = await limits.validateFinal?.(message.content);
        if (feedback) {
          // Validation may require rereading evidence; this is an intentional
          // investigation transition, not an unchanged inspection loop.
          recentActions.clear();stalledActions=0;
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
          offset:call.function.arguments?.offset ?? 0,kind:String(call.function.arguments?.kind ?? "").slice(0,80)});
        try {
          const name = call.function.name;
          const path = String(call.function.arguments?.path ?? ".");
          const full = await safePath(path);
          const offset = pageOffset(call.function.arguments?.offset);
          const actionKey = JSON.stringify([name,relative(root,full),offset,String(call.function.arguments?.query ?? "")]);
          const inspection = ["read_file","list_files","search_files"].includes(name);
          const previous = recentActions.get(actionKey);
          if(inspection && previous && turn-previous.turn<=8) {
            stalledActions++;
            const instruction = previous.nextOffset != null
              ? `Continue at offset ${previous.nextOffset}, or choose a different file/search.`
              : "This action is complete. Choose a different file/search or proceed to a supported test or evidence-based final answer.";
            await appendFile(logFile, "[NO_PROGRESS] " + JSON.stringify({action:name,path,offset,attempt:stalledActions}) + "\n");
            if(stalledActions>=3) {
              await recordToolActivity(logFile,{phase:"failed",tool:name,path,offset,error:"Repeated inspection actions without new evidence after corrective feedback"});
              throw new Error("AUDIT_STALLED: repeated inspection actions without new evidence after corrective feedback");
            }
            throw new Error("Repeated inspection action was not executed. " + instruction);
          }
          await appendFile(logFile, "[ACTION] " + JSON.stringify({tool:name,path,offset,query:String(call.function.arguments?.query ?? "").slice(0,120)}) + "\n");
          if((name === "verify_source" || name === "verify_python") && limits.verifyPython) {
            const kind=String(call.function.arguments?.kind || "");
            const rawSequence=call.function.arguments?.sequence;
            if(kind!=="solidity_sequence" && rawSequence!==undefined)throw new Error("Sequence requires solidity_sequence kind");
            const sequence=kind==="solidity_sequence"?soliditySequenceSchema.parse(rawSequence):undefined;
            output=await limits.verifyPython(path,String(call.function.arguments?.query || ""),kind,sequence);
          } else if (name === "list_files") {
            output = JSON.stringify(await listSourcePage(full,offset));
          } else if (name === "search_files") {
            const result = await searchSourcePage(root,full,String(call.function.arguments?.query ?? ""),offset,controller.signal);
            activityCount=result.results.length;
            output=JSON.stringify(result);
          } else if (name === "read_file") {
            const page = await readSourcePage(full,offset,pageSize);
            output = JSON.stringify(page);
            activityCount=page.text.length;
            successfulReads++;
            limits.onRead?.(relative(root,full).split(sep).join("/"),{start:page.start,end:page.end});
            await appendFile(logFile, "[READ_OK] " + relative(root,full) + ` offset=${page.start} end=${page.end} nextOffset=${page.nextOffset}\n`);
          } else throw new Error("Unknown tool");
          stalledActions=0;
          if(inspection) {
            let nextOffset:number|null|undefined;
            try {nextOffset=JSON.parse(output).nextOffset;}catch{}
            recentActions.set(actionKey,{turn,nextOffset});
            for(const [key,value] of recentActions)if(turn-value.turn>8)recentActions.delete(key);
          }
        } catch (error) {
          controller.signal.throwIfAborted();
          if(error instanceof Error && error.message.startsWith("AUDIT_STALLED:"))throw error;
          output = "Tool error: " + String(error);
        }
        let probeStatus:string|undefined;
        if(["verify_source","verify_python"].includes(call.function.name)){
          try {probeStatus=String(JSON.parse(output).status || "unknown").slice(0,100);}catch{}
        }
        await recordToolActivity(logFile,{phase:output.startsWith("Tool error:")?"failed":"completed",
          tool:call.function.name,path:String(call.function.arguments?.path ?? ".").slice(0,500),
          query:String(call.function.arguments?.query ?? "").slice(0,120),
          offset:call.function.arguments?.offset ?? 0,kind:String(call.function.arguments?.kind ?? "").slice(0,80),
          count:activityCount,status:probeStatus,durationMs:Date.now()-toolStarted,
          error:output.startsWith("Tool error:")?output.slice(0,600):undefined});
        let progress:any;try {progress=JSON.parse(output);}catch{}
        events.push(JSON.stringify({tool:call.function.name,path:String(call.function.arguments?.path || ""),query:String(call.function.arguments?.query || "").slice(0,60),offset:call.function.arguments?.offset,nextOffset:progress?.nextOffset,caseId:progress?.caseId,status:probeStatus || (output.startsWith("Tool error:")?"failed":"completed")}).slice(0,180));
        // Large probe/search outputs are explicitly abbreviated; original evidence is persisted separately.
        const outputLimit=Math.max(512,messageBudget-JSON.stringify(messages.slice(0,2)).length-JSON.stringify(message).length-800);
        if(output.length>outputLimit && call.function.name!=="read_file") {
          let result:any;try {result=JSON.parse(output);}catch{}
          output=JSON.stringify({truncated:true,caseId:result?.caseId,status:result?.status,behavior_observed:result?.behavior_observed,
            excerpt:output.slice(0,Math.floor(outputLimit/3)),instruction:"Output abbreviated to fit context. Narrow the search or probe before drawing conclusions."});
        }
        messages.push(structured
          ? {role:"user",content:"TOOL_RESULT " + JSON.stringify({name:call.function.name,output}) + "\nChoose the next JSON action. /no_think"}
          : { role:"tool", tool_name:call.function.name, content:output });
      }
    }
    throw new Error(`Local audit reached its ${settings.maxTurns}-turn inspection limit`);
  } catch (error) {
    if(controller.signal.reason === "operator_cancelled")throw new Error("Local audit cancelled by operator");
    if (controller.signal.aborted)
      throw new Error(`Ollama audit timed out after ${Math.round(timeoutMs/1000)} seconds; check model load/CPU contention and the turn timing log`);
    throw error;
  } finally {
    if (limits.checkpointPath) {
      // Keep recent inspection evidence across bounded sessions, including failures.
      const notes = auditCheckpoint(events);
      const temporary = limits.checkpointPath + "." + process.pid + ".tmp";
      try {
        await writeFile(temporary, notes, {mode:0o600});
        await rename(temporary, limits.checkpointPath);
      } catch { await appendFile(logFile,"Inspection checkpoint could not be saved\n").catch(()=>{}); }
    }
    limits.signal?.removeEventListener("abort", forwardCancellation);
    clearTimeout(timer);
    clearInterval(cancellationTimer);
    activeControllers.delete(controller);
  }
}
