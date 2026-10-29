import {modelProfile} from './model-profile';
import { InvestigationWorkflow } from "./investigation-workflow";
import {guidedSourceProbe} from './source-guided-probes';
import { postQwenAgentJson } from "./qwen-agent-transport";
import { AuditAllowance } from "./audit-allowance";
import { AuditNavigation } from "./audit-navigation";
import { SoliditySourceIndex } from "./solidity-source-index";
import { allocateAuditContext, compactAuditContext, auditCheckpoint, fitAuditToolOutput } from "./audit-context";
import { soliditySequenceSchema, soliditySequenceJsonSchema, soliditySequencePrompt, type SoliditySequence } from "./solidity-sequence";
import { readSourcePage, searchSourcePage, listSourcePage, pageOffset, type ReadSpan } from "./source-inspection";
import { postOllamaChat } from "../../core/src/ollama-chat";
import { auditActionSchema, auditProtocolPrompt, decodeAuditAction } from "./local-audit-protocol";
import { readFile, realpath, appendFile, writeFile, rename, mkdtemp } from "node:fs/promises";
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
  {type:"function",function:{name:"outline_solidity",description:"List Solidity declarations and exact IDs, without marking source inspected. Use before reading a Solidity function. On parse failure use read_file.",parameters:{type:"object",properties:{path:{type:"string"},offset:{type:"integer",minimum:0}},required:["path"]}}},
  {type:"function",function:{name:"read_solidity",description:"Read a Solidity function by outline ID in query, with bounded state/modifier/base context. Follow nextOffset; inspect unresolved context separately. On failure use read_file.",parameters:{type:"object",properties:{path:{type:"string"},query:{type:"string"},offset:{type:"integer",minimum:0}},required:["path","query"]}}},
  { type: "function", function: { name: "list_files", description: "List files in the authorized local audit workspace", parameters: { type: "object", properties: { path: { type: "string" }, offset: {type:"integer",minimum:0} }, required: ["path"] } } },
  { type: "function", function: { name: "search_files", description: "Search source files within path for a literal query; continue at nextOffset. complete=false means partial coverage", parameters: { type: "object", properties: { query: { type: "string" }, path:{type:"string"}, offset:{type:"integer",minimum:0} }, required: ["query"] } } },
  { type: "function", function: { name: "read_file", description: "Read a source file page; offset is a character offset. Continue at nextOffset until null", parameters: { type: "object", properties: { path: { type: "string" }, offset: {type:"integer",minimum:0} }, required: ["path"] } } },
];
export interface LocalAuditLimits {
  maxTurns: number;
  finalSchema?: Record<string,unknown>;
  productionWorkflow?: boolean;
  dynamicAllowance?: boolean;
  /** Pre-read only authorized source pages for read-only independent review. */
  prefetchReadOnly?: boolean;
  onAllowance?: (deadline:number) => Promise<void>;
  checkpointPath?: string;
  initialSourcePaths?: string[];
  initialSourceLocations?: Array<{path:string;offset:number}>;
  numPredict: number;
  numCtx: number;
  numThreads: number;
  /** Return corrective feedback to reject a final answer, or null to accept. */
  validateFinal?: (answer: string) => string | null | Promise<string | null>;
  /** Optional controller-owned state, refreshed each request and counted in context. */
  progressNote?: () => string;
  /** Optional finite task contract; JSON decoding and runtime validation both enforce it. */
  actionConstraints?: () => Partial<Record<"action"|"path"|"query"|"answer",string[]>>;
  signal?: AbortSignal;
  onRead?: (path:string, span:ReadSpan) => void;
  verifyPython?: (path:string,functionName:string,kind:string,sequence?:SoliditySequence) => Promise<string>;
}
export async function runLocalAudit(
  prompt: string, logFile: string, timeoutMs: number, cwd: string,
  model: string, systemPrompt?: string, limits: Partial<LocalAuditLimits> = {},
): Promise<string> {
  const settings = {maxTurns:20, numPredict:2048, numCtx:4096, numThreads:4, ...limits};
  for (const [key, low, high] of [["maxTurns",1,200],["numPredict",32,4096],["numCtx",1024,32768],["numThreads",1,32]] as const) {
    if (!Number.isSafeInteger(settings[key]) || settings[key] < low || settings[key] > high)
      throw new Error("Invalid local audit limit: " + key);
  }
  const protocol = process.env.LOCAL_OLLAMA_TOOL_PROTOCOL || "json";
  if (!["json","native"].includes(protocol)) throw new Error("LOCAL_OLLAMA_TOOL_PROTOCOL must be json or native");
  const structured = protocol === "json";
  if(limits.actionConstraints&&!structured)throw new Error("Task action constraints require JSON protocol");
  if(limits.productionWorkflow && (!structured || !limits.verifyPython || limits.actionConstraints))
    throw new Error("Production workflow requires JSON protocol, source probes and no fixture constraints");
  const workflow=limits.productionWorkflow ? new InvestigationWorkflow() : undefined;
  const adapter=process.env.LOCAL_MODEL_ADAPTER || 'ollama';
  if(!['ollama','qwen-agent'].includes(adapter))throw new Error('Unknown LOCAL_MODEL_ADAPTER');
  if(adapter==='qwen-agent'&&!structured)throw new Error('Qwen-Agent adapter requires JSON action protocol');
  let successfulReads = 0;
  let generationBudget = settings.numPredict;
  const root = await realpath(cwd);
  const controller = new AbortController();
  const solidityIndex = new SoliditySourceIndex(root,controller.signal);
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
  const allowance=new AuditAllowance(settings.maxTurns,auditStartedAt,timeoutMs,limits.dynamicAllowance);
  let timer = setTimeout(() => controller.abort(), timeoutMs);
  let usedTurns=0, finalAnswer:string|undefined, stoppingReason="Inspection interrupted";
  let emptyFinals=0;
  let invalidReviewFinals=0;
  let rejectedPlans=0;
  let consecutiveWorkflowRejections=0;
  let lastWorkflowRejection='';
  const sourceTotals=new Map<string,number>();
  const hypotheses:Array<{turn:number;path:string;statement:string}>=[];
  const renew=async(turn:number)=>{
    const extension=allowance.extend(turn,Date.now());
    if(extension) {
      clearTimeout(timer);timer=setTimeout(()=>controller.abort(),Math.max(1,allowance.deadline-Date.now()));
      await appendFile(logFile,"[ALLOWANCE_EXTENDED] "+JSON.stringify(extension)+"\n");
      await limits.onAllowance?.(allowance.deadline);
    }
  };
  const actionSchema = limits.verifyPython ? {...auditActionSchema,properties:{...auditActionSchema.properties,...(limits.finalSchema?{result:limits.finalSchema}:{}),sequence:soliditySequenceJsonSchema,
    action:{type:"string",enum:[...auditActionSchema.properties.action.enum,"verify_source","verify_python",...(workflow?["plan_probe","continue_inspection"]:[])]}}} : {...auditActionSchema,properties:{...auditActionSchema.properties,...(limits.finalSchema?{result:limits.finalSchema}:{})}};
  const probePrompt = limits.verifyPython ? "\nThe verify_source action invokes a fixed, isolated source function probe. Set path to a .py, .js, .mjs, .cjs, .java or .sol source file, query to its public/exported function name (Contract.function for Solidity), answer to html_reflection or path_construction. The function must take one string and return a string. JavaScript exports may be async. Java supports public Class.method with a String or byte[] argument and String or UTF-8 byte[] return value, either static or with a public no-argument constructor; only JDK and repository source dependencies are supported, without Maven/Gradle execution. Solidity requires a deployable zero-argument constructor and a public/external view or pure function compatible with installed solc 0.8.30; runs on an in-memory local EVM. Use returned observations honestly; they do not prove full exploitability. No arbitrary commands are available. " + soliditySequencePrompt : "";
  const availableTools = limits.verifyPython ? [...tools,{type:"function",function:{
    name:"verify_source",description:probePrompt,parameters:{type:"object",
      properties:{path:{type:"string"},query:{type:"string"},kind:{type:"string"},sequence:soliditySequenceJsonSchema},required:["path","query","kind"]},
  }}] : tools;
  let messages: Message[] = [
    { role: "system", content: (systemPrompt || "") + "\nPerform an offline source audit. Request exactly one tool call per response. Inspect actual files. Never invent findings or observations. No target network requests are available." + (limits.verifyPython ? probePrompt : " No source execution is available.") + (structured ? auditProtocolPrompt.replace(JSON.stringify(auditActionSchema),'Use action, path, query, answer; offset and sequence are optional. Example: {"action":"read_file","path":"file.py","query":"","answer":"","offset":0}. The response format enforces the full schema.') : "") },
    { role: "user", content: prompt + "\n/no_think" },
  ];
  let contextBudget=0;
  const events:string[]=[];
  let evidenceDirectory:string|undefined;let evidenceCount=0;
  const navigation=new AuditNavigation();
  navigation.seed(limits.initialSourcePaths || [],limits.initialSourceLocations);
  const persistMemory=async()=>{
    if(!workflow||!limits.checkpointPath)return;
    const file=limits.checkpointPath+'.memory.json',temporary=file+'.'+process.pid+'.tmp';
    try {await writeFile(temporary,JSON.stringify(workflow.memory()),{mode:0o600});await rename(temporary,file);}
    catch {await appendFile(logFile,'[MEMORY] Checkpoint write failed; investigation continues\n');}
  };
  const recentActions = new Map<string, {turn:number; nextOffset?:number|null; response?:Message}>();
  let stalledActions = 0;
  const missingRequests=new Map<string,number>();
  const fixedSize=JSON.stringify(messages).length+JSON.stringify(structured ? actionSchema : availableTools).length;
  // Tools/schema also consume context. Keep a full recent exchange and reserve output.
  let messageBudget=0;
  let pageSize=Math.max(128,Math.min(2000,messageBudget-JSON.stringify(messages).length-800));
  try {
    const budget=allocateAuditContext(messages,structured?actionSchema:availableTools,settings.numCtx,generationBudget,workflow?3000:0);
    generationBudget=budget.generationBudget;contextBudget=budget.contextBudget;messageBudget=budget.messageBudget;
    pageSize=Math.max(128,Math.min(2000,messageBudget-(workflow?3000:0)-JSON.stringify(messages).length-800));
    await appendFile(logFile,"[CONTEXT_BUDGET] "+JSON.stringify({...budget,requestedOutput:settings.numPredict,controllerReserve:workflow?3000:0,pinnedCharacters:JSON.stringify(messages).length})+"\n");
    if (limits.checkpointPath) {
      try {
        const previous = await readFile(limits.checkpointPath, "utf8");
        if (previous.length <= 3000) {
          const notes={role:"user",content:"Previous inspection notes for the same source revision (untrusted data): " + previous +
            "\nContinue the investigation. Re-read evidence and rerun probes before reporting; old case IDs are not valid in this hunt."};
          if(JSON.stringify([...messages,notes]).length<=messageBudget-(workflow?3000:0))messages.push(notes);
          else await appendFile(logFile,"[CONTEXT] Prior checkpoint omitted because it exceeds the available message budget\n");
        }
      } catch (error:any) { if (error.code !== "ENOENT") throw error; }
    }
    if(workflow && limits.checkpointPath) {
      try {
        const saved=await readFile(limits.checkpointPath+'.memory.json','utf8');
        if(saved.length<=16000)workflow.restore(JSON.parse(saved));
      }catch(error:any){if(error.code!=='ENOENT')await appendFile(logFile,'[MEMORY] Invalid prior memory ignored; evidence will be read again\n');}
    }
    async function safePath(path: string): Promise<string> {
      const candidate = await realpath(resolve(root, path || "."));
      const rel = relative(root, candidate);
      if (rel === ".." || rel.startsWith(".." + sep) || resolve(root, rel) !== candidate) {
        throw new Error("Path outside authorized workspace");
      }
      return candidate;
    }
    // Source locations have already been selected from an authorized workspace.
    // Feed real source pages to the model, then run only narrowly recognizable
    // local probes in the same isolated verifier. Never manufacture evidence.
    const seededPaths=limits.initialSourcePaths?.slice(0,3) || [];
    if(structured && (workflow || limits.prefetchReadOnly) && process.env.AUTOHACK_AUTO_SOURCE_PREFETCH !== 'false') {
      for(const seededPath of seededPaths) {
        const seeded=limits.initialSourceLocations?.find(item=>item.path===seededPath);
        const offset=seeded?.offset ?? 0;
        try {
          controller.signal.throwIfAborted();
          const full=await safePath(seededPath);
          const page=await readSourcePage(full,offset,pageSize);
          const action={action:'read_file',path:seededPath,query:'',answer:'',offset};
          const request:Message={role:'assistant',content:JSON.stringify(action)};
          const remaining=messageBudget-3000-JSON.stringify(messages.slice(2)).length;
          const fitted=fitAuditToolOutput(messages.slice(0,2),request,'read_file',JSON.stringify(page),remaining,true);
          const delivered=JSON.parse(fitted.output) as typeof page;
          if(!delivered.text || delivered.end<=delivered.start)throw new Error('No source text fits the initial context budget');
          messages.push(request,fitted.message);
          const path=relative(root,full).split(sep).join('/');
          sourceTotals.set(path,delivered.totalCharacters);
          allowance.read(path,delivered.start,delivered.end,0);
          workflow?.read(path);
          workflow?.observe(action,fitted.output);
          limits.onRead?.(path,{start:delivered.start,end:delivered.end});
          navigation.observe('read_file',path,offset,'',delivered);
          successfulReads++;
          recentActions.set(JSON.stringify(['read_file',path,offset,'']),{turn:-1,nextOffset:delivered.nextOffset,response:fitted.message});
          events.push(JSON.stringify({tool:'read_file',path,offset,end:delivered.end,nextOffset:delivered.nextOffset,status:'prefetched'}).slice(0,180));
          await appendFile(logFile,'[INITIAL_SOURCE_READ] '+JSON.stringify({path,start:delivered.start,end:delivered.end,nextOffset:delivered.nextOffset})+'\n');
          if(!workflow || process.env.AUTOHACK_GUIDED_SOURCE_PROBES==='false' || delivered.nextOffset!==null || offset!==0 || !limits.verifyPython)continue;
          const hint=guidedSourceProbe(path,delivered.text);
          if(!hint)continue;
          const planned={action:'plan_probe',path,query:hint.functionName,answer:hint.kind,hypothesis:hint.hypothesis};
          if(workflow.validate(planned as any))continue;
          workflow.plan(planned as any);
          let raw:string;
          try {raw=await limits.verifyPython(path,hint.functionName,hint.kind);}
          catch(error) {raw=JSON.stringify({status:'probe_failed',detail:String(error).slice(0,500),behavior_observed:false});}
          let result:any;
          try {result=JSON.parse(raw);}catch {result={status:'probe_failed',detail:'Verifier returned invalid JSON',behavior_observed:false};}
          // A failed or unsupported attempt is recorded as such, never as evidence
          // of a vulnerability or a passing result.
          if(typeof result!=='object'||result===null||Array.isArray(result))result={status:'probe_failed',detail:'Invalid verifier result'};
          evidenceDirectory ||= await mkdtemp(join(root,'.audit-evidence-'));
          const evidenceFile=join(evidenceDirectory,++evidenceCount+'.json');
          await writeFile(evidenceFile,JSON.stringify({path,function:hint.functionName,kind:hint.kind,result},null,2),{mode:0o600});
          result.evidenceFile=relative(root,evidenceFile).split(sep).join('/');
          const output=JSON.stringify(result);
          const verify={action:'verify_source',path,query:hint.functionName,answer:hint.kind};
          workflow.observe(verify as any,output);
          if(['behavior_observed','behavior_not_observed'].includes(result.status))
            allowance.probe(JSON.stringify([path,hint.functionName,hint.kind,undefined]),0);
          const record:Message={role:'assistant',content:JSON.stringify(verify)};
          const available=messageBudget-3000-JSON.stringify(messages.slice(2)).length;
          try {
            const response=fitAuditToolOutput(messages.slice(0,2),record,'verify_source',output,available,true);
            messages.push(record,response.message);
          }catch { // The evidence file remains available for a later explicit read.
            messages.push({role:'user',content:'An isolated probe was attempted for '+path+
              '; result status '+String(result.status)+'. Read '+result.evidenceFile+' for the full observation. /no_think'});
          }
          await appendFile(logFile,'[GUIDED_SOURCE_PROBE] '+JSON.stringify({path,function:hint.functionName,status:result.status,evidenceFile:result.evidenceFile})+'\n');
        } catch(error) {
          if(controller.signal.aborted)throw error;
          // Bad hints never authorize additional paths or imply a successful read.
          await appendFile(logFile,'[INITIAL_SOURCE_SKIPPED] '+String(error).slice(0,180)+'\n');
        }
      }
    }
    for (let turn = 0; turn < allowance.turns; turn++) {
      usedTurns=turn+1;
      controller.signal.throwIfAborted();
      // Keep stable history; send fresh controller state only with this request.
      let constraints=workflow ? await workflow.constraints() : limits.actionConstraints?.();
      if(workflow && consecutiveWorkflowRejections>=2 && constraints?.action?.includes('plan_probe')) {
        const otherActions=constraints.action.filter(name=>name!=='plan_probe');
        if(otherActions.length)constraints={...constraints,action:otherActions};
      }
      if(constraints && (JSON.stringify(constraints).length>3000 || Object.entries(constraints).some(([key,values])=>
        !["action","path","query","answer"].includes(key) || !Array.isArray(values) || !values.length || values.some(value=>typeof value!=="string"))))
        throw new Error("Invalid task action constraints");
      if(constraints?.action?.some(action=>!actionSchema.properties.action.enum.includes(action)))throw new Error("Task requested an unavailable action");
      let requestSchema:Record<string,any>=constraints ? {...actionSchema,properties:{...actionSchema.properties,
        ...Object.fromEntries(Object.entries(constraints).map(([key,values])=>[key,{type:"string",enum:values}]))}} : actionSchema;
      if(structured && limits.finalSchema && (emptyFinals>=1 || invalidReviewFinals>=2) &&
         (!constraints?.action || constraints.action.includes('final'))) {
        // Qwen3:4b sometimes returns a valid "final" action with both answer=""
        // and result omitted. Once that is observed, require the typed final
        // result in the NEXT model response rather than repeating an identical
        // unconstrained prompt. The semantic validator still checks every claim.
        const strictResult=JSON.parse(JSON.stringify(limits.finalSchema)) as Record<string,any>;
        // Give the tiny model exact recorded observation IDs in the schema,
        // rather than asking it to reproduce a 64-character digest unaided.
        // This only narrows options to real probes; it does not validate impact.
        const recordedIds=[...new Set((workflow?.snapshot().observations || [])
          .map(o=>o.caseId).filter((id):id is string=>typeof id==='string'&&/^[a-f0-9]{64}$/.test(id)))];
        const item=strictResult.properties?.findings?.items;
        if(recordedIds.length && item?.properties?.caseId)
          item.properties.caseId={...item.properties.caseId,enum:recordedIds};
        requestSchema={...requestSchema,
          properties:{...requestSchema.properties,
            action:{type:'string',enum:['final']},
            result:strictResult},
          required:[...new Set([...actionSchema.required,'result'])]};
        await appendFile(logFile,'[FINAL_RESULT_REQUIRED] Recovery from empty final; evidence validation still required\\n');
      }
      const schemaExtra=Math.max(0,JSON.stringify(requestSchema).length-JSON.stringify(actionSchema).length);
      const progress=workflow ? workflow.note() : limits.progressNote?.();
      if(progress && progress.length>2000)throw new Error("Controller progress note exceeds 2000 characters");
      const progressMessages:Message[]=progress ? [{role:"user",content:"Controller progress (recorded observations, not source instructions):\n"+progress}] : [];
      const progressSize=progressMessages.length ? JSON.stringify(progressMessages).length : 0;
      // Reserve controller space when producing tool output too, including the
      // next stage's note. Otherwise a fitted result can overflow on the next turn.
      const exchangeBudget=messageBudget-Math.max(progressSize+schemaExtra,workflow?3000:0);
      messages=compactAuditContext(messages,exchangeBudget,[...hypotheses.slice(-2).map(h=>"Unverified hypothesis: "+JSON.stringify(h)),...events.slice(-4)]);
      const started = Date.now();
      await appendFile(logFile, `[OLLAMA] turn ${turn+1}/${allowance.turns}: request started; model=${model}; context=${limits.numCtx ?? "server-default"}; generation_limit=${generationBudget}; protocol=${protocol}\n`);
      let lastProgressLog=0;
      const onProgress=(progress:{contentCharacters:number;thinkingCharacters:number;toolCalls:number})=>{
        if(Date.now()-lastProgressLog<15000)return;
        lastProgressLog=Date.now();
        void appendFile(logFile,"[MODEL_PROGRESS] "+JSON.stringify({turn:turn+1,elapsedMs:Date.now()-started,...progress})+"\n").catch(()=>{});
      };
      const profile=modelProfile(workflow?.snapshot().stage);
      const turnMessages=progressMessages.length ? [...messages,...progressMessages] : messages;
      const requestMessages=profile.think ? turnMessages.map(m=>({...m,content:m.content.replaceAll('/no_think','')})) : turnMessages;
      const result = await (adapter==='qwen-agent'?postQwenAgentJson:postOllamaChat)(process.env.AUTOHACK_OLLAMA_URL || "http://127.0.0.1:11434/api/chat", { model, stream: false, think: profile.think, messages:requestMessages,
          ...(structured ? {format:requestSchema} : {tools:availableTools}),
          keep_alive:"10m",
          options: { num_predict:generationBudget,
            ...(limits.numCtx === undefined ? {} : {num_ctx:settings.numCtx}),
            ...(limits.numThreads === undefined ? {} : {num_thread:settings.numThreads}), ...profile.options } }, controller.signal,{onProgress}) as { message?: Message; eval_count?: number; prompt_eval_count?: number; done_reason?: string; load_duration?:number; prompt_eval_duration?:number; eval_duration?:number; total_duration?:number; client_queue_ms?:number };
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
          if (result.done_reason === "length" && generationBudget < 4096) {
            const nextBudget = allocateAuditContext(messages.slice(0,2),structured?actionSchema:availableTools,settings.numCtx,Math.min(generationBudget*2,4096),workflow?3000:0).generationBudget;
            if(nextBudget<=generationBudget)throw new Error("Truncated action exceeds available output space; use a smaller action or sequence");
            const nextContext = Math.max(2000,(settings.numCtx-nextBudget-512)*3);
            if (fixedSize > nextContext) throw new Error("Truncated action needs more context for a larger output budget; increase numCtx");
            generationBudget = nextBudget;
            contextBudget = nextContext;
            messageBudget = contextBudget-JSON.stringify(structured ? actionSchema : availableTools).length;
            pageSize = Math.max(128,Math.min(2000,messageBudget-JSON.stringify(messages.slice(0,2)).length-800));
            await appendFile(logFile, `[OLLAMA] truncated JSON action; retrying with generation_limit=${generationBudget}\n`);
            continue;
          }
          throw new Error("Ollama did not return a valid read-only JSON action; no tool was executed");
        }
        if(constraints && Object.entries(constraints).some(([key,values])=>!values!.includes(action[key as "action"|"path"|"query"|"answer"]))) {
          await appendFile(logFile,"[ACTION_REJECTED] "+JSON.stringify({action,constraints})+"\n");
          messages.push({role:"user",content:"That action is not available in the current task stage. Use the current response schema and controller progress. No tool was executed. /no_think"});
          continue;
        }
        if(['plan_probe','verify_source','verify_python'].includes(action.action) &&
            action.answer!=='solidity_sequence' && action.sequence!==undefined) {
          // Normalize optional structured-output fields before validation,
          // planning and duplicate detection; they are unused by these probes.
          delete action.sequence;
          await appendFile(logFile,'[UNUSED_SEQUENCE_IGNORED] '+JSON.stringify({action:action.action,path:action.path,kind:action.answer})+'\n');
        }
        const workflowError=workflow?.validate(action);
        if(workflowError) {
          workflow!.feedback(workflowError);
          consecutiveWorkflowRejections=lastWorkflowRejection===workflowError?consecutiveWorkflowRejections+1:1;
          lastWorkflowRejection=workflowError;
          await appendFile(logFile,'[WORKFLOW_REJECTED] '+workflowError+'\n');
          messages.push({role:'user',content:'Controller rejected the last action: '+workflowError+
            '. Do not repeat the rejected probe. Inspect a new call site, use recorded evidence, or give an evidence-based final finding or incomplete outcome. /no_think'});
          continue;
        }
        consecutiveWorkflowRejections=0;
        lastWorkflowRejection='';
        if(action.action==='continue_inspection') {
          if(!workflow)throw new Error('Inspection decisions require production workflow');
          workflow.continueInspection(action);
          await persistMemory();
          await appendFile(logFile,'[INSPECTION_DECISION] '+JSON.stringify(action)+'\n');
          continue;
        }
        if(action.action==='plan_probe') {
          if(!workflow)throw new Error('Probe planning requires production workflow');
          if(action.answer==='solidity_sequence') {
            const sequence=soliditySequenceSchema.safeParse(action.sequence);
            if(!sequence.success) {
              const feedback='Provide a valid declarative Solidity sequence before planning its probe.';
              workflow.feedback(feedback);
              await appendFile(logFile,'[PLAN_REJECTED] '+feedback+'\n');
              messages.push({role:'user',content:feedback+' /no_think'});
              if(++rejectedPlans>=3)throw new Error('Repeated invalid Solidity probe plans');
              continue;
            }
          }
          if(JSON.stringify([...messages.slice(0,2),message]).length>exchangeBudget-1000) {
            const feedback='The proposed action is too large for one exchange. Plan a shorter probe sequence.';
            workflow.feedback(feedback);
            await appendFile(logFile,'[PLAN_REJECTED] '+feedback+'\n');
            messages.push({role:'user',content:feedback+' /no_think'});
            if(++rejectedPlans>=3)throw new Error('Repeated oversized probe plans');
            continue;
          }
          rejectedPlans=0;
          workflow.plan(action);
          await persistMemory();
          messages.push({role:"assistant",content:message.content});
          if(action.hypothesis)hypotheses.push({turn:turn+1,path:action.path,statement:action.hypothesis});
          await appendFile(logFile,'[PROBE_PLANNED] '+JSON.stringify(action)+'\n');
          continue;
        }
        if(action.hypothesis)hypotheses.push({turn:turn+1,path:action.path,statement:action.hypothesis});
        await appendFile(logFile,"[MODEL_ACTION] "+JSON.stringify(action)+"\n");
        messages.push({role:"assistant",content:message.content});
        message = action.action === "final" ? {role:"assistant",content:action.answer?.trim() || (action.result ? JSON.stringify(action.result) : "")} : {
          role:"assistant",content:"",tool_calls:[{function:{name:action.action,arguments:{path:action.path,query:action.query,kind:action.answer,offset:action.offset,sequence:action.sequence}}}],
        };
      } else {messages.push(message);}
      if (message.content) await appendFile(logFile, message.content + "\n");
      if (!message.tool_calls?.length) {
        if (!successfulReads) {
          const rejected=messages.at(-1)!;
          rejected.content="Final answer deferred: no successful source read.";
          messages.push(fitAuditToolOutput(messages.slice(0,2),rejected,"final_validation",
            "No source file has been successfully read. Choose read_file now; a final answer is not accepted before a successful file read. /no_think",exchangeBudget,true).message);
          continue;
        }
        if (!message.content?.trim()) {
          if(++emptyFinals>2)throw new Error("Ollama returned empty final response after two corrective retries");
          const rejected=messages.at(-1)!;
          rejected.content="Empty final answer rejected.";
          messages.push(fitAuditToolOutput(messages.slice(0,2),rejected,"final_validation",
            'Your final action had neither a nonempty answer nor a populated result object. Return a final action with the requested JSON either in answer as a JSON-encoded string OR in result as a JSON object, with answer set to "". Do not omit both. Use only recorded test evidence and actual inspected caller lines.',exchangeBudget,true).message);
          await appendFile(logFile,"[EMPTY_FINAL_RETRY] "+emptyFinals+"\n");
          continue;
        }
        // Only CONSECUTIVE empty finals count as a retry streak. A substantive
        // final rejected for source/schema reasons must not carry an old empty count.
        emptyFinals=0;
        const feedback = await limits.validateFinal?.(message.content);
        if (feedback) {
          // Escalate only repeated output-format failures; evidence-coverage failures
          // must remain free to request more source pages.
          invalidReviewFinals = !workflow && feedback.startsWith('Return the requested review JSON')
            ? invalidReviewFinals + 1 : 0;
          // Fresh evidence may be needed, but a rejected final must not reset
          // the inspection checkpoint and reopen an unconditional read loop.
          recentActions.clear();stalledActions=0;workflow?.finalRejected(feedback);
          const rejected=messages.at(-1)!;
          rejected.content="Previous final answer rejected; follow the validation feedback.";
          await appendFile(logFile, "[FINAL_REJECTED] " + feedback + "\n");
          messages.push(fitAuditToolOutput(messages.slice(0,2),rejected,"final_validation",feedback + "\nRe-read the source when necessary. /no_think",exchangeBudget,true).message);
          continue;
        }
        controller.signal.throwIfAborted();
        invalidReviewFinals=0;
        finalAnswer=message.content;stoppingReason="Validated final answer";
        return message.content;
      }
      for (const call of message.tool_calls.slice(0, 8)) {
        controller.signal.throwIfAborted();
        await appendFile(logFile, "[TOOL] " + call.function.name + "\n");
        let output: string;
        let fatalToolError:string|undefined;
        let activityCount:number|undefined;
        let completedActionKey:string|undefined;
        // Keep the executed request in history, but omit irrelevant model prose.
        const requestMessage=messages.at(-1)!;
        if(JSON.stringify(requestMessage).length>Math.max(200,Math.floor((messageBudget-JSON.stringify(messages.slice(0,2)).length)/3))) {
          requestMessage.content="Executed tool request; arguments retained in the action log.";
          if(requestMessage.tool_calls)requestMessage.tool_calls=[{function:{name:call.function.name,arguments:{}}}];
        }
        const fitOutput=(value:string)=>fitAuditToolOutput(messages.slice(0,2),requestMessage,call.function.name,value,exchangeBudget,structured);
        const toolStarted=Date.now();
        await recordToolActivity(logFile,{phase:"started",tool:call.function.name,
          path:String(call.function.arguments?.path ?? ".").slice(0,500),
          query:String(call.function.arguments?.query ?? "").slice(0,120),
          offset:call.function.arguments?.offset ?? 0,kind:String(call.function.arguments?.kind ?? "").slice(0,80)});
        try {
          const name = call.function.name;
          const path = String(call.function.arguments?.path ?? ".");
          const full = await safePath(path);
          let offset = pageOffset(call.function.arguments?.offset);
          const keyAt=(at:number)=>JSON.stringify([name,relative(root,full),at,String(call.function.arguments?.query ?? "")]);
          let actionKey = keyAt(offset);
          const inspection = ["read_file","list_files","search_files","outline_solidity","read_solidity"].includes(name);
          let previous = recentActions.get(actionKey);
          // An evicted tool result cannot be used as evidence by the model.
          // Honor a reread after compaction instead of penalizing our own prompt.
          if (previous?.response && !messages.includes(previous.response) &&
              (call.function.arguments?.offset !== undefined || previous.nextOffset == null)) {
            await appendFile(logFile,"[CONTEXT_REREAD] "+JSON.stringify({tool:name,path,offset})+"\n");
            previous=undefined;
          }
          // Recover a repeated page request using the tool's actual cursor.
          // Stay on the same action/path/query and record the effective span.
          if (inspection && previous?.nextOffset != null) {
            const requestedOffset=offset;
            while(previous?.nextOffset != null && previous.nextOffset>offset) {
              offset=previous.nextOffset;actionKey=keyAt(offset);previous=recentActions.get(actionKey);
            }
            call.function.arguments.offset=offset;
            await appendFile(logFile,"[PAGE_ADVANCE] "+JSON.stringify({tool:name,path,requestedOffset,offset})+"\n");
          }
          if(inspection && previous && turn-previous.turn<=8) {
            stalledActions++;
            const instruction = previous.nextOffset != null
              ? `Continue at offset ${previous.nextOffset}, or choose a different file/search.`
              : "This action is complete. Choose a different file/search or proceed to a supported test or evidence-based final answer.";
            await appendFile(logFile, "[NO_PROGRESS] " + JSON.stringify({action:name,path,offset,attempt:stalledActions}) + "\n");
            if(stalledActions>=3) {
              await recordToolActivity(logFile,{phase:"failed",tool:name,path,offset,error:"Repeated inspection actions without new evidence after corrective feedback"});
              throw new Error(`AUDIT_STALLED: repeated ${name} ${relative(root,full)} at offset ${offset}; the completed result is still in context; choose a different source or probe`);
            }
            throw new Error("Repeated inspection action was not executed. " + instruction + " " + navigation.hint());
          }
          await appendFile(logFile, "[ACTION] " + JSON.stringify({tool:name,path,offset,query:String(call.function.arguments?.query ?? "").slice(0,120)}) + "\n");
          if((name === "verify_source" || name === "verify_python") && limits.verifyPython) {
            const kind=String(call.function.arguments?.kind || "");
            const rawSequence=call.function.arguments?.sequence;
            if(kind!=="solidity_sequence" && rawSequence!==undefined)throw new Error("Sequence requires solidity_sequence kind");
            const sequence=kind==="solidity_sequence"?soliditySequenceSchema.parse(rawSequence):undefined;
            output=await limits.verifyPython(path,String(call.function.arguments?.query || ""),kind,sequence);
            try {
              const result=JSON.parse(output);
              if(workflow && output.length<=256000) {
                evidenceDirectory ||= await mkdtemp(join(root,'.audit-evidence-'));
                const evidenceFile=join(evidenceDirectory,++evidenceCount+'.json');
                await writeFile(evidenceFile,JSON.stringify({path,function:call.function.arguments?.query,kind,result},null,2),{mode:0o600});
                result.evidenceFile=relative(root,evidenceFile).split(sep).join('/');
                output=JSON.stringify(result);
              }
              if(["behavior_observed","behavior_not_observed"].includes(result.status))
                allowance.probe(JSON.stringify([relative(root,full),call.function.arguments?.query,kind,sequence]),turn+1);
            }catch{}
          } else if (name === "list_files") {
            output = JSON.stringify(await listSourcePage(full,offset));
          } else if (name === "search_files") {
            const result = await searchSourcePage(root,full,String(call.function.arguments?.query ?? ""),offset,controller.signal);
            activityCount=result.results.length;
            output=JSON.stringify(result);
          } else if (name === "outline_solidity" || name === "read_solidity") {
            const budget=Math.min(8000,Math.max(512,exchangeBudget-JSON.stringify(messages.slice(0,2)).length-JSON.stringify(message).length-800));
            if(name === "outline_solidity")output=JSON.stringify(await solidityIndex.outline(full,offset,budget));
            else {
              const result=await solidityIndex.context(full,String(call.function.arguments?.query || ""),offset,budget);
              output=fitOutput(JSON.stringify(result)).output;
              if(output.startsWith("Tool error:"))throw new Error("Indexed source exceeds available context; use read_file with a page offset");
              if(output.length>budget)throw new Error("Indexed context exceeds message budget; use read_file");
              for(const excerpt of result.excerpts) {
                allowance.read(excerpt.path,excerpt.start,excerpt.end,turn+1);
                successfulReads++;
                workflow?.read(excerpt.path);
                limits.onRead?.(excerpt.path,{start:excerpt.start,end:excerpt.end});
                await appendFile(logFile, "[READ_OK] " + excerpt.path + ` offset=${excerpt.start} end=${excerpt.end} indexed=true\n`);
              }
              activityCount=result.excerpts.reduce((n,e)=>n+e.text.length,0);
            }
          } else if (name === "read_file") {
            const rawPage = await readSourcePage(full,offset,pageSize);
            output = fitOutput(JSON.stringify(rawPage)).output;
            const page = JSON.parse(output) as typeof rawPage;
            sourceTotals.set(relative(root,full),page.totalCharacters);
            allowance.read(relative(root,full),page.start,page.end,turn+1);
            activityCount=page.text.length;
            successfulReads++;
            workflow?.read(relative(root,full).split(sep).join("/"));
            limits.onRead?.(relative(root,full).split(sep).join("/"),{start:page.start,end:page.end});
            await appendFile(logFile, "[READ_OK] " + relative(root,full) + ` offset=${page.start} end=${page.end} nextOffset=${page.nextOffset}\n`);
          } else throw new Error("Unknown tool");
          output=fitOutput(output).output;
          try {navigation.observe(name,relative(root,full).split(sep).join("/") || ".",offset,String(call.function.arguments?.query || ""),JSON.parse(output));}catch{}
          stalledActions=0;
          if(inspection) {
            let nextOffset:number|null|undefined;
            try {nextOffset=JSON.parse(output).nextOffset;}catch{}
            recentActions.set(actionKey,{turn,nextOffset});
            completedActionKey=actionKey;
            // Bounded by maxTurns; keep cursor chains after history compaction.
          }
        } catch (error) {
          controller.signal.throwIfAborted();
          if(error instanceof Error && error.message.startsWith("AUDIT_STALLED:"))throw error;
          output = "Tool error: " + String(error);
          if((error as any)?.code === "ENOENT") {
            const key=JSON.stringify([call.function.name,resolve(root,String(call.function.arguments?.path || "."))]);
            const count=(missingRequests.get(key)||0)+1;missingRequests.set(key,count);
            output+=" This path does not exist. Do not repeat it. Use list_files on a known directory or select an existing source hint. "+navigation.hint();
            if(count>=3)fatalToolError="AUDIT_STALLED: repeated missing source path after corrective feedback; inspection incomplete";
          }
        }
        workflow?.observe({action:call.function.name,path:String(call.function.arguments?.path || ''),
          query:String(call.function.arguments?.query || ''),answer:String(call.function.arguments?.kind || ''),
          sequence:call.function.arguments?.sequence},output);
        let probeStatus:string|undefined;
        if(["verify_source","verify_python"].includes(call.function.name)){
          try {probeStatus=String(JSON.parse(output).status || "unknown").slice(0,100);}catch{}
        }
        await recordToolActivity(logFile,{phase:output.startsWith("Tool error:")?"failed":"completed",
          tool:call.function.name,path:String(call.function.arguments?.path ?? ".").slice(0,500),
          query:String(call.function.arguments?.query ?? "").slice(0,120),
          offset:call.function.arguments?.offset ?? 0,kind:String(call.function.arguments?.kind ?? "").slice(0,80),
          ...(()=>{try {const page=JSON.parse(output);return {end:page.end,nextOffset:page.nextOffset};}catch{return {};}})(),
          count:activityCount,status:probeStatus,durationMs:Date.now()-toolStarted,
          ...(()=>{
            if(!["verify_source","verify_python"].includes(call.function.name))return {};
            try {
              const result=JSON.parse(output);
              return {result:output.length<=16000?result:{truncated:true,status:result.status,caseId:result.caseId,
                behavior_observed:result.behavior_observed,excerpt:output.slice(0,15000)}};
            }catch{return {result:{error:output.slice(0,16000)}};}
          })(),
          error:output.startsWith("Tool error:")?output.slice(0,600):undefined});
        if(fatalToolError)throw new Error(fatalToolError);
        let progress:any;try {progress=JSON.parse(output);}catch{}
        events.push(JSON.stringify({tool:call.function.name,path:String(call.function.arguments?.path || ""),query:String(call.function.arguments?.query || "").slice(0,60),offset:call.function.arguments?.offset,end:progress?.end,nextOffset:progress?.nextOffset,caseId:progress?.caseId,status:probeStatus || (output.startsWith("Tool error:")?"failed":"completed")}).slice(0,180));
        const fitted=fitOutput(output);
        const responseMessage=fitted.message;
        messages.push(responseMessage);
        if(completedActionKey)recentActions.get(completedActionKey)!.response=responseMessage;
        await persistMemory();
        await renew(turn+1);
      }
    }
    throw new Error(`Local audit reached its ${allowance.turns}-turn inspection limit`);
  } catch (error) {
    stoppingReason=error instanceof Error ? error.message : String(error);
    if(controller.signal.reason === "operator_cancelled")throw new Error("Local audit cancelled by operator");
    if (controller.signal.aborted)
      throw new Error(`Ollama audit timed out after ${Math.round((allowance.deadline-auditStartedAt)/1000)} seconds; check model load/CPU contention and the turn timing log`);
    throw error;
  } finally {
    if(controller.signal.aborted)stoppingReason=controller.signal.reason === "operator_cancelled" ? "Cancelled by operator" : "Audit deadline reached";
    await writeFile(logFile+".summary.json",JSON.stringify({startedAt:new Date(auditStartedAt).toISOString(),
      endedAt:new Date().toISOString(),model,adapter,profile:modelProfile().name,workflow:workflow?.snapshot(),turns:usedTurns,successfulReads,stoppingReason,finalAnswer,hypotheses,
      ...allowance.snapshot(),files:allowance.snapshot().files.map(file=>({...file,totalCharacters:sourceTotals.get(file.path),
        complete:sourceTotals.has(file.path)&&file.ranges.length===1&&file.ranges[0][0]===0&&file.ranges[0][1]===sourceTotals.get(file.path)}))},null,2),{mode:0o600}).catch(()=>{});
    if (limits.checkpointPath && workflow) {
      const destination=limits.checkpointPath+'.memory.json';
      const temporary=destination+'.'+process.pid+'.tmp';
      try {await writeFile(temporary,JSON.stringify(workflow.memory()),{mode:0o600});await rename(temporary,destination);}
      catch {await appendFile(logFile,'[MEMORY] Could not save investigation memory\n').catch(()=>{});}
    }
    if (limits.checkpointPath) {
      // Keep recent inspection evidence across bounded sessions, including failures.
      const checkpoint=JSON.parse(auditCheckpoint(events));
      checkpoint.navigation=navigation.snapshot();
      if(JSON.stringify(checkpoint).length>3000)checkpoint.navigation={next:navigation.snapshot().next.slice(0,1)};
      if(JSON.stringify(checkpoint).length>3000)delete checkpoint.navigation;
      const notes = JSON.stringify(checkpoint);
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
