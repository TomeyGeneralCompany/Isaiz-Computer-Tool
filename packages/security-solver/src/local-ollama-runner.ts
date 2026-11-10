import {ControllerEvidenceArchive} from './controller-evidence-archive';
import {modelProfile} from './model-profile';
import {normalizeForcedOutlineCursor} from './outline-cursor';
import {z} from "zod";
import {javaSequenceSchema, type JavaSequence} from "./java-sequence";
import {polyglotSequenceSchema,type PolyglotSequence} from "./polyglot-sequence";
import {sourceGroundedSolidityProbe,sourceGroundedSolidityProbes,traceProjectErc1155Callers} from './controller-solidity-security-probes';
import {privilegedRoleMutationCandidate} from './solidity-security-candidates';
import {rankTracedSourceCandidates} from './controller-source-candidates';
import { InvestigationWorkflow } from "./investigation-workflow";
import {guidedProbeAcrossSourceChain,guidedSourceProbe} from './source-guided-probes';
import {controllerPolyglotPlan,controllerPolyglotPlans,canonicalControllerPolyglotIntent} from './controller-polyglot-plan';
import {declaredProbeTarget, sourceDeclarationHints, supportedJavaProbeHints, javaProbeSelectorCompatible, probeChoices} from './probe-target-validation';
import { postQwenAgentJson } from "./qwen-agent-transport";
import { AuditAllowance } from "./audit-allowance";
import { AuditNavigation } from "./audit-navigation";
import {controllerOwnedNextAction,canonicalSourceNavigationAction} from "./controller-next-action";
import { SoliditySourceIndex } from "./solidity-source-index";
import { allocateAuditContext, compactAuditContext, auditCheckpoint, fitAuditToolOutput } from "./audit-context";
import { soliditySequenceSchema, soliditySequenceJsonSchema, type SoliditySequence } from "./solidity-sequence";
import { readSourcePage, searchSourcePage, listSourcePage, pageOffset, type ReadSpan } from "./source-inspection";
import { postOllamaChat } from "../../core/src/ollama-chat";
import { auditActionSchema, auditProtocolPrompt, decodeAuditAction } from "./local-audit-protocol";
import { readFile, realpath, appendFile, writeFile, rename, mkdtemp } from "node:fs/promises";
import { resolve, relative, sep, join } from "node:path";
import { createHash } from "node:crypto";

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
  /** Production acquisition explicitly enables controller-owned indexed scheduling. */
  controllerIndex?: boolean;
  /** An explicit task contract may require one specific local probe kind. */
  requiredProbeKind?: 'html_reflection'|'path_construction';
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
  /** Controller-generated, source-backed report packet supplied only when a
   * proposed final is rejected. Never changes the investigation page budget.
   */
  finalEvidencePacket?: () => string | Promise<string>;
  /** Recover an independently validated conservative final after required source
   * pages have been read, without another unnecessary model generation.
   * The caller must enforce all domain-specific evidence requirements. */
  recoverFinal?: () => string | null | Promise<string | null>;
  /** Optional controller-owned state, refreshed each request and counted in context. */
  progressNote?: () => string;
  /** Optional finite task contract; JSON decoding and runtime validation both enforce it. */
  actionConstraints?: () => Partial<Record<"action"|"path"|"query"|"answer",string[]>>;
  signal?: AbortSignal;
  onRead?: (path:string, span:ReadSpan) => void;
  /** Trusted controller source analysis: exact caller path for a reproduced case.
   * No model text can create or change this routing decision. */
  onVerifiedCase?: (caseId:string,path:string,selector:string,kind:string) =>
    Promise<{callers:string[];promoted?:{caseId:string;path:string;selector:string;kind:string}}|null>;
  verifyPython?: (path:string,functionName:string,kind:string,sequence?:SoliditySequence | JavaSequence | PolyglotSequence) => Promise<string>;
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
  let rejectedRequiredProbeFinals = 0;
  let controllerAutoReadCount = 0;
  let indexedLastProgressKey = '';
  let indexedSyntheticStalls = 0;
  const controllerStalledPaths=new Set<string>();
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
  const allowance=new AuditAllowance(settings.maxTurns,auditStartedAt,timeoutMs,limits.dynamicAllowance,640,limits.productionWorkflow === true && limits.dynamicAllowance === true);
  let timer = setTimeout(() => controller.abort(), timeoutMs);
  let usedTurns=0, finalAnswer:string|undefined, stoppingReason="Inspection interrupted";
  let emptyFinals=0;
  let emptyFinalRecoveryCycles=0;
  let requireInvestigationAfterEmpty=false;
  let invalidReviewFinals=0;
  // Preserve the verifier's facts independently of Qwen's compacted chat.
  let lastRejectedConclusion='';
  let repeatedRejectedConclusions=0;
  let postProbeRecoveryReads=0;
  // Repeated completed-page requests must change the next model action,
  // not merely receive another warning that Qwen can ignore.
  let blockCompletedReadsUntil=0;

  let rejectedPlans=0;
  let consecutiveWorkflowRejections=0;
  let unsupportedFinalRejections=0;
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
  const actionSchema = limits.verifyPython ? {...auditActionSchema,properties:{...auditActionSchema.properties,...(limits.finalSchema?{result:limits.finalSchema}:{}),sequence:{type:"object",properties:{
      constructorArgs:{type:"array",items:{type:"string"}},
      constructor:{type:"array",items:{}},
      steps:{type:"array",items:{type:"object",properties:{
        operation:{type:"string"},function:{type:"string"},method:{type:"string"},
        args:{type:"array",items:{}},sender:{type:"integer"},
        expect:{type:"string"},expected:{},valueWei:{type:"string"}
      }}}
    },required:["steps"]},
    action:{type:"string",enum:[...auditActionSchema.properties.action.enum,"verify_source","verify_python",...(workflow?["plan_probe","probe_intent","continue_inspection"]:[])]}}} : {...auditActionSchema,properties:{...auditActionSchema.properties,...(limits.finalSchema?{result:limits.finalSchema}:{})}};
  const probePrompt = limits.verifyPython ? "\\nUse probe_intent with inspected path, exact query (or blank for a unique candidate), supported answer kind, hypothesis and optional sequence. The controller validates and executes the accepted request. Python top-level and exported JavaScript functions require one string input and string output. Java text probes support one text/byte argument. For Python and JavaScript stateful behavior, use python_sequence or javascript_sequence with a declarative factory (optional), constructor array and at least two steps {method,args,expected?}, all on the same object; state observations are not security findings. For Java methods with primitive/String args, use java_sequence with constructor args and method steps; calls share one instance. Do not use html_reflection for Java numeric/state methods. Solidity accepts state-changing sends and read assertions in a local EVM. Do not invent method names, expected values, or findings. " : "";
  const availableTools = limits.verifyPython ? [...tools,{type:"function",function:{
    name:"verify_source",description:probePrompt,parameters:{type:"object",
      properties:{path:{type:"string"},query:{type:"string"},kind:{type:"string"},sequence:soliditySequenceJsonSchema},required:["path","query","kind"]},
  }}] : tools;
  const recoveredFindingProbes=new Set<string>();
  const finalCallerRecoveries=new Set<string>();
  let messages: Message[] = [
    { role: "system", content: (systemPrompt || "") + "\nPerform an offline source audit. Request exactly one tool call per response. Inspect actual files. Never invent findings or observations. No target network requests are available." + (limits.verifyPython ? probePrompt : " No source execution is available.") + (structured ? auditProtocolPrompt.replace(JSON.stringify(auditActionSchema),'Use action, path, query, answer; offset and sequence are optional. Example: {"action":"read_file","path":"file.py","query":"","answer":"","offset":0}. The response format enforces the full schema.') : "") },
    { role: "user", content: prompt + "\n/no_think" },
  ];
  let contextBudget=0;
  const events:string[]=[];
  let evidenceDirectory:string|undefined;let evidenceCount=0;
  const controllerArchive=workflow?new ControllerEvidenceArchive(logFile+'.evidence.jsonl'):null;
  const navigation=new AuditNavigation();
  navigation.seed(limits.initialSourcePaths || [],limits.initialSourceLocations);
  const persistMemory=async()=>{
    if(!workflow||!limits.checkpointPath)return;
    const file=limits.checkpointPath+'.memory.json',temporary=file+'.'+process.pid+'.tmp';
    try {await writeFile(temporary,JSON.stringify(workflow.memory()),{mode:0o600});await rename(temporary,file);}
    catch {await appendFile(logFile,'[MEMORY] Checkpoint write failed; investigation continues\n');}
  };
  // Durable cold tier: model-context eviction never discards the original exchange.
  // This archive is not a verified finding; evidenceFile and reviewer gates remain authoritative.
  const archivedExchangeHashes=new Set<string>();
  const archiveEvictedExchanges=async(before:Message[],after:Message[])=>{
    if(!workflow)return;
    const retained=new Set(after.slice(2));
    const evicted=before.slice(2).filter(m=>!retained.has(m));
    if(!evicted.length)return;
    const entries=evicted.map(m=>{
      const digest=createHash('sha256').update(JSON.stringify(m)).digest('hex');
      return {digest,message:m};
    }).filter(e=>!archivedExchangeHashes.has(e.digest));
    if(!entries.length)return;
    // Append-only JSONL alongside the audit log; never feed the whole archive to Qwen.
    await appendFile(logFile+'.exchanges.jsonl',entries.map(e=>JSON.stringify({version:1,sha256:e.digest,exchange:e.message})).join('\n')+'\n');
    for(const entry of entries)await controllerArchive?.append('exchange',entry.message);
    for(const e of entries)archivedExchangeHashes.add(e.digest);
    await appendFile(logFile,'[CONTEXT_ARCHIVED] '+JSON.stringify({messages:entries.length,archive:logFile+'.exchanges.jsonl'})+'\n');
  };
  const recentActions = new Map<string, {turn:number; nextOffset?:number|null; response?:Message}>();
  // Independent of context compaction: an evicted source page is not an unread page.
  const sourceReadCounts = new Map<string,number>();
  // Completed pages survive model-context eviction and unreliable offset replay.
  const terminalReadPages = new Map<string,{offset:number;response?:Message}>();
  const terminalPageRecoveries = new Set<string>();
  const probeDispositions = new Map<string,{status:string;reason:string}>();
  const probeIdentity=(path:string,selector:string,kind:string)=>JSON.stringify([path,selector,kind]);
  const unresolvedProbes=()=>[...probeDispositions.entries()].filter(([,v])=>v.status==='selected');
  const recordProbeDisposition=async(path:string,selector:string,kind:string,status:string,reason:string)=>{
    const key=probeIdentity(path,selector,kind);
    const previous=probeDispositions.get(key);
    if(previous?.status===status && previous.reason===reason)return;
    probeDispositions.set(key,{status,reason});
    const record={path,selector,kind,status,reason};
    await appendFile(logFile,'[CONTROLLER_PROBE_DISPOSITION] '+JSON.stringify(record)+'\n');
    await controllerArchive?.append('decision',record);
  };
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
    /** Resolve a verified source-root alias for read-only navigation only.
     * Structured JSON actions and native tool calls use the same resolver.
     * No speculative path rewriting for probes, writes or external paths.
     */
    async function canonicalSourceReadPath(path:string):Promise<string> {
      const readOnlyCandidate = path !== "." && path !== "" && !path.startsWith("/") &&
        !path.startsWith("source/") && path !== "source" &&
        !path.split(/[\\/]/).some(segment=>segment===".." || segment===".") &&
        !path.includes("\\");
      if (!readOnlyCandidate) return path;
      try {
        await safePath(path);
        return path;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") return path;
        const aliased = "source/"+path;
        try {
          await safePath(aliased);
          await appendFile(logFile,"[CONTROLLER_SOURCE_ALIAS] "+JSON.stringify({requested:path,resolved:aliased})+"\n");
          return aliased;
        } catch {return path;}
      }
    }
    // Controller-owned bounded scan of authorized Solidity source. It is a
    // candidate priority signal, not an exploitability verdict. Qwen cannot
    // change the source-derived role, selector or read order.
    const privilegedSolidityCandidates=new Map<string,{selector:string;role:string;method:string}>();
    const accessibleSoliditySources=new Map<string,string>();
    for(const path of [...new Set(limits.initialSourcePaths||[])].slice(0,200)){
      if(!path.startsWith('source-')||!path.endsWith('.sol'))continue;
      try{
        const content=await readFile(await safePath(path),'utf8');
        if(content.length<=256000)accessibleSoliditySources.set(path,content);
      }catch{}
    }
    // Trace project-owned ERC1155 call sites BEFORE considering inherited
    // library entries. A call graph hint directs source reading only; it
    // never authorizes a transaction without a source-proven assertion.
    const projectErc1155Callers=[...accessibleSoliditySources.entries()].flatMap(
      ([path,source])=>traceProjectErc1155Callers(path,source));
    const projectErc1155CallerPaths=[...new Set(projectErc1155Callers.map(item=>item.path))];
    if(projectErc1155Callers.length)
      await appendFile(logFile,'[CONTROLLER_ERC1155_PROJECT_CALLERS] '+
        JSON.stringify(projectErc1155Callers.slice(0,40))+'\n');
    const SolidityCode=[...accessibleSoliditySources.values()];
    for(const [path,content] of accessibleSoliditySources){
      const risk=privilegedRoleMutationCandidate(path,content,SolidityCode);
      if(risk)privilegedSolidityCandidates.set(path,risk);
    }
    if(privilegedSolidityCandidates.size)await appendFile(logFile,'[CONTROLLER_SOLIDITY_ROLE_CANDIDATES] '+
      JSON.stringify([...privilegedSolidityCandidates].map(([path,r])=>({path,selector:r.selector,role:r.role})))+'\n');
    const tracedCandidates=workflow && process.env.LOCAL_CONTROLLER_OWNED_ACTIONS!=='false'
      ? await rankTracedSourceCandidates(root,limits.initialSourcePaths||[]) : [];
    if(tracedCandidates.length)await appendFile(logFile,'[CONTROLLER_TRACED_SOURCE_CANDIDATES] '+
      JSON.stringify(tracedCandidates.slice(0,8).map(c=>({path:c.path,selector:c.selector,score:c.score,chain:c.chain})))+'\n');
    // Source locations have already been selected from an authorized workspace.
    // Feed real source pages to the model, then run only narrowly recognizable
    // local probes in the same isolated verifier. Never manufacture evidence.
    // Audit policy is an authorized controller-owned document, not a model
    // exploration target. Register every actual page as read and archive its
    // content before the model can report findings; otherwise a paginated
    // policy can consume the entire turn budget after a verified probe.
    if(structured && limits.initialSourcePaths?.includes('audit-policy.txt') &&
        process.env.AUTOHACK_AUTO_SOURCE_PREFETCH !== 'false') {
      try {
        const policyPath=await safePath('audit-policy.txt');
        let policyOffset=0;
        for(let policyPage=0;policyPage<10000;policyPage++) {
          controller.signal.throwIfAborted();
          const page=await readSourcePage(policyPath,policyOffset,pageSize);
          if(page.end<=policyOffset && page.nextOffset!==null)
            throw new Error('Audit policy paging made no forward progress');
          limits.onRead?.('audit-policy.txt',{start:page.start,end:page.end});
          allowance.read('audit-policy.txt',page.start,page.end,0);
          navigation.observe('read_file','audit-policy.txt',policyOffset,'',page);
          const id=await controllerArchive?.append('source',{
            path:'audit-policy.txt',start:page.start,end:page.end,
            content:page.text,nextOffset:page.nextOffset},{source:'audit-policy.txt'});
          if(id)workflow?.recordEvidence(id);
          if(page.nextOffset===null)break;
          policyOffset=page.nextOffset;
          if(policyPage===9999)throw new Error('Audit policy exceeds controller paging safety bound');
        }
        await appendFile(logFile,'[CONTROLLER_POLICY_PAGES_COMPLETE]\n');
      } catch(error) {
        await appendFile(logFile,'[CONTROLLER_POLICY_PREFETCH_FAILED] '+String(error)+'\n');
        throw error;
      }
    }
    const seededPaths=limits.initialSourcePaths?.filter(p=>p!=='audit-policy.txt').slice(0,3) || [];
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
          const sourceEvidenceId=await controllerArchive?.append('source',{path,start:delivered.start,end:delivered.end,content:delivered.text,nextOffset:delivered.nextOffset},{source:path});
          if(sourceEvidenceId)workflow?.recordSourceEvidence(path,sourceEvidenceId);
          limits.onRead?.(path,{start:delivered.start,end:delivered.end});
          navigation.observe('read_file',path,offset,'',delivered);
          successfulReads++;
          recentActions.set(JSON.stringify(['read_file',path,offset,'']),{turn:-1,nextOffset:delivered.nextOffset,response:fitted.message});
          if(delivered.nextOffset===null)terminalReadPages.set(path,{offset,response:fitted.message});
          events.push(JSON.stringify({tool:'read_file',path,offset,end:delivered.end,nextOffset:delivered.nextOffset,status:'prefetched'}).slice(0,180));
          await appendFile(logFile,'[INITIAL_SOURCE_READ] '+JSON.stringify({path,start:delivered.start,end:delivered.end,nextOffset:delivered.nextOffset})+'\n');
          await recordToolActivity(logFile,{phase:'completed',tool:'read_file',
            path,offset:delivered.start,end:delivered.end,nextOffset:delivered.nextOffset,
            origin:'controller_prefetch'});
          if(!workflow || process.env.AUTOHACK_GUIDED_SOURCE_PROBES==='false' || !limits.verifyPython)continue;
          // Guided probe discovery is controller-owned. The model sees paginated
          // source pages, but the controller may inspect the complete authorized
          // file without consuming model context. Requiring nextOffset===null
          // here silently disabled guided probes for real-world Solidity files.
          const guidedSource=delivered.nextOffset===null && offset===0
            ? delivered.text : await readFile(full,'utf8');
          const guidedHint=await guidedProbeAcrossSourceChain(root,path,guidedSource);
          const fallbackPlan=!guidedHint ? controllerPolyglotPlan(path,guidedSource) : null;
          const hint=guidedHint || (fallbackPlan ? {
            functionName:fallbackPlan.query,kind:fallbackPlan.answer,
            hypothesis:fallbackPlan.hypothesis,sequence:fallbackPlan.sequence
          } : null);
          if(!hint) {
            await appendFile(logFile,'[GUIDED_PROBE_NO_CANDIDATE] '+JSON.stringify({
              path,paginated:delivered.nextOffset!==null,sourceCharacters:guidedSource.length})+'\n');
            continue;
          }
          const planned={action:'plan_probe',path,query:hint.functionName,answer:hint.kind,hypothesis:hint.hypothesis,
            ...('sequence' in hint && hint.sequence!==undefined ? {sequence:hint.sequence} : {})};
          if(workflow.validate(planned as any))continue;
          workflow.plan(planned as any);
          let raw:string;
          try {raw=await limits.verifyPython(path,hint.functionName,hint.kind,
            'sequence' in hint ? hint.sequence as any : undefined);}
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
          const evidenceId=await controllerArchive?.append('probe',{path,function:hint.functionName,kind:hint.kind,result},
            {source:path,caseId:typeof result.caseId==='string'?result.caseId:undefined});
          if(evidenceId)result.controllerEvidenceId=evidenceId;
          if(evidenceId)workflow?.recordEvidence(evidenceId);
          const output=JSON.stringify(result);
          const verify={action:'verify_source',path,query:hint.functionName,answer:hint.kind,
            ...('sequence' in hint && hint.sequence!==undefined ? {sequence:hint.sequence} : {})};
          workflow.observe(verify as any,output);
          if(result.status==='behavior_observed' &&
             typeof result.caseId==='string' && limits.onVerifiedCase &&
             process.env.LOCAL_CONTROLLER_OWNED_ACTIONS!=='false') {
            const handoff=await limits.onVerifiedCase(result.caseId,path,hint.functionName,hint.kind);
            if(handoff?.promoted) {
              const promoted=handoff.promoted;
              workflow.observe({action:'verify_source',path:promoted.path,query:promoted.selector,
                answer:promoted.kind} as any,
                JSON.stringify({status:'behavior_observed',behavior_observed:true,caseId:promoted.caseId}));
            }
            const focusId=handoff?.promoted?.caseId||result.caseId;
            if(handoff?.callers.length && workflow.focusVerifiedEvidence(focusId)) {
              workflow.requireSources(handoff.callers);
              await appendFile(logFile,'[CONTROLLER_GUIDED_CASE_FOCUS] '+
                JSON.stringify({caseId:focusId,sourceCaseId:result.caseId,callers:handoff.callers,
                  promoted:!!handoff.promoted})+'\n');
            }
          }
          // A controller-initiated negative probe must also advance navigation.
          // Previously only model-initiated negative probes triggered the
          // mandatory source handoff, leaving Qwen free to cycle on decoys.
          if(result.status==='behavior_not_observed') {
            const next=workflow.requireNextUnreadSource(limits.initialSourcePaths||[]);
            if(next)await appendFile(logFile,'[GUIDED_NEGATIVE_PROBE_SOURCE_HANDOFF] '+
              JSON.stringify({testedPath:path,next})+'\n');
          }
          if(result.status==='behavior_observed' && !workflow.snapshot().verifiedEvidenceFocus) {
            const paths=(limits.initialSourcePaths||[]).filter(p=>p.startsWith('source-') &&
              p!==path && /\.(?:py|js|mjs|cjs|java|sol)$/.test(p));
            paths.sort((a,b)=>Number(/(?:caller|handler|route|controller|entry|server)/i.test(b))-
              Number(/(?:caller|handler|route|controller|entry|server)/i.test(a)));
            if(paths[0]) {
              // Prefetch already supplies the caller text and records its read.
              // Do not force the model to reread an exhausted source page.
              if(!workflow.snapshot().readPaths.includes(paths[0]))workflow.requireSource(paths[0]);
              else workflow.feedback('Probe reproduced in '+path+'. Caller '+paths[0]+
                ' was already read. Evaluate caller reachability and impact using the recorded source and probe evidence; reread only if context was evicted.');
              await appendFile(logFile,'[POST_PROBE_CALLER_REQUIRED] '+JSON.stringify({
                testedPath:path,caller:paths[0],guided:true,
                alreadyRead:workflow.snapshot().readPaths.includes(paths[0])
              })+'\n');
            }
          }

          if(['behavior_observed','behavior_not_observed'].includes(result.status))
            allowance.probe(JSON.stringify([path,hint.functionName,hint.kind,
              'sequence' in hint ? hint.sequence : undefined]),0);
          const record:Message={role:'assistant',content:JSON.stringify(verify)};
          const available=messageBudget-3000-JSON.stringify(messages.slice(2)).length;
          try {
            const response=fitAuditToolOutput(messages.slice(0,2),record,'verify_source',output,available,true);
            messages.push(record,response.message);
          }catch { // The evidence file remains available for a later explicit read.
            messages.push({role:'user',content:'An isolated probe was attempted for '+path+
              '; result status '+String(result.status)+'. Read '+result.evidenceFile+' for the full observation. /no_think'});
          }
          await appendFile(logFile,'[GUIDED_SOURCE_PROBE] '+JSON.stringify({
            path,function:hint.functionName,kind:hint.kind,status:result.status,
            caseId:result.caseId||null,evidenceFile:result.evidenceFile,
            detail:String(result.detail||result.limitation||'').slice(0,240)})+'\n');
          await recordToolActivity(logFile,{phase:result.status==='probe_failed'?'failed':'completed',
            tool:'verify_source',path,query:hint.functionName,kind:hint.kind,
            status:result.status,origin:'controller_guided',
            detail:String(result.detail||result.limitation||'').slice(-220)});
        } catch(error) {
          if(controller.signal.aborted)throw error;
          // Bad hints never authorize additional paths or imply a successful read.
          await appendFile(logFile,'[INITIAL_SOURCE_SKIPPED] '+String(error).slice(0,180)+'\n');
        }
      }
    }
    for (let turn = 0; allowance.unbounded || turn < allowance.turns; turn++) {
      usedTurns=turn+1;
      controller.signal.throwIfAborted();
      // Keep stable history; send fresh controller state only with this request.
      let constraints=workflow ? await workflow.constraints() : limits.actionConstraints?.();
      // The inspection graph moves into hypothesis mode after six source reads.
      // Keep source reading *eligible* while controller-ranked, scoped sources
      // remain unread; otherwise a repetitive small model cannot be redirected
      // past six files and wastes the remaining turn allowance on rejections.
      // Never override an exact required probe, caller read, or final-only gate.
      if(workflow && constraints?.action?.includes('continue_inspection') &&
         constraints.action.includes('plan_probe') &&
         !constraints.action.includes('read_file') &&
         (limits.initialSourcePaths||[]).some(path=>
           /^source-[0-9]+\//.test(path) &&
           /\.(?:py|js|mjs|cjs|java|sol)$/.test(path) &&
           !workflow.snapshot().readPaths.includes(path))) {
        constraints={...constraints,action:['read_file',...constraints.action]};
        await appendFile(logFile,'[UNREAD_SOURCE_ACTION_RESTORED] '+
          JSON.stringify({turn:turn+1,remaining:(limits.initialSourcePaths||[])
            .filter(path=>!workflow.snapshot().readPaths.includes(path)).length})+'\n');
      }

      if(workflow && requireInvestigationAfterEmpty && constraints?.action?.includes('final') && constraints.action.length>1) {
        constraints={...constraints,action:constraints.action.filter(name=>name!=='final')};
        await appendFile(logFile,'[EMPTY_FINAL_INVESTIGATE] Require a concrete tool action before another conclusion\n');
      }
      // Mandatory indexed transition: completed source acquisition advances to
      // controller-owned probe planning, never back to speculative source reads.
      const eligibleForProbe=[...new Set(limits.initialSourcePaths||[])].filter(path=>
        path.startsWith('source-') && ['.sol','.java','.py','.js','.mjs','.cjs'].some(ext=>path.endsWith(ext)));
      const sourceStageComplete=!!workflow && eligibleForProbe.length>0 &&
        eligibleForProbe.every(path=>terminalReadPages.has(path));
      if(sourceStageComplete && constraints?.action?.includes('read_file') &&
         !workflow!.snapshot().pending && !workflow!.snapshot().verifiedEvidenceFocus) {
        constraints={...constraints,action:[...new Set([
          ...constraints.action.filter(action=>!['read_file','continue_inspection','list_files','search_files'].includes(action)),
          'plan_probe'])]};
        await appendFile(logFile,'[MANDATORY_PROBE_TRANSITION] '+
          JSON.stringify({turn:turn+1,completed:eligibleForProbe.length})+'\n');
      }
      // A stage permitting plan_probe also permits its controller-executed
      // equivalent, without changing the underlying workflow validation.
      if(workflow && constraints?.action?.includes('plan_probe') && !constraints.action.includes('probe_intent'))
        constraints={...constraints,action:[...constraints.action,'probe_intent']};
      if(workflow && turn<blockCompletedReadsUntil && constraints?.action?.includes('read_file')) {
        const alternatives=constraints.action.filter(name=>name!=='read_file');
        if(alternatives.length) {
          constraints={...constraints,action:alternatives};
          await appendFile(logFile,'[REPEATED_READ_BLOCKED] '+JSON.stringify({turn:turn+1,actions:alternatives})+'\n');
        }
      }
      if(workflow && consecutiveWorkflowRejections>=2 && constraints?.action?.includes('plan_probe')) {
        const otherActions=constraints.action.filter(name=>name!=='plan_probe' && name!=='probe_intent');
        if(otherActions.length)constraints={...constraints,action:otherActions};
      }
      if(constraints && (JSON.stringify(constraints).length>3000 || Object.entries(constraints).some(([key,values])=>
        !["action","path","query","answer"].includes(key) || !Array.isArray(values) || !values.length || values.some(value=>typeof value!=="string"))))
        throw new Error("Invalid task action constraints");
      if(constraints?.action?.some(action=>!actionSchema.properties.action.enum.includes(action)))throw new Error("Task requested an unavailable action");
      let requestSchema:Record<string,any>=constraints ? {...actionSchema,properties:{...actionSchema.properties,
        ...Object.fromEntries(Object.entries(constraints).map(([key,values])=>[key,{type:"string",enum:values}]))}} : actionSchema;
      if(structured && !requireInvestigationAfterEmpty && limits.finalSchema && (emptyFinals>=1 || invalidReviewFinals>=2 || !!workflow?.snapshot().verifiedEvidenceFocus) &&
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
        if(!recordedIds.length && strictResult.properties?.findings) {
          // A model cannot cite a reproduction before the controller has
          // registered one. Keep a legitimate scoped negative result possible.
          strictResult.properties.findings={...strictResult.properties.findings,maxItems:0};
          await appendFile(logFile,'[FINAL_UNVERIFIED_FINDINGS_BLOCKED] No recorded reproduction case\n');
        } else if(item?.properties?.caseId) {
          item.properties.caseId={...item.properties.caseId,enum:recordedIds};
        }
        requestSchema={...requestSchema,
          properties:{...requestSchema.properties,
            action:{type:'string',enum:['final']},
            result:strictResult},
          required:[...new Set([...actionSchema.required,'result'])]};
        await appendFile(logFile,'[FINAL_RESULT_REQUIRED] Recovery from empty final; evidence validation still required\n');
      }
      const schemaExtra=Math.max(0,JSON.stringify(requestSchema).length-JSON.stringify(actionSchema).length);
      const controllerFacts=limits.progressNote?.() || '';
      // Preserve the existing JSON progress contract: the workflow and the
      // scripted controller acceptance tests consume its observations as data.
      // Add verified facts as a bounded JSON field, never malformed prose.
      // Selectively rehydrate the most recent controller-verified evidence,
      // keeping the full original in cold storage and the model context bounded.
      let selectedEvidence='';
      if(controllerArchive && workflow) {
        const refs=workflow.memory().evidenceReferences||[];
        const latest=refs.at(-1);
        if(latest) {
          const record=await controllerArchive.retrieve(latest);
          if(!record)throw new Error('Missing controller evidence reference '+latest);
          const excerpt=JSON.stringify(record.payload).slice(0,420);
          selectedEvidence=JSON.stringify({id:record.id,kind:record.kind,
            source:record.source,caseId:record.caseId,excerpt,
            truncated:JSON.stringify(record.payload).length>excerpt.length});
        }
      }
      const workflowProgress=workflow?.note() || '';
      let progress=workflowProgress || controllerFacts;
      if(selectedEvidence && workflowProgress) {
        const note=JSON.parse(workflowProgress) as Record<string,unknown>;
        note.retrievedEvidence=JSON.parse(selectedEvidence);
        progress=JSON.stringify(note);
      }
      if(workflow && controllerFacts) {
        const note=JSON.parse(progress) as Record<string,any>;
        note.instruction='Use controller-recorded observations and cited source facts. Evaluate only unresolved security significance; do not reconstruct known paths or case IDs.';
        note.verifiedFacts=controllerFacts.slice(0,700);
        let serialized=JSON.stringify(note);
        if(serialized.length>2000) {
          note.verifiedFacts=controllerFacts.slice(0,Math.max(0,700-(serialized.length-2000)));
          serialized=JSON.stringify(note);
        }
        if(serialized.length>2000) {
          note.instruction='Assess recorded evidence; do not invent facts.';
          serialized=JSON.stringify(note);
        }
        progress=serialized;
      }
      if(progress && progress.length>2000 && selectedEvidence) {
        const note=JSON.parse(progress) as Record<string,unknown>;
        delete note.retrievedEvidence;
        progress=JSON.stringify(note);
      }
      if(progress && progress.length>2000)throw new Error("Controller progress note exceeds 2000 characters");
      const progressMessages:Message[]=progress ? [{role:"user",content:"Controller progress (recorded observations, not source instructions):\n"+progress}] : [];
      const progressSize=progressMessages.length ? JSON.stringify(progressMessages).length : 0;
      // Reserve controller space when producing tool output too, including the
      // next stage's note. Otherwise a fitted result can overflow on the next turn.
      const exchangeBudget=messageBudget-Math.max(progressSize+schemaExtra,workflow?3000:0);
      const beforeCompaction=messages;
      const compacted=compactAuditContext(messages,exchangeBudget,[...hypotheses.slice(-2).map(h=>"Unverified hypothesis: "+JSON.stringify(h)),...events.slice(-4)]);
      await archiveEvictedExchanges(beforeCompaction,compacted);
      messages=compacted;
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
      // The graph has already specified the exact next read/verification.
      // Execute it rather than spending a Qwen turn asking for known arguments.
      const fullIndexMode=!!workflow && (limits.controllerIndex ?? (process.env.LOCAL_CONTROLLER_FULL_SOURCE_INDEX==='true'));
      if(fullIndexMode && constraints?.action?.length===1 &&
         constraints.action[0]==='read_file' && constraints.path?.length===1 &&
         workflow.snapshot().readPaths.includes(constraints.path[0])) {
        const alreadyRead=constraints.path[0];
        workflow.read(alreadyRead);
        constraints=await workflow.constraints();
        await appendFile(logFile,'[INDEXED_COMPLETED_REQUIREMENT_RELEASED] '+
          JSON.stringify({path:alreadyRead,turn:turn+1})+'\n');
      }
      let controllerAction=structured && workflow && process.env.LOCAL_CONTROLLER_OWNED_ACTIONS!=='false' ?
        controllerOwnedNextAction(constraints,workflow.snapshot().pending) : null;
      // The controller has already inspected actual source and knows the
      // verifier's accepted formats. When a grounded probe is executable,
      // choose the exact declaration and plan instead of asking Qwen to guess.
      // The normal workflow validator and isolated verifier remain mandatory.
      if(!controllerAction && structured && workflow &&
         process.env.LOCAL_CONTROLLER_OWNED_ACTIONS!=='false' &&
         !workflow.snapshot().verifiedEvidenceFocus &&
         // Probe progression is bounded by evidence-backed candidates, not an arbitrary count.
         constraints?.action?.includes('plan_probe')) {
        const inspected=new Set(workflow.snapshot().readPaths);
        // Candidate ranking is controller-owned. Iteration in reverse read
        // order used to favor the last decoy that happened to be prefetched.
        // Keep prioritized paths first, then other actually inspected paths.
        const ranked=[...new Set([...(limits.initialSourcePaths||[]),
          ...workflow.snapshot().readPaths])].filter(path=>inspected.has(path) &&
          path.startsWith('source-') && /\.(?:sol|java|py|js|mjs|cjs)$/.test(path));
        const rankedInspected=[...new Set([...privilegedSolidityCandidates.keys(),...projectErc1155CallerPaths,...tracedCandidates.map(c=>c.path),...ranked].filter(path=>inspected.has(path)))];
        for(const path of rankedInspected) {
          try {
            const full=await safePath(path);
            let plan:{action:string;path:string;query:string;answer:string;hypothesis:string;sequence?:unknown}|null=null;
            if(path.endsWith('.sol')) {
              const source=await readFile(full,'utf8');
              const menu=await solidityIndex.probeMenu(full,64);
              // Source-grounded AST scenarios, not ABI mutability or guessed
              // role names, are the only eligible Solidity security probes.
              const groundedOptions=sourceGroundedSolidityProbes(source,menu);
              const supported=new Set(groundedOptions.map(entry=>entry.selector));
              for(const entry of menu.filter(entry=>entry.operation==='send'))
                if(!supported.has(entry.selector))
                  await recordProbeDisposition(path,entry.selector,'solidity_sequence',
                    'unsupported','security_setup_or_assertion_not_source_proven');
              for(const {selector,probe:grounded} of groundedOptions) {
                const candidate={action:'plan_probe',path,query:selector,
                  answer:'solidity_sequence',
                  hypothesis:grounded.hypothesis,sequence:grounded.sequence};
                const attempted=workflow.snapshot().observations.some(item=>
                  item.path===path && item.function===candidate.query &&
                  item.kind===candidate.answer);
                if(attempted) {
                  await recordProbeDisposition(path,candidate.query,candidate.answer,
                    'observed','existing_workflow_observation');
                  continue;
                }
                const rejection=workflow.validate(candidate as any);
                if(!rejection){plan=candidate;break;}
                await recordProbeDisposition(path,candidate.query,candidate.answer,
                  'rejected',String(rejection).slice(0,240));
              }
            }else {
              const traced=tracedCandidates.find(candidate=>candidate.path===path);
              const code=await readFile(full,'utf8');
              const controllerPlan=controllerPolyglotPlan(path,code);
              const hint=traced?{functionName:traced.selector,kind:traced.kind,
                hypothesis:traced.hypothesis}:guidedSourceProbe(path,code);
              // An independently traced security lead outranks a generic state
              // observation in the same file. Both choices are source-derived;
              // the isolated verifier still determines executable capability.
              const tracedPlan=traced && await declaredProbeTarget(full,traced.selector)
                ? {action:'plan_probe' as const,path,query:traced.selector,
                    answer:traced.kind,hypothesis:traced.hypothesis}:null;
              // Enumerate every source-backed adapter; record explicit skip reasons.
              const candidates=[...(tracedPlan?[tracedPlan]:[]),...controllerPolyglotPlans(path,code),
                ...(controllerPlan?[controllerPlan]:[]),...(hint?[{action:'plan_probe' as const,
                  path,query:hint.functionName,answer:hint.kind,hypothesis:hint.hypothesis}]:[])];
              const seen=new Set<string>();
              for(const candidate of candidates) {
                const identity=JSON.stringify([candidate.query,candidate.answer]);
                if(seen.has(identity))continue;
                seen.add(identity);
                if(probeDispositions.has(probeIdentity(path,candidate.query,candidate.answer)) &&
                   probeDispositions.get(probeIdentity(path,candidate.query,candidate.answer))?.status!=='selected')continue;
                if(!candidate.answer.endsWith('_sequence') &&
                   !(await declaredProbeTarget(full,candidate.query,candidate.answer,
                     'sequence' in candidate ? candidate.sequence : undefined))) {
                  await recordProbeDisposition(path,candidate.query,candidate.answer,'unsupported','declaration_preflight_failed');
                  continue;
                }
                const attempted=workflow.snapshot().observations.some(item=>
                  item.path===path && item.function===candidate.query && item.kind===candidate.answer);
                if(attempted) {
                  await recordProbeDisposition(path,candidate.query,candidate.answer,'observed','existing_workflow_observation');
                  continue;
                }
                const rejection=workflow.validate(candidate as any);
                if(!rejection){plan=candidate;break;}
                await recordProbeDisposition(path,candidate.query,candidate.answer,'rejected',String(rejection).slice(0,240));
              }
            }
            if(!plan)continue;
            // Admit only inspected, controller-selected candidates to the
            // explicit lifecycle. A proposed hypothesis is not a finding.
            workflow.registerControllerPlan(plan,
              workflow.latestSourceEvidence(path)||'inspected:'+path,
              plan.hypothesis,
              'The isolated experiment does not exhibit the proposed behavior.');
            controllerAction=plan;
            await recordProbeDisposition(path,plan.query,plan.answer,'selected','controller_scheduled');
            await appendFile(logFile,'[CONTROLLER_SOURCE_PROBE_SELECTED] '+
              JSON.stringify({path,selector:plan.query,kind:plan.answer})+'\n');
            break;
          }catch(error) {
            await appendFile(logFile,'[CONTROLLER_SOURCE_PROBE_UNAVAILABLE] '+
              JSON.stringify({path,error:String(error).slice(0,160)})+'\n');
          }
        }
      }
      // The acquisition/ranking controller already owns a finite list of real
      // candidates. Read the next ranked, existing source directly, rather
      // than allowing Qwen to choose from a filename menu before receiving
      // sufficient facts. Cap this scan; unresolved semantic questions still
      // belong to the model.
      if(!controllerAction && structured && workflow &&
         process.env.LOCAL_CONTROLLER_OWNED_ACTIONS!=='false' &&
         !workflow.snapshot().verifiedEvidenceFocus &&
         controllerAutoReadCount<(fullIndexMode
           ? new Set(limits.initialSourcePaths||[]).size : 8) &&
         constraints?.action?.includes('read_file')) {
        const inspected=new Set(workflow.snapshot().readPaths);
        // The full-index controller already owns source ranking and read history.
        // Use that evidence to choose the next unread source, rather than
        // delegating filename selection to the small model.
        const rankedSources=[...new Set([...privilegedSolidityCandidates.keys(),
          ...projectErc1155CallerPaths,...tracedCandidates.map(c=>c.path),...(limits.initialSourcePaths||[])])];
        for(const candidate of rankedSources) {
          if(constraints.path?.length && !constraints.path.includes(candidate))continue;
          if(!candidate.startsWith('source-') || !/\.(?:java|py|js|mjs|cjs|sol)$/.test(candidate) ||
             inspected.has(candidate))continue;
          try {
            await safePath(candidate);
            controllerAction={action:'read_file',path:candidate,query:'',answer:'',offset:0};
            controllerAutoReadCount++;
            await appendFile(logFile,'[CONTROLLER_RANKED_SOURCE_READ] '+
              JSON.stringify({path:candidate,rankedRead:controllerAutoReadCount})+'\n');
            break;
          }catch{}
        }
      }
      // Real-world 88mph run: Qwen repeatedly requested a terminal SafeERC20
      // page at turns 70-75, taking 5-13 minutes per request. The old recovery
      // handed off another ranked file only AFTER wasting a model turn. When
      // controller-ranked source remains, perform that read directly instead.
      // Source progress and terminal pages are controller-owned, not model-owned.
      if(!controllerAction && fullIndexMode && structured && workflow &&
         process.env.LOCAL_CONTROLLER_OWNED_ACTIONS!=='false' &&
         constraints?.action?.includes('read_file') &&
         !workflow.snapshot().verifiedEvidenceFocus) {
        const remaining=[...new Set(limits.initialSourcePaths||[])].filter(path=>
          path.startsWith('source-') && /\.(?:sol|java|py|js|mjs|cjs)$/.test(path) &&
          !terminalReadPages.has(path) &&
          (!constraints?.path?.length || constraints.path.includes(path)));
        for(const candidate of remaining) {
          try {
            await safePath(candidate);
            const offsets=[...recentActions.entries()]
              .filter(([key,value])=>JSON.parse(key)[0]==='read_file' && JSON.parse(key)[1]===candidate && value.nextOffset!=null)
              .map(([,value])=>value.nextOffset as number);
            const offset=offsets.length ? Math.max(...offsets) : 0;
            controllerAction={action:'read_file',path:candidate,query:'',answer:'',offset};
            await appendFile(logFile,'[INDEXED_CONTROLLER_MODEL_BYPASS] '+
              JSON.stringify({turn:turn+1,path:candidate,offset,
                remaining:remaining.length,completed:terminalReadPages.size})+'\n');
            break;
          }catch{}
        }
      }
      if(fullIndexMode && structured && workflow &&
         process.env.LOCAL_CONTROLLER_OWNED_ACTIONS!=='false' &&
         !controllerAction && !workflow.snapshot().observations.length &&
         !workflow.snapshot().verifiedEvidenceFocus) {
        // The model is not an alternate source/probe scheduler. An exhausted
        // deterministic candidate queue is a controller diagnostic, not an
        // invitation for repeated speculative model finalization.
        const snapshot=workflow.snapshot();
        const eligible=(limits.initialSourcePaths||[]).filter(path=>
          path.startsWith('source-') && /\.(?:sol|java|py|js|mjs|cjs)$/.test(path));
        const unread=eligible.filter(path=>!snapshot.readPaths.includes(path));
        await appendFile(logFile,'[CONTROLLER_CANDIDATE_QUEUE_EXHAUSTED] '+
          JSON.stringify({turn:turn+1,stage:snapshot.stage,
            eligible:eligible.length,read:snapshot.readPaths.length,
            unread:unread.slice(0,12),observations:0})+'\n');
        if(!unread.length && workflow.finishControllerCandidates()) {
          constraints=await workflow.constraints();
          requestSchema={...requestSchema,properties:{...requestSchema.properties,
            action:{type:'string',enum:['final']}}};
          await appendFile(logFile,'[CONTROLLER_NO_SUPPORTED_SECURITY_SCENARIOS] '+
            JSON.stringify({inspected:eligible.length,unsupported:[...probeDispositions.values()]
              .filter(v=>v.status==='unsupported').length})+'\n');
        } else if(unread.length) {
          // Exhausted planning is not exhausted source coverage. Select the
          // next verified workspace path directly; never hand scheduling to Qwen.
          for(const path of unread){
            try {
              await safePath(path);
              controllerAction={action:'read_file',path,query:'',answer:'',offset:0};
              await appendFile(logFile,'[CONTROLLER_EXHAUSTED_QUEUE_RECOVERY] '+
                JSON.stringify({path,remaining:unread.length})+'\n');
              break;
            }catch{}
          }
        }
      }
      // Exhaustion is an explicit controller transition. Unsupported/negative
      // observations cannot authorize more source scheduling by the model.
      if(fullIndexMode && workflow && !controllerAction &&
         process.env.LOCAL_CONTROLLER_OWNED_ACTIONS!=='false' &&
         workflow.snapshot().observations.length && !workflow.snapshot().pending &&
         !workflow.snapshot().verifiedEvidenceFocus) {
        const snapshot=workflow.snapshot();
        const eligible=(limits.initialSourcePaths||[]).filter(path=>
          /^source-[0-9]+\//.test(path) && /\.(?:sol|java|py|js|mjs|cjs)$/.test(path));
        const unreadRemaining=eligible.filter(path=>!terminalReadPages.has(path) && !snapshot.readPaths.includes(path));
        if(eligible.length && !unreadRemaining.length && unresolvedProbes().length) {
          await appendFile(logFile,'[CONTROLLER_UNRESOLVED_PROBES] '+JSON.stringify(unresolvedProbes())+'\n');
          throw new Error('CONTROLLER_UNRESOLVED_PROBES: selected probes require verifier dispositions');
        }
        if(eligible.length && !unreadRemaining.length &&
           workflow.finishControllerCandidates()) {
          constraints=await workflow.constraints();
          requestSchema={...requestSchema,properties:{...requestSchema.properties,
            action:{type:'string',enum:['final']}}};
          await appendFile(logFile,'[CONTROLLER_EVIDENCE_ASSESSMENT_HANDOFF] '+
            JSON.stringify({observations:workflow.snapshot().observations.length,completedFiles:eligible.length})+'\n');
        }
      }
      if(fullIndexMode && !controllerAction && constraints?.action?.length===1 &&
         constraints.action[0]==='final' && unresolvedProbes().length)
        throw new Error('CONTROLLER_UNRESOLVED_PROBES: final reporting blocked until selected probes have verifier dispositions');
      // Never delegate source selection, probe execution or workflow transitions
      // to Qwen in controller-owned indexed investigations. Only a semantic
      // final assessment may use the model, after deterministic work is done.
      // An unresolved action is a controller defect, not a model prompt.
      if(fullIndexMode && workflow && !controllerAction &&
         process.env.LOCAL_CONTROLLER_OWNED_ACTIONS!=='false') {
        const snapshot=workflow.snapshot();
        const permitted=constraints?.action||[];
        const semanticOnly=permitted.length>0 &&
          permitted.every(action=>action==='final') &&
          !snapshot.pending;
        if(!semanticOnly) {
          // Repair the controller's own missing transition deterministically.
          // The model is never an alternate source or verifier scheduler.
          if(snapshot.pending && permitted.includes('verify_source')) {
            const p=snapshot.pending;
            controllerAction={action:'verify_source',path:p.path,query:p.query,
              answer:p.answer,sequence:p.sequence};
          } else if(permitted.includes('read_file')) {
            const outstanding=(limits.initialSourcePaths||[]).filter(path=>
              /^source-[0-9]+\//.test(path) &&
              /\.(?:sol|java|py|js|mjs|cjs)$/.test(path) &&
              !terminalReadPages.has(path));
            for(const path of outstanding){
              try{
                await safePath(path);
                const offsets=[...recentActions.entries()]
                  .filter(([key,value])=>JSON.parse(key)[0]==='read_file' &&
                    JSON.parse(key)[1]===path && value.nextOffset!=null)
                  .map(([,value])=>value.nextOffset as number);
                controllerAction={action:'read_file',path,query:'',answer:'',
                  offset:offsets.length?Math.max(...offsets):0};
                break;
              }catch{}
            }
          }
          if(!controllerAction && !snapshot.pending &&
             !(limits.initialSourcePaths||[]).some(path=>
               /^source-[0-9]+\//.test(path) &&
               /\.(?:sol|java|py|js|mjs|cjs)$/.test(path) &&
               !terminalReadPages.has(path)) &&
             workflow.finishControllerCandidates()) {
            constraints=await workflow.constraints();
            requestSchema={...requestSchema,properties:{...requestSchema.properties,
              action:{type:'string',enum:['final']}}};
          }
          await appendFile(logFile,'[CONTROLLER_ACTION_RECOVERY] '+
            JSON.stringify({turn:turn+1,stage:snapshot.stage,
              permitted,pending:snapshot.pending,
              recovered:controllerAction?.action||'evidence_assessment'})+'\n');
          if(!controllerAction && constraints?.action?.some(action=>action!=='final'))
            throw new Error('CONTROLLER_UNRESOLVED_ACTION: no supported action remains after deterministic recovery');
        }
      }
      if(controllerAction && fullIndexMode) {
        const snapshot=workflow.snapshot();
        const progressKey=JSON.stringify([snapshot.sourceProgress,
          snapshot.observations.length,snapshot.pending?.path||'',
          snapshot.pending?.query||'',snapshot.verifiedEvidenceFocus||'']);
        indexedSyntheticStalls=progressKey===indexedLastProgressKey
          ? indexedSyntheticStalls+1:0;
        indexedLastProgressKey=progressKey;
        if(indexedSyntheticStalls>=12) {
          const stalled=controllerAction;
          indexedSyntheticStalls=0;
          await appendFile(logFile,'[INDEXED_CONTROLLER_PROGRESS_STALL] '+
            JSON.stringify({turn:turn+1,action:stalled,progressKey})+'\n');
          // Release an actual stuck plan without inventing a successful probe.
          if(stalled.action==='verify_source') {
            const released=workflow.abortPending('Verifier made no progress after repeated controller actions');
            if(released)await recordProbeDisposition(released.path,released.query,released.kind,
              'controller_blocked','verifier_no_progress');
          } else if(stalled.action==='plan_probe') {
            await recordProbeDisposition(stalled.path,stalled.query,stalled.answer,
              'rejected','planning_no_progress');
          }
          if(stalled.action==='read_file'||stalled.action==='read_solidity'||
             stalled.action==='outline_solidity')controllerStalledPaths.add(stalled.path);
          controllerAction=null;
          const candidates=(limits.initialSourcePaths||[]).filter(path=>
            /^source-[0-9]+\//.test(path) &&
            /\.(?:sol|java|py|js|mjs|cjs)$/.test(path) &&
            !terminalReadPages.has(path) && !controllerStalledPaths.has(path));
          for(const path of candidates) {
            try {
              await safePath(path);
              controllerAction={action:'read_file',path,query:'',answer:'',offset:0};
              break;
            }catch{controllerStalledPaths.add(path);}
          }
          if(!controllerAction && !workflow.snapshot().pending &&
             workflow.finishControllerCandidates()) {
            constraints=await workflow.constraints();
            requestSchema={...requestSchema,properties:{...requestSchema.properties,
              action:{type:'string',enum:['final']}}};
          }
          if(!controllerAction && constraints?.action?.some(item=>item!=='final'))
            throw new Error('CONTROLLER_NO_RECOVERY: unsupported source/probe after bounded recovery');
          await appendFile(logFile,'[CONTROLLER_STALL_RECOVERY] '+
            JSON.stringify({previous:stalled.action,
              next:controllerAction?.path||'final',excluded:controllerStalledPaths.size})+'\n');
        }
      } else if(fullIndexMode && !controllerAction)indexedSyntheticStalls=0;
      if(controllerAction) {
        await appendFile(logFile,'[CONTROLLER_OWNED_ACTION] '+JSON.stringify(controllerAction)+'\n');
        await recordToolActivity(logFile,{phase:'completed',tool:'controller_action',
          path:controllerAction.path,query:controllerAction.query,
          kind:controllerAction.answer,selectedAction:controllerAction.action,
          turn:turn+1,origin:'controller'});
      } else {
        await recordToolActivity(logFile,{phase:'started',tool:'model_generation',
          turn:turn+1,model,origin:'model'});
      }
      const result: {message?:Message;eval_count?:number;prompt_eval_count?:number;done_reason?:string;load_duration?:number;prompt_eval_duration?:number;eval_duration?:number;total_duration?:number;client_queue_ms?:number} = controllerAction ?
        {message:{role:'assistant',content:JSON.stringify(controllerAction)}} :
        await (async () => {
          // A stalled Ollama request must not terminate a multi-hour investigation.
          // Retry only the model generation; controller memory, read cursors,
          // observations and completed probes remain unchanged.
          const endpoint=process.env.AUTOHACK_OLLAMA_URL || "http://127.0.0.1:11434/api/chat";
          const request={ model, stream: false, think: profile.think, messages:requestMessages,
          ...(structured ? {format:requestSchema} : {tools:availableTools}),
          keep_alive:"10m",
          options: { num_predict:generationBudget,
            ...(limits.numCtx === undefined ? {} : {num_ctx:settings.numCtx}),
            ...(limits.numThreads === undefined ? {} : {num_thread:settings.numThreads}), ...profile.options } };
          for(let attempt=1;attempt<=5;attempt++) {
            controller.signal.throwIfAborted();
            const attemptController=new AbortController();
            let inactivityTimer: ReturnType<typeof setTimeout> | undefined;
            const resetInactivity=()=>{
              clearTimeout(inactivityTimer);
              inactivityTimer=setTimeout(()=>attemptController.abort('model_request_stalled'),12*60*1000);
            };
            resetInactivity();
            const progressHandler=(progress:any)=>{
              resetInactivity();
              onProgress?.(progress);
            };
            const signal=AbortSignal.any([controller.signal,attemptController.signal]);
            try {
              return await (adapter==='qwen-agent'?postQwenAgentJson:postOllamaChat)(
                endpoint,request,signal,{onProgress:progressHandler});
            } catch(error) {
              if(controller.signal.aborted)throw error;
              if(attempt===5)throw error;
              await appendFile(logFile,'[MODEL_REQUEST_RECOVERY] '+JSON.stringify({
                turn:turn+1,attempt,reason:String(error).slice(0,200),
                retainedControllerMemory:true})+'\n');
              await new Promise(r => setTimeout(r, Math.min(attempt * 4000, 15000)));
            } finally {clearTimeout(inactivityTimer);}
          }
          throw new Error('Model request retries exhausted');
        })() as { message?: Message; eval_count?: number; prompt_eval_count?: number; done_reason?: string; load_duration?:number; prompt_eval_duration?:number; eval_duration?:number; total_duration?:number; client_queue_ms?:number };
      if(!controllerAction)await recordToolActivity(logFile,{
        phase:'completed',tool:'model_generation',turn:turn+1,model,
        durationMs:Date.now()-started,origin:'model',
        generatedTokens:result.eval_count ?? null,
        promptTokens:result.prompt_eval_count ?? null});
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
        // Incompatible source-navigation operations have a deterministic read
        // equivalent. Never run a Solidity parser on Python/JavaScript/Java.
        const navigationAction=canonicalSourceNavigationAction(action);
        if(navigationAction.action!==action.action) {
          await appendFile(logFile,'[CONTROLLER_LANGUAGE_NAVIGATION] '+JSON.stringify({
            from:action.action,to:navigationAction.action,path:action.path})+'\n');
          action=navigationAction;
        }
        // read_solidity requires a declaration ID. The real 88mph run sent
        // read_solidity(path=SafeERC20.sol, query="") for turns 66-80.
        // An empty query cannot identify a function; route through the
        // controller's paginated source reader instead of wasting model turns.
        if(action.action==='read_solidity' && !action.query.trim()) {
          await appendFile(logFile,'[CONTROLLER_EMPTY_SOLIDITY_QUERY_RECOVERY] '+
            JSON.stringify({path:action.path,turn:turn+1})+'\n');
          action={...action,action:'read_file',query:'',offset:0};
        }
        // Normalize navigation requests BEFORE workflow validation so source
        // evidence and read-history checks see the same canonical path.
        // Existing absolute-path canonicalization remains intact.
        if(action.path.startsWith('/')) {
          try {
            const normalized=relative(root,await safePath(action.path)).split(sep).join('/');
            if(normalized!==action.path) {
              await appendFile(logFile,'[MODEL_PATH_CANONICALIZED] '+JSON.stringify({from:action.path,to:normalized})+'\n');
              action.path=normalized;
            }
          } catch {}
        } else if (["read_file","list_files","search_files","outline_solidity","read_solidity"].includes(action.action)) {
          action.path=await canonicalSourceReadPath(action.path);
        }
        // If a read-only source navigation path is nonexistent, select an
        // *existing*, controller-ranked unread file. Do not keep asking the
        // model to reconstruct guessed file names. This is not a probe rewrite.
        if(workflow && action.action==='read_file' && action.path.startsWith('source-')) {
          let validPath=true;
          try {await safePath(action.path);}catch {validPath=false;}
          if(!validPath) {
            const snapshot=workflow.snapshot();
            let fallback='';
            for(const hint of limits.initialSourcePaths||[]) {
              if(!hint.startsWith('source-') || !/\.(?:py|js|mjs|cjs|java|sol)$/.test(hint) ||
                 snapshot.readPaths.includes(hint))continue;
              try {await safePath(hint);fallback=hint;break;}catch{}
            }
            if(fallback) {
              await appendFile(logFile,'[CONTROLLER_MISSING_PATH_HANDOFF] '+
                JSON.stringify({requested:action.path,next:fallback})+'\n');
              action.path=fallback;action.offset=0;action.query='';action.answer='';
            }
          }
        }
        // The model may carry a read_file *character* cursor into the
        // controller-required outline_solidity action, whose offset indexes
        // declarations. Reset only forced outlines; preserve normal pagination.
        const outlineOffset=normalizeForcedOutlineCursor(action.action,action.offset ?? 0,constraints?.action);
        if(outlineOffset!==action.offset) {
          await appendFile(logFile,'[FORCED_OUTLINE_CURSOR_RESET] '+JSON.stringify({
            path:action.path,requested:action.offset,used:outlineOffset})+'\n');
          action.offset=outlineOffset;
        }
        // The workflow owns the exact pending verifier request. Do not ask
        // Qwen to reconstruct it after a correct plan has been accepted.
        if(workflow && action.action==='verify_source') {
          const pending=workflow.snapshot().pending;
          if(pending) {
            const changed=action.path!==pending.path || action.query!==pending.query ||
              action.answer!==pending.answer || JSON.stringify(action.sequence)!==JSON.stringify(pending.sequence);
            if(changed) {
              action.path=pending.path;action.query=pending.query;
              action.answer=pending.answer;action.sequence=pending.sequence;
              await appendFile(logFile,'[PROBE_REQUEST_CANONICALIZED] '+JSON.stringify({path:action.path,query:action.query,kind:action.answer})+'\n');
            }
          }
        }
        // Validate EVERY Solidity plan, including model-authored intentions.
        // Never upgrade an ABI send/getter observation into a security probe.
        // The source controller owns the scenario; model assertions are ignored.
        if(workflow && action.path.endsWith('.sol') &&
           ['plan_probe','probe_intent'].includes(action.action)) {
          let grounded:ReturnType<typeof sourceGroundedSolidityProbe>=null;
          try {
            const full=await safePath(action.path);
            const source=await readFile(full,'utf8');
            const menu=await solidityIndex.probeMenu(full,64);
            grounded=sourceGroundedSolidityProbes(source,menu)
              .find(item=>item.selector===action.query)?.probe||null;
          }catch{}
          if(!grounded) {
            await recordProbeDisposition(action.path,action.query,'solidity_sequence',
              'unsupported','security_setup_or_assertion_not_source_proven');
            await appendFile(logFile,'[CONTROLLER_UNSUPPORTED_SOLIDITY_SCENARIO] '+
              JSON.stringify({path:action.path,selector:action.query})+'\n');
            // An unsupported scenario is a rejected required plan, not a reason
            // to lock the controller into requesting the same method forever.
            if(workflow.rejectedRequiredProbePlan())
              await appendFile(logFile,'[UNSUPPORTED_SOLIDITY_REQUIRED_PROBE_RELEASED] '+
                JSON.stringify({path:action.path,selector:action.query})+'\n');
            workflow.feedback('No source-grounded security scenario with a proved '+
              'caller/role setup and asserted invariant exists for this Solidity method. '+
              'Do not spend an isolated transaction probe; inspect project callers/wrappers '+
              'or mark the method unsupported.');
            messages.push({role:'user',content:
              'This Solidity method lacks a controller-verifiable security hypothesis, '+
              'setup, and invariant assertion. It has been skipped as unsupported; '+
              'inspect a project-owned caller or another source-grounded candidate. /no_think'});
            continue;
          }
          action.answer='solidity_sequence';
          action.sequence=grounded.sequence;
          action.hypothesis=grounded.hypothesis;
          await appendFile(logFile,'[CONTROLLER_SOLIDITY_SCENARIO_GROUNDED] '+
            JSON.stringify({path:action.path,selector:action.query,
              guardedConsumer:grounded.guardedConsumer})+'\n');
        }
        // All three non-Solidity languages obey the same source-owned probe
        // request contract as Solidity. The model may choose an actual method,
        // but its guessed kind, typed arguments and sequence are never trusted.
        if(!controllerAction && workflow && ['plan_probe','probe_intent'].includes(action.action) &&
           action.path.startsWith('source-') && /\.(?:java|py|js|mjs|cjs)$/.test(action.path)) {
          try {
            const full=await safePath(action.path);
            const grounded=canonicalControllerPolyglotIntent(action.path,
              await readFile(full,'utf8'),{query:action.query,answer:action.answer});
            if(grounded) {
              const prior={query:action.query,answer:action.answer,sequence:action.sequence};
              action.query=grounded.query;action.answer=grounded.answer;
              action.hypothesis=grounded.hypothesis;
              if(grounded.sequence===undefined)delete action.sequence;
              else action.sequence=grounded.sequence;
              if(JSON.stringify(prior)!==JSON.stringify({query:action.query,answer:action.answer,sequence:action.sequence}))
                await appendFile(logFile,'[CONTROLLER_POLYGLOT_PROBE_CANONICALIZED] '+
                  JSON.stringify({path:action.path,from:prior,query:action.query,kind:action.answer})+'\n');
            }
          } catch(error) {
            await appendFile(logFile,'[CONTROLLER_POLYGLOT_PROBE_UNAVAILABLE] '+
              JSON.stringify({path:action.path,error:String(error).slice(0,160)})+'\n');
          }
        }
        const automaticProbe=action.action==='probe_intent';
        if(automaticProbe) {
          action.action='plan_probe';
          if(!action.query.trim() && ['html_reflection','path_construction'].includes(action.answer)) {
            try {
              const full=await safePath(action.path);
              const choices=full.endsWith('.java')
                ? await supportedJavaProbeHints(full,24)
                : (await probeChoices(full,action.answer as 'html_reflection'|'path_construction',24)).map(choice=>choice.selector);
              if(choices.length===1) {
                action.query=choices[0];
                await appendFile(logFile,'[PROBE_INTENT_RESOLVED] '+JSON.stringify({path:action.path,query:action.query,kind:action.answer})+'\n');
              }
            }catch{}
          }
        }
        if(constraints && Object.entries(constraints).some(([key,values])=>!values!.includes(action[key as "action"|"path"|"query"|"answer"]))) {
          await appendFile(logFile,"[ACTION_REJECTED] "+JSON.stringify({action,constraints})+"\n");
          messages.push({role:"user",content:"That action is not available in the current task stage. Use the current response schema and controller progress. No tool was executed. /no_think"});
          continue;
        }
        if((action.action==='plan_probe'||action.action==='verify_source') &&
            action.path.endsWith('.java') && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(action.query)) {
          const javaClass=action.path.split('/').at(-1)!.slice(0,-5);
          action.query=javaClass+'.'+action.query;
          await appendFile(logFile,'[JAVA_QUERY_NORMALIZED] '+JSON.stringify({path:action.path,query:action.query})+'\n');
        }
        if(['plan_probe','verify_source','verify_python'].includes(action.action) &&
            !['solidity_sequence','java_sequence','python_sequence','javascript_sequence'].includes(action.answer) && action.sequence!==undefined) {
          // Normalize optional structured-output fields before validation,
          // planning and duplicate detection; they are unused by these probes.
          delete action.sequence;
          await appendFile(logFile,'[UNUSED_SEQUENCE_IGNORED] '+JSON.stringify({action:action.action,path:action.path,kind:action.answer})+'\n');
        }
        // A speculative final cannot skip a compatible source reproduction.
        if(workflow && action.action==='final') {
          let proposed:any;
          try { proposed=JSON.parse(action.answer || (action.result ? JSON.stringify(action.result) : '')); }catch{}
          const observationIds=new Set((workflow.snapshot().observations || []).map(o=>o.caseId).filter(Boolean));
          if(!observationIds.size && Array.isArray(proposed?.findings) && proposed.findings.length) {
            const candidate=proposed.findings[0];
            const path=String(candidate?.callerFile || '');
            const narrative=[candidate?.title,candidate?.ratingReason,candidate?.impact].filter(x=>typeof x==='string').join(' ');
            const selector=narrative.match(/\b([A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*)\b/)?.[1];
            const kind=/path.construction|path traversal|directory traversal/i.test(narrative)?'path_construction':
              /html.reflection|html injection|html output/i.test(narrative)?'html_reflection':null;
            if(workflow.snapshot().readPaths.includes(path) && selector && kind && /\.(?:java|py|js|mjs|cjs|sol)$/.test(path)) {
              let declared=false;
              try {const full=await safePath(path);declared=path.endsWith('.sol')?
                await solidityIndex.hasFunction(full,selector):await declaredProbeTarget(full,selector);}catch{}
              const recoveryKey=JSON.stringify([path,selector,kind]);
              if(declared && !recoveredFindingProbes.has(recoveryKey)) {
                recoveredFindingProbes.add(recoveryKey);
                workflow.requireProbe(path,selector,kind);
                await appendFile(logFile,'[PROBE_RECOVERY_REQUIRED] '+recoveryKey+'\n');
                messages.push({role:'user',content:'An unverified finding referred to an inspected declared function. Your NEXT action must be plan_probe with path='+path+', query='+selector+', answer='+kind+', and a hypothesis with a falsification condition. The controller then requires verify_source. Do not invent case IDs. /no_think'});
                continue;
              }
            }
          }
        }
        const workflowError=workflow?.validate(action);
        if(workflowError) {
          if(action.action==='plan_probe' && workflowError==='Read the candidate source before planning its test.') {
            // Do not pin the workflow to a model-typed path that does not exist.
            // This used to force an invalid read_file repeatedly until AUDIT_STALLED.
            let exists=false;
            try {await safePath(action.path);exists=true;}catch{}
            if(exists)workflow!.requireSource(action.path);
            else {
              const grounded=workflow!.snapshot().readPaths.slice(-8);
              workflow!.feedback('That candidate path does not exist. Use an EXACT path already read: '+grounded.join(', ')+'. Do not reconstruct filenames from memory.');
              await appendFile(logFile,'[INVALID_PROBE_PATH_RECOVERY] '+JSON.stringify({rejected:action.path,readPaths:grounded})+'\n');
            }
          }
          else if(action.action==='plan_probe' && workflowError==='This probe already finished or was attempted. Use its observation; choose a different candidate or conclude with the permitted incomplete outcome.')workflow!.rejectedDuplicateProbe();
          else workflow!.feedback(workflowError);
          consecutiveWorkflowRejections=lastWorkflowRejection===workflowError?consecutiveWorkflowRejections+1:1;
          lastWorkflowRejection=workflowError;
          await appendFile(logFile,'[WORKFLOW_REJECTED] '+workflowError+'\n');
          // Do not waste the remaining turns on a repeated untestable plan.
          // Choose an already-ranked unread source, never a fabricated target.
          if(action.action==='plan_probe' && consecutiveWorkflowRejections>=2 &&
             workflowError==='Select a function from the inspected source and a supported probe kind.') {
            const next=workflow!.requireNextUnreadSource(limits.initialSourcePaths||[]);
            if(next) {
              await appendFile(logFile,'[REJECTED_PLAN_SOURCE_HANDOFF] '+JSON.stringify({next})+'\n');
              messages.push({role:'user',content:'Repeated incomplete probe plans did not create evidence. Read the next ranked candidate: '+next+' with offset=0. Do not invent a probe or unverified finding. /no_think'});
              continue;
            }
          }
          if(action.action==='plan_probe' && workflow!.rejectedRequiredProbePlan())
            await appendFile(logFile,'[REQUIRED_PROBE_PLAN_RELEASED] Repeated invalid plans; reopen investigation\n');
          const template=action.action==='plan_probe' ?
            ' Correct probe format: '+JSON.stringify({action:'plan_probe',path:action.path,query:action.query,answer:action.answer,hypothesis:'Describe suspected behavior and the observation that would disprove it.'})+'.' : '';
          messages.push({role:'user',content:'Controller rejected the last action: '+workflowError+template+
            ' Do not repeat the rejected probe. Inspect a new call site, use recorded evidence, or give an evidence-based final finding or incomplete outcome. /no_think'});
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
          if(/\.(?:sol|java|py|js|mjs|cjs)$/.test(action.path)) {
            let declared=false;
            try {
              const target=await safePath(action.path);
              declared=action.path.endsWith('.sol') ?
                await solidityIndex.hasFunction(target,action.query) :
                await declaredProbeTarget(target,action.query,action.answer,action.sequence);
            }catch{}
            if(!declared) {
              let hints:string[]=[];
              try {
                const target=await safePath(action.path);
                if(!action.path.endsWith('.sol'))hints=action.path.endsWith('.java') ? await supportedJavaProbeHints(target) : await sourceDeclarationHints(target);
              }catch{}
              const suffix=hints.length ? ' Declared method names in this file (eligibility not yet verified): '+hints.join(', ')+'. Select only an actually eligible signature.' :
                ' Inspect actual declarations'+(action.path.endsWith('.sol')?' with outline_solidity':' in the source')+'; do not guess names.';
              const feedback='No matching source function declaration for '+action.query+'; no probe was run.'+suffix;
              workflow.feedback(feedback);
              await appendFile(logFile,'[PLAN_REJECTED] '+feedback+'\n');
              if(workflow.rejectedRequiredProbePlan())
                await appendFile(logFile,'[REQUIRED_PROBE_PLAN_RELEASED] Repeated undeclared plans; reopen investigation\n');
              messages.push({role:'user',content:feedback+' /no_think'});
              continue;
            }
          }
          if(action.path.endsWith('.java') && action.answer!=='java_sequence') {
            let compatible=false;
            let alternatives:string[]=[];
            try {
              const target=await safePath(action.path);
              compatible=await javaProbeSelectorCompatible(target,action.query);
              if(!compatible)alternatives=await supportedJavaProbeHints(target);
            }catch{}
            if(!compatible) {
              // Probe eligibility belongs to the verifier; investigation eligibility
              // does not. Preserve the suspected method instead of laundering an
              // unrelated compatible method into the next probe.
              const choices=alternatives.filter(selector=>selector!==action.query);
              const nextPaths=(limits.initialSourcePaths||[]).filter(p=>
                p.startsWith('source-') && p!==action.path &&
                /\.(?:java|sol|py|js|mjs|cjs)$/.test(p));
              const caller=nextPaths.find(p=>/(?:caller|handler|program|state|manager|service|controller)/i.test(p))||
                nextPaths[0];
              const feedback='PROBE_UNSUPPORTED_NOT_HYPOTHESIS_REJECTED: '+action.query+
                ' is not executable through the one-argument Java text adapter. '+
                'Stateful Java execution IS available: use plan_probe with answer=java_sequence '+
                'and a declarative sequence {constructor:[...],steps:[{method:"'+action.query.split('.').at(-1)+
                '",args:[...]}]}, including the selected method. '+
                'Read its constructor, call sites and initialization methods to derive concrete arguments. '+
                'Use expected only when justified by source; an observation-only sequence is valid. '+
                'Do not replace the method with '+(choices[0]||'another method')+
                ' merely because that method supports a text probe. '+
                'If required object/dependency construction remains unsupported, record the precise limitation.';
              workflow.feedback(feedback,true);
              await appendFile(logFile,'[JAVA_SEQUENCE_GUIDED] '+JSON.stringify({path:action.path,query:action.query})+'\n');
              await appendFile(logFile,'[PROBE_CAPABILITY_GAP] '+JSON.stringify({
                path:action.path,selector:action.query,kind:action.answer,
                hypothesis:action.hypothesis,caller:caller||null,
                supportedAlternativesNotSubstituted:choices
              })+'\n');
              messages.push({role:'user',content:feedback+' /no_think'});
              continue;
            }
          }
          // A single controller-facing handoff for all supported source probes.
          // Unlike model prompts, these choices derive from actual declarations.
          if(!['solidity_sequence','python_sequence','javascript_sequence'].includes(action.answer) && !action.path.endsWith('.java') && !action.path.endsWith('.sol')) {
            let valid=false;
            let menu:Awaited<ReturnType<typeof probeChoices>>=[];
            try {
              const full=await safePath(action.path);
              valid=await declaredProbeTarget(full,action.query);
              if(!valid)menu=await probeChoices(full,action.answer as 'html_reflection'|'path_construction',24,action.path);
            }catch{}
            if(!valid) {
              const feedback='Controller source probe menu: '+JSON.stringify(menu)+
                '. Choose a selector whose behavior matches your hypothesis, or inspect another function. '+
                'Do not invent a function or report an unexecuted probe.';
              workflow.feedback(feedback);
              await appendFile(logFile,'[PROBE_INTENT_MENU] '+JSON.stringify({path:action.path,kind:action.answer,menu})+'\n');
              messages.push({role:'user',content:feedback+' /no_think'});
              continue;
            }
          }
          if(['python_sequence','javascript_sequence'].includes(action.answer)) {
            const parsed=polyglotSequenceSchema.safeParse(action.sequence);
            const extension=action.answer==='python_sequence'?/\.py$/:/\.(?:js|mjs|cjs)$/;
            if(!extension.test(action.path) || !parsed.success ||
               !parsed.data.steps.some(step=>step.method===action.query)) {
              const feedback='Controller stateful execution requires a source-grounded '+
                'declarative sequence: {factory:"actualFactory",constructor:[],steps:['+
                '{method:"selectedMethod",args:[],expected:0},{method:"selectedMethod",args:[],expected:1}]}. '+
                'The factory is optional for module-level functions. Two or more executed steps must invoke the selected method. '+ 
                'Expected mismatches are observations, not security findings.';
              workflow.feedback(feedback);
              await appendFile(logFile,'[POLYGLOT_SEQUENCE_INVALID] '+JSON.stringify({path:action.path,query:action.query})+'\n');
              messages.push({role:'user',content:feedback+' /no_think'});
              continue;
            }
          }
          if(action.answer==='java_sequence') {
            const sequence=javaSequenceSchema.safeParse(action.sequence);
            if(!action.path.endsWith('.java') || !sequence.success ||
               !sequence.data?.steps.some(step=>step.method===action.query.split('.').at(-1))) {
              const feedback='Java stateful probe requires a Java Class.method and a source-derived sequence '+
                'with constructor arguments and steps naming public primitive/String methods, '+
                'including the selected method. Example: {constructor:[],steps:[{method:"getCount",args:[],expected:0}]}.';
              workflow.feedback(feedback);
              await appendFile(logFile,'[JAVA_SEQUENCE_INVALID] '+JSON.stringify({path:action.path,query:action.query})+'\n');
              messages.push({role:'user',content:feedback+' /no_think'});
              continue;
            }
          }
          if(action.answer==='solidity_sequence') {
            const sequence=soliditySequenceSchema.safeParse(action.sequence);
            if(!sequence.success) {
              let declarations:unknown[]=[];
              try {
                const full=await safePath(action.path);
                declarations=await solidityIndex.probeMenu(full,24);
              }catch{}
              const errors=sequence.error.issues.map(issue=>issue.path.join('.')+': '+issue.message).slice(0,6);
              const feedback='Controller Solidity probe guidance: '+JSON.stringify({errors,declarations,
                expectedStructure:{constructorArgs:[],steps:[
                  {operation:'send',function:'stateChangingMethod(type)',args:[],sender:0},
                  {operation:'call',function:'observableGetter()',args:[],expect:'actual_expected_value'}
                ]}})+
                '. Use source-derived ABI argument types and a justified expected value; do not invent a state assertion. Read the declaration/context when unknown.';
              workflow.feedback(feedback);
              await appendFile(logFile,'[PLAN_REJECTED] '+feedback+'\n');
              messages.push({role:'user',content:feedback+' /no_think'});
              if(++rejectedPlans>=3) {
                rejectedPlans=0;
                await recordProbeDisposition(action.path,action.query,action.answer,'rejected',
                  'controller_rejected_invalid_probe_plan');
                workflow.rejectedRequiredProbePlan();
                const next=workflow.requireNextUnreadSource(limits.initialSourcePaths||[]);
                if(!next)workflow.finishControllerCandidates();
                await appendFile(logFile,'[CONTROLLER_INVALID_PLAN_RECOVERY] '+
                  JSON.stringify({path:action.path,query:action.query,next})+'\\n');
              }
              continue;
            }
          }
          if(JSON.stringify([...messages.slice(0,2),message]).length>exchangeBudget-1000) {
            const feedback='The proposed action is too large for one exchange. Plan a shorter probe sequence.';
            workflow.feedback(feedback);
            await appendFile(logFile,'[PLAN_REJECTED] '+feedback+'\n');
            messages.push({role:'user',content:feedback+' /no_think'});
            if(++rejectedPlans>=3) {
                rejectedPlans=0;
                await recordProbeDisposition(action.path,action.query,action.answer,'rejected',
                  'controller_rejected_oversized_probe_plan');
                workflow.rejectedRequiredProbePlan();
                const next=workflow.requireNextUnreadSource(limits.initialSourcePaths||[]);
                if(!next)workflow.finishControllerCandidates();
                await appendFile(logFile,'[CONTROLLER_INVALID_PLAN_RECOVERY] '+
                  JSON.stringify({path:action.path,query:action.query,next})+'\\n');
              }
            continue;
          }
          rejectedPlans=0;
          rejectedRequiredProbeFinals=0;
          workflow.plan({...action});
          await persistMemory();
          if(!automaticProbe && action.hypothesis)hypotheses.push({turn:turn+1,path:action.path,statement:action.hypothesis});
          await appendFile(logFile,'[PROBE_PLANNED] '+JSON.stringify(action)+'\n');
          await recordToolActivity(logFile,{phase:'completed',tool:'probe_plan',
            path:action.path,query:action.query,kind:action.answer,
            origin:controllerAction?'controller':'model',turn:turn+1});
          if(!automaticProbe) {
            messages.push({role:"assistant",content:message.content});
            continue;
          }
          // Intent mode is one-step: the exact accepted plan becomes the verifier
          // request, never a second Qwen-generated reconstruction.
          action.action='verify_source';
          message={role:'assistant',content:JSON.stringify(action)};
          await appendFile(logFile,'[PROBE_INTENT_EXECUTE] '+JSON.stringify({path:action.path,query:action.query,kind:action.answer})+'\n');
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
          emptyFinals++;
          if(workflow && emptyFinals>=2 && ++emptyFinalRecoveryCycles<=3) {
            // A typed-final retry failed. Resume actual investigation rather than
            // spend every subsequent turn on another forced empty conclusion.
            emptyFinals=0;
            requireInvestigationAfterEmpty=true;
            workflow.feedback("An empty final response contains no evidence. Choose an eligible inspection or supported probe; do not finish until there is a valid result.");
            await appendFile(logFile,"[EMPTY_FINAL_RECOVER] Reopening investigative actions; cycle="+emptyFinalRecoveryCycles+"\n");
            messages.push({role:"user",content:"Empty final rejected twice. Execute an allowed inspection/probe action next, using existing source evidence. Do not claim unverified findings. /no_think"});
            continue;
          }
          if(!workflow && emptyFinals>2)throw new Error("Ollama returned empty final response after two corrective retries");
          if(workflow && emptyFinalRecoveryCycles>3)throw new Error("Ollama returned repeated empty final responses despite investigative recovery");
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
          // A final claiming an unread caller line cannot be repaired by another
          // model-only final. Read the *actual* authorized caller page first.
          // This is navigation evidence, never a finding or a reviewer verdict.
          if (workflow && /Read the page containing the entire claimed caller line before reporting/i.test(feedback)) {
            let claimed:{callerFile?:unknown;callerLine?:unknown}|undefined;
            try {
              const answer=JSON.parse(message.content) as {findings?:Array<{callerFile?:unknown;callerLine?:unknown}>};
              claimed=answer.findings?.[0];
            } catch {}
            const caller=typeof claimed?.callerFile==='string' ? claimed.callerFile : '';
            const line=claimed?.callerLine;
            if (caller && Number.isSafeInteger(line) && Number(line)>0 &&
                (limits.initialSourcePaths||[]).includes(caller)) {
              try {
                const full=await safePath(caller);
                let offset=0, pages=0, seenLines=0, reached=false;
                while(pages++<32) {
                  const page=await readSourcePage(full,offset,pageSize);
                  if(!page.text || page.end<=page.start)break;
                  const action={action:'read_file',path:caller,query:'',answer:'',offset};
                  const request:Message={role:'assistant',content:JSON.stringify(action)};
                  const fitted=fitAuditToolOutput(messages.slice(0,2),request,'read_file',
                    JSON.stringify(page),exchangeBudget,true);
                  const delivered=JSON.parse(fitted.output) as typeof page;
                  if(!delivered.text || delivered.end<=delivered.start)break;
                  // Track the real source span through the same controller
                  // callbacks as an ordinary tool read; do not synthesize it.
                  workflow.read(caller);
                  workflow.observe(action,fitted.output);
                  const callerEvidenceId=await controllerArchive?.append('source',{path:caller,start:delivered.start,end:delivered.end,content:delivered.text,nextOffset:delivered.nextOffset},{source:caller});
                  if(callerEvidenceId)workflow?.recordSourceEvidence(caller,callerEvidenceId);
                  limits.onRead?.(caller,{start:delivered.start,end:delivered.end});
                  navigation.observe('read_file',caller,offset,'',delivered);
                  allowance.read(caller,delivered.start,delivered.end,turn);
                  successfulReads++;
                  sourceTotals.set(caller,delivered.totalCharacters);
                  recentActions.set(JSON.stringify(['read_file',caller,offset,'']),
                    {turn,nextOffset:delivered.nextOffset,response:fitted.message});
                  if(delivered.nextOffset===null)
                    terminalReadPages.set(caller,{offset,response:fitted.message});
                  messages.push(request,fitted.message);
                  await appendFile(logFile,'[CONTROLLER_CALLER_PAGE_READ] '+
                    JSON.stringify({path:caller,start:delivered.start,end:delivered.end,
                      nextOffset:delivered.nextOffset,claimedLine:line})+'\n');
                  seenLines+=(delivered.text.match(/\n/g)||[]).length;
                  if(seenLines>=Number(line) || delivered.nextOffset===null) {
                    reached=seenLines>=Number(line)-1;
                    break;
                  }
                  if(delivered.nextOffset===null || delivered.nextOffset<=offset)break;
                  offset=delivered.nextOffset;
                }
                if(reached) {
                  repeatedRejectedConclusions=0;
                  lastRejectedConclusion='';
                  await appendFile(logFile,'[CONTROLLER_CALLER_PAGE_READY] '+
                    JSON.stringify({path:caller,line})+'\n');
                }
              } catch(error) {
                await appendFile(logFile,'[CONTROLLER_CALLER_PAGE_UNAVAILABLE] '+
                  JSON.stringify({path:caller,error:String(error).slice(0,250)})+'\n');
              }
            }
          }
          const observations=workflow?.snapshot().observations.filter(o=>o.status==='behavior_observed')||[];
          if(observations.length) {
            const normalizedConclusion=message.content.replace(/\s+/g,' ').trim().slice(0,1000);
            repeatedRejectedConclusions=normalizedConclusion===lastRejectedConclusion
              ? repeatedRejectedConclusions+1 : 1;
            lastRejectedConclusion=normalizedConclusion;
            const observed=observations.at(-1)!;
            const known=(limits.initialSourcePaths||[]).filter(p=>
              p.startsWith('source-') && /\.(?:py|js|mjs|cjs|java|sol)$/.test(p) && p!==observed.path);
            known.sort((a,b)=>Number(/(?:caller|handler|route|controller|entry|server)/i.test(b))-
              Number(/(?:caller|handler|route|controller|entry|server)/i.test(a)));
            if(repeatedRejectedConclusions>=2 && known.length && postProbeRecoveryReads<2) {
              const required=known[postProbeRecoveryReads%known.length];
              postProbeRecoveryReads++;
              workflow!.requireSource(required);
              requireInvestigationAfterEmpty=true;
              emptyFinals=0;
              await appendFile(logFile,'[POST_PROBE_RECOVERY] '+JSON.stringify({
                path:required,observation:observed,repeatedRejectedConclusions
              })+'\n');
            }
            // A bounded classification test may already have all its results
            // verified by independent local probes. When the model repeatedly
            // emits a schema-invalid boolean, assemble only the recorded
            // per-file observations and let the caller's validator decide.
            // Never infer a vulnerability or bypass the final validator.
            if(repeatedRejectedConclusions>=2 && limits.validateFinal &&
               limits.initialSourcePaths?.length) {
              const recorded=workflow!.snapshot().observations;
              const paths=[...new Set(limits.initialSourcePaths)];
              const complete=paths.every(path=>recorded.some(o=>o.path===path &&
                (o.status==='behavior_observed'||o.status==='behavior_not_observed')));
              if(complete) {
                const classification=JSON.stringify({files:paths.map(path=>{
                  const observation=recorded.find(o=>o.path===path &&
                    (o.status==='behavior_observed'||o.status==='behavior_not_observed'))!;
                  return {path,rawMarkup:observation.status==='behavior_observed'};
                })});
                if(!(await limits.validateFinal(classification))) {
                  await appendFile(logFile,'[CONTROLLER_VERIFIED_CLASSIFICATION_FINAL] '+
                    JSON.stringify({paths,observations:recorded.length})+'\n');
                  return classification;
                }
              }
            }
            if(repeatedRejectedConclusions>=4) {
              await appendFile(logFile,'[AUDIT_INCOMPLETE_POST_PROBE] '+JSON.stringify({
                reason:'Repeated rejected conclusions despite reproduced behavior',
                observation:observed,attempts:repeatedRejectedConclusions
              })+'\n');
              throw new Error('AUDIT_INCOMPLETE_POST_PROBE: probe evidence preserved, but the model could not produce a supported conclusion after bounded recovery; see audit log');
            }
            const guidance='Verified probe (not automatically a vulnerability): '+
              JSON.stringify(observed)+'. Remaining requirements: establish caller reachability, input provenance, mitigations and impact from source before reporting. '+
              (known.length?'Inspect caller candidate '+known[0]+' and cite its exact relevant lines. Caller methods of classes (such as do_GET) are NOT top-level functions and must not be submitted to the single-argument source verifier; inspect their call expressions and user-input flow from source instead. ':'Identify a concrete missing caller source. ')+
              'Allowed conclusions must cite actual recorded caseId/evidenceFile and caller evidence; otherwise explicitly state which requirement remains unverified. Never claim there was no testable candidate.';
            workflow!.feedback(guidance,true);
            await appendFile(logFile,'[POST_PROBE_EVIDENCE_GUIDANCE] '+guidance+'\n');
          } else {
            repeatedRejectedConclusions=0;
            lastRejectedConclusion='';
          }
          // Escalate only repeated output-format failures; evidence-coverage failures
          // must remain free to request more source pages.
          invalidReviewFinals = !workflow && feedback.startsWith('Return the requested review JSON')
            ? invalidReviewFinals + 1 : 0;
          // Fresh evidence may be needed, but a rejected final must not reset
          // the inspection checkpoint and reopen an unconditional read loop.
          // Retain read-action history: rejecting a final answer does not make prior pages new evidence.
          if(!workflow)recentActions.clear(); // Legacy no-workflow repair may explicitly require a fresh source read.
          stalledActions=0;workflow?.finalRejected(feedback);
          if(workflow && feedback.startsWith('No supported probe has completed.') &&
             !workflow.snapshot().observations.length) {
            unsupportedFinalRejections++;
            if(unsupportedFinalRejections>=2) {
              const next=workflow.requireNextUnreadSource(limits.initialSourcePaths||[]);
              if(next) {
                unsupportedFinalRejections=0;
                requireInvestigationAfterEmpty=true;
                await appendFile(logFile,'[REJECTED_FINAL_SOURCE_HANDOFF] '+JSON.stringify({next})+'\n');
              }
            }
          } else unsupportedFinalRejections=0;
          if(workflow?.snapshot().observations.some(o=>o.status==='behavior_observed')) {
            const observed=workflow.snapshot().observations.filter(o=>o.status==='behavior_observed').at(-1)!;
            const required=(limits.initialSourcePaths||[]).find(p=>p.startsWith('source-') &&
              /(?:caller|handler|route|controller|entry|server)/i.test(p));
            workflow.feedback('Verified observation '+JSON.stringify(observed)+
              '. Caller reachability and impact still require independent source support. '+
              (required?'Reinspect '+required+'. ':'Locate caller source. ')+
              'Use recorded evidence identifiers; do not claim no testable candidate.');
          }
          // A validator that explicitly requires a probe must not let a small
          // model repeat unsupported final classifications indefinitely.
          // Do not force the first declared function: that could be unrelated.
          // Require the model to choose a relevant, declared probe target.
          if(workflow && /\btest\b.*\bbefore\b.*\bclassif/i.test(feedback)) {
            rejectedRequiredProbeFinals++;
            if(rejectedRequiredProbeFinals>=2) {
              const snapshot=workflow.snapshot();
              const attempted=new Set(snapshot.observations.filter(o=>
                (o.status==='behavior_observed'||o.status==='behavior_not_observed') &&
                (!limits.requiredProbeKind||o.kind===limits.requiredProbeKind))
                .map(o=>JSON.stringify([o.path,o.function])));
              const candidates:string[]=[];
              for(const path of snapshot.readPaths) {
                if(!/\.(?:py|js|mjs|cjs|java)$/.test(path))continue;
                try {
                  const full=await safePath(path);
                  for(const selector of await sourceDeclarationHints(full)) {
                    if(attempted.has(JSON.stringify([path,selector])))continue;
                    if(await declaredProbeTarget(full,selector))candidates.push(path+':'+selector);
                    if(candidates.length>=12)break;
                  }
                }catch{}
                if(candidates.length>=12)break;
              }
              if(candidates.length) {
                workflow.requireProbePlanning(candidates.join(', '),limits.requiredProbeKind);
                await appendFile(logFile,'[REJECTED_FINAL_PROBE_HANDOFF] '+JSON.stringify({candidates})+'\n');
              }
            }
          } else rejectedRequiredProbeFinals=0;
          // Coverage validator can name the next inspected candidate. Make the
          // next source read deterministic instead of asking a small model to
          // infer another path from an already rejected conclusion.
          // A recorded probe can be real while its caller context has fallen
          // out of Qwen's compacted conversation. Force one source-backed caller
          // read before letting repeated incomplete finals burn the time budget.
          if(workflow && /A supported source probe HAS completed|no testable candidate|no probes/i.test(feedback) &&
             workflow.snapshot().observations.some(o=>o.status==='behavior_observed')) {
            const inspected=new Set(workflow.snapshot().readPaths);
            const paths=(limits.initialSourcePaths||[]).filter(path=>
              path.startsWith('source-') && /\.(?:py|js|mjs|cjs|java|sol)$/.test(path));
            const next=paths.find(path=>!finalCallerRecoveries.has(path) &&
              (/(?:caller|handler|route|controller|entry|server)/i.test(path) || !inspected.has(path)));
            if(next) {
              finalCallerRecoveries.add(next);
              workflow.requireSource(next);
              requireInvestigationAfterEmpty=true;
              emptyFinals=0;
              await appendFile(logFile,'[CALLER_CONTEXT_RECOVERY] '+JSON.stringify({path:next})+'\n');
            }
          }
          const requiredNextSource=feedback.match(/Suggested next file:\s*(\S+?\.(?:sol|java|ts|tsx|js|jsx|py))\b/i)?.[1];
          if(requiredNextSource && workflow && !terminalReadPages.has(requiredNextSource)) {
            workflow.requireSource(requiredNextSource);
            // A typed-final retry must not trap the model in final-only mode
            // when source coverage requires a new concrete tool action.
            requireInvestigationAfterEmpty=true;
            emptyFinals=0;
          }
          // A controller-owned caller read can append source exchanges after the
          // rejected final. Start a separate bounded correction exchange instead
          // of attaching validation output to the caller-page read group.
          const rejected:Message={role:"assistant",content:"Final rejected; reassess recorded source and probe evidence."};
          messages.push(rejected);
          await appendFile(logFile, "[FINAL_REJECTED] " + feedback + "\n");
          const evidencePacket=limits.finalEvidencePacket ? await limits.finalEvidencePacket() : '';
          if(evidencePacket)await appendFile(logFile,'[CONTROLLER_FINAL_EVIDENCE_HANDOFF] '+
            JSON.stringify({length:evidencePacket.length})+'\n');
          messages.push(fitAuditToolOutput(messages.slice(0,2),rejected,"final_validation",feedback +
            (evidencePacket ? "\nController-verified report input (actual stored evidence, not model speculation):\n"+
              evidencePacket.slice(0,2400)+"\nUse these facts to organize your findings JSON. Supply only your evidence-based impact, severity, and falsification interpretation." : "") +
            (workflow?.snapshot().observations.some(o=>o.status==='behavior_observed') ? "\n"+workflow.note() : "") +
            "\nRe-read the specified source when necessary. /no_think",exchangeBudget,true).message);
          continue;
        }
        controller.signal.throwIfAborted();
        invalidReviewFinals=0;
        unsupportedFinalRejections=0;
        // Only a final accepted by the independent validator can resolve
        // a reproduced case as verified. Reject unsupported model claims.
        if(workflow) {
          let accepted:any;
          try{accepted=JSON.parse(message.content);}catch{}
          const findings=Array.isArray(accepted?.findings)?accepted.findings:[];
          for(const observation of workflow.snapshot().observations)
            if(observation.status==='behavior_observed')
              workflow.acceptedReview(observation.path,observation.function,observation.kind,
                'validated-final:'+String(observation.caseId||observation.evidenceFile||'review'),
                findings.some((finding:any)=>finding?.caseId===observation.caseId));
          await persistMemory();
        }
        finalAnswer=message.content;stoppingReason="Validated final answer";
        return message.content;
      }
      if(requireInvestigationAfterEmpty && message.tool_calls?.length) {
        requireInvestigationAfterEmpty=false;
        emptyFinals=0;
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
          let path = String(call.function.arguments?.path ?? ".");
          if (["read_file","list_files","search_files","outline_solidity","read_solidity"].includes(name))
            path=await canonicalSourceReadPath(path);
          let full = await safePath(path);
          call.function.arguments.path=path;
          let offset = pageOffset(call.function.arguments?.offset);
          const keyAt=(at:number)=>JSON.stringify([name,relative(root,full),at,String(call.function.arguments?.query ?? "")]);
          let actionKey = keyAt(offset);
          const inspection = ["read_file","list_files","search_files","outline_solidity","read_solidity"].includes(name);
          let previous = recentActions.get(actionKey);
          // An evicted tool result cannot be used as evidence by the model.
          // Honor a reread after compaction instead of penalizing our own prompt.
          if (previous?.response && !messages.includes(previous.response)) {
            await appendFile(logFile,"[CONTEXT_REREAD] "+JSON.stringify({tool:name,path,offset})+"\n");
            // In a compacted prompt a completed page may be replayed once for
            // genuine context recovery. Never reset a live pagination cursor,
            // and never permit unlimited identical recovery reads.
            if(previous.nextOffset===null && (sourceReadCounts.get(actionKey)||0)<2)previous=undefined;
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
          // A completed source page remains completed across model context
          // compaction. The controller, not Qwen, chooses an unread in-scope
          // source when Qwen repeats that page; do not spend another model
          // turn on the same text or pretend this creates new evidence.
          if(name==='read_file' && fullIndexMode &&
             (terminalReadPages.has(path) || previous?.nextOffset===null)) {
            const complete=terminalReadPages.get(path);
            const prior=complete?.response;
            // Exactly one source-page replay is permitted when compaction has
            // genuinely evicted the prior evidence. Do not substitute a
            // different file for an already-satisfied required caller.
            if(complete && prior && !messages.includes(prior) &&
               !terminalPageRecoveries.has(path)) {
              terminalPageRecoveries.add(path);
              offset=complete.offset;
              call.function.arguments.offset=offset;
              actionKey=keyAt(offset);
              previous=undefined;
              await appendFile(logFile,'[INDEXED_CONTEXT_RECOVERY] '+
                JSON.stringify({path,offset,turn:turn+1})+'\n');
            } else {
              await appendFile(logFile,'[INDEXED_COMPLETED_READ_REJECTED] '+
                JSON.stringify({path,turn:turn+1})+'\n');
              // Advance only to a controller-selected, previously unread source.
              // Never invent a read or erase the completed page's evidence.
              // readPaths can include a file after its first page, while its
              // controller-owned pagination still has unread pages. Prefer
              // a source not yet completed over reissuing a terminal page.
              // Production hunts must not fall back to large test fixtures
              // after exhausting a contract: the 88mph laptop run repeatedly
              // paged test/base.js while the model requested SafeERC20.sol.
              // Prefer production source with a recorded unread cursor.
              const candidates=(limits.initialSourcePaths||[]).filter(candidate=>
                /^source-[0-9]+\//.test(candidate) &&
                /\.(?:sol|java|py|js|mjs|cjs)$/.test(candidate) &&
                candidate!==path && !terminalReadPages.has(candidate));
              const production=candidates.filter(candidate=>
                !/(?:^|\/)(?:test|tests|__tests__|fixtures|mocks)(?:\/|$)/i.test(candidate));
              const ranked=production.length ? production : candidates;
              const required=process.env.LOCAL_CONTROLLER_OWNED_ACTIONS!=='false'
                ? workflow?.requireNextUnreadSource(limits.initialSourcePaths||[]) : null;
              const next=required && required!==path && ranked.includes(required)
                ? required : process.env.LOCAL_CONTROLLER_OWNED_ACTIONS!=='false' ? ranked[0] || null : null;
              await appendFile(logFile,'[INDEXED_SOURCE_RECOVERY_DECISION] '+
                JSON.stringify({from:path,required,rankedRemaining:ranked.length,
                  next,completedFiles:terminalReadPages.size,turn:turn+1})+'\n');
              if(next && next!==path) {
                const nextFull=await safePath(next);
                await appendFile(logFile,'[INDEXED_CONTROLLER_SOURCE_HANDOFF] '+
                  JSON.stringify({from:path,to:next,turn:turn+1})+'\n');
                // Resume the controller-owned page cursor. Selecting a file
                // with an already-recorded first page at offset zero traps the
                // small model in a NO_PROGRESS loop until all turns expire.
                path=next;full=nextFull;offset=0;
                actionKey=keyAt(offset);
                previous=recentActions.get(actionKey);
                const visitedOffsets=new Set<number>();
                while(previous?.nextOffset!=null && previous.nextOffset>offset &&
                      !visitedOffsets.has(offset)) {
                  visitedOffsets.add(offset);
                  offset=previous.nextOffset;
                  actionKey=keyAt(offset);
                  previous=recentActions.get(actionKey);
                }
                call.function.arguments.path=next;
                call.function.arguments.offset=offset;
                await appendFile(logFile,'[INDEXED_CONTROLLER_CURSOR_RESUME] '+
                  JSON.stringify({path:next,offset,turn:turn+1})+'\n');
              } else {
                // Source-index exhaustion is a phase transition, not an audit failure.
                // Preserve the existing evidence and give the model a tool-level
                // rejection so it can select a declared probe or evidence-backed
                // final. Do not fabricate a probe or silently mark a hunt complete.
                const observations=workflow?.snapshot().observations||[];
                const feedback='All controller-ranked source files have reached their terminal page. '+
                  'The requested source '+path+' is already recorded. Source reading is complete; '+
                  'your NEXT action must be plan_probe for a concrete declared function with '+
                  'a falsifiable hypothesis, verify_source for an already pending probe, '+
                  'or final using only verified evidence. Do not request read_file again. '+
                  'Recorded observations: '+JSON.stringify(observations.slice(-6)).slice(0,1800);
                workflow?.feedback(feedback,true);
                await appendFile(logFile,'[INDEXED_SOURCE_TO_EVIDENCE_HANDOFF] '+
                  JSON.stringify({path,completedFiles:terminalReadPages.size,
                    observations:observations.length,pending:!!workflow?.snapshot().pending,
                    turn:turn+1})+'\n');
                throw new Error('SOURCE_INDEX_EXHAUSTED: '+feedback);
              }
            }
          }
          if(name==='read_file' && workflow && !fullIndexMode &&
             (terminalReadPages.has(path) || previous?.nextOffset===null)) {
            const completed=terminalReadPages.get(path);
            const recordedResponse=completed?.response || (completed
              ? recentActions.get(keyAt(completed.offset))?.response : previous?.response);
            const evicted=!!recordedResponse && !messages.includes(recordedResponse);
            if(completed && evicted && !terminalPageRecoveries.has(path)) {
              // Exactly one bounded recovery of a compacted source result.
              terminalPageRecoveries.add(path);
              offset=completed.offset;
              call.function.arguments.offset=offset;
              actionKey=keyAt(offset);
              previous=undefined;
              await appendFile(logFile,'[TERMINAL_PAGE_CONTEXT_RECOVERY] '+
                JSON.stringify({path,offset,turn:turn+1})+'\n');
            } else {
              // Choose from the entire authorized, source-ranked candidate list,
              // not the last page or the exhausted eight-file prefetch.
              const readPaths=new Set(workflow.snapshot().readPaths);
              const next=(limits.initialSourcePaths||[]).find(candidate=>
                /^source-[0-9]+\//.test(candidate) &&
                /\.(?:py|js|mjs|cjs|java|sol)$/.test(candidate) &&
                candidate!==path && !readPaths.has(candidate));
              if(next) {
                const nextFull=await safePath(next);
                await appendFile(logFile,'[CONTROLLER_READ_REDIRECT] '+
                  JSON.stringify({from:path,requestedOffset:offset,to:next,turn:turn+1})+'\n');
                path=next;full=nextFull;offset=0;
                call.function.arguments.path=path;
                call.function.arguments.offset=0;
                actionKey=keyAt(0);
                previous=recentActions.get(actionKey);
              } else {
                workflow.feedback('All source pages in the candidate queue are complete. Choose a supported probe, another evidence-bearing search, or a fact-grounded final.');
                throw new Error('Completed source page has already been recorded. No new eligible source remains; do not reread it.');
              }
            }
          }
          const repeatCount=sourceReadCounts.get(actionKey)||0;
          if(inspection && previous && (turn-previous.turn<=8 || previous.nextOffset===null || repeatCount>=2)) {
            stalledActions++;
            const instruction = previous.nextOffset != null
              ? `Continue at offset ${previous.nextOffset}, or choose a different file/search.`
              : "This action is complete. Choose a different file/search or proceed to a supported test or evidence-based final answer.";
            await appendFile(logFile, "[NO_PROGRESS] " + JSON.stringify({action:name,path,offset,attempt:stalledActions}) + "\n");
            if(stalledActions>=3 && workflow) {
              // A small CPU model can request a page whose content has fallen
              // out of active context. Repeated completed-page requests are
              // recoverable navigation feedback, not a fatal hunt failure.
              // Keep the finite turn allowance as the ultimate bound.
              await appendFile(logFile,"[CONTEXT_RECOVERY] "+JSON.stringify({tool:name,path,offset,attempt:stalledActions})+"\n");
              blockCompletedReadsUntil=Math.max(blockCompletedReadsUntil,turn+4);
              // A required caller/source read can be satisfied by a previously
              // completed page after context compaction. If that reread is now
              // rejected as a duplicate, release the requiredSource constraint;
              // otherwise it forces read_file forever and hides final/probe.
              // No new source span, observation, or finding is credited here.
              if(previous.nextOffset===null && workflow.snapshot().readPaths.includes(path)) {
                workflow.read(path);
                requireInvestigationAfterEmpty=false;
                await appendFile(logFile,'[COMPLETED_SOURCE_REQUIREMENT_RELEASED] '+JSON.stringify({path,offset})+'\n');
              }
              workflow.feedback('This exact source page is already recorded and rereading it produced no new evidence. Next choose an evidence-backed final, a different eligible probe, or a specific continuation. Do not reread this completed page.');
              stalledActions=0;
              throw new Error("Completed source page is already recorded. Choose another selected source or use the saved observation; do not request this completed page again. "+navigation.hint());
            }
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
            if(!["solidity_sequence","java_sequence","python_sequence","javascript_sequence"].includes(kind) && rawSequence!==undefined)throw new Error("Sequence requires a sequence kind");
            const sequence=kind==="solidity_sequence"?soliditySequenceSchema.parse(rawSequence):kind==="java_sequence"?javaSequenceSchema.parse(rawSequence):["python_sequence","javascript_sequence"].includes(kind)?polyglotSequenceSchema.parse(rawSequence):undefined;
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
            // A terminal page must never be scheduled again, even if formatting
            // its optional probe menu fails. The source cursor is authoritative.
            const readPath=relative(root,full).split(sep).join('/');
            if(rawPage.nextOffset===null)terminalReadPages.set(readPath,{offset:rawPage.start});
            output = fitOutput(JSON.stringify(rawPage)).output;
            const page = JSON.parse(output) as typeof rawPage;
            // Present grounded choices as soon as a file's last page is read,
            // before Qwen needs to invent a probe target or a Solidity sequence.
            if(workflow && page.nextOffset===null && ['.sol','.py','.js','.mjs','.cjs','.java'].some(ext=>full.endsWith(ext))) {
              try {
                const menu=full.endsWith('.sol')
                  ? await solidityIndex.probeMenu(full,16)
                  : await probeChoices(full,'html_reflection',12);
                if(menu.length) {
                  const original=JSON.parse(output);
                  original.probeMenu=menu;
                  original.probeMenuNote=full.endsWith('.sol')
                    ? 'Select actual contract methods. Send means state-changing transaction, call means read assertion. A valid sequence needs grounded constructor arguments and an expected call value.'
                    : 'These are source-derived function selectors, not proven vulnerabilities. Choose a probe kind matching inspected behavior.';
                  output=JSON.stringify(original);
                  await appendFile(logFile,'[PROBE_INTENT_MENU] '+JSON.stringify({path:relative(root,full),count:menu.length})+'\n');
                }
              }catch{}
            }

          } else throw new Error("Unknown tool");
          // Optional probe menus must never invalidate a successfully read page.
          // Fall back to the source-only page if the enlarged payload cannot fit.
          if(name==='read_file' && !output.startsWith('Tool error:')) {
            try {
              const fitted=fitOutput(output).output;
              JSON.parse(fitted);
              output=fitted;
            } catch {
              output=fitOutput(JSON.stringify(await readSourcePage(full,offset,pageSize))).output;
              await appendFile(logFile,'[PROBE_MENU_FIT_FALLBACK] '+JSON.stringify({path:relative(root,full),offset})+'\\n');
            }
          } else output=fitOutput(output).output;
          if(name==='read_file') {
            // Menus and escaping can force a second fit. Only the final
            // delivered range is read evidence or a pagination cursor.
            const page=JSON.parse(output);
            const sourcePath=relative(root,full).split(sep).join('/');
            sourceTotals.set(sourcePath,page.totalCharacters);
            allowance.read(sourcePath,page.start,page.end,turn+1);
            activityCount=page.text.length;successfulReads++;
            workflow?.read(sourcePath);
            limits.onRead?.(sourcePath,{start:page.start,end:page.end});
            await appendFile(logFile,'[READ_OK] '+sourcePath+
              ` offset=${page.start} end=${page.end} nextOffset=${page.nextOffset}\n`);
            if(page.nextOffset===null)terminalReadPages.set(sourcePath,{offset:page.start});
            const id=await controllerArchive?.append('source',{
              path:sourcePath,start:page.start,end:page.end,content:page.text,nextOffset:page.nextOffset
            },{source:sourcePath});
            if(id)workflow?.recordSourceEvidence(sourcePath,id);
          }
          try {navigation.observe(name,relative(root,full).split(sep).join("/") || ".",offset,String(call.function.arguments?.query || ""),JSON.parse(output));}catch{}
          stalledActions=0;
          if(inspection) {
            let nextOffset:number|null|undefined;
            try {nextOffset=JSON.parse(output).nextOffset;}catch{}
            recentActions.set(actionKey,{turn,nextOffset});
            sourceReadCounts.set(actionKey,(sourceReadCounts.get(actionKey)||0)+1);
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
            // A generic navigation hint can be empty once all seeded pages have been read.
            // Give the small model exact, successful source paths instead of asking
            // it to reconstruct a long or random filename after an ENOENT.
            const verifiedPaths=[...new Set((workflow?.snapshot().readPaths ||
              navigation.snapshot().recent.filter(entry=>entry.action==='read_file' && typeof entry.path==='string')
                .map(entry=>String(entry.path))).filter(path=>path.length<=512))].slice(-4);
            output+=" This path does not exist. Do not repeat it. "+
              (verifiedPaths.length ? "Exact successfully read source paths (copy exactly; no automatic substitution): "+JSON.stringify(verifiedPaths)+". " : "")+
              "Use list_files on a known directory or select an existing source hint. "+navigation.hint();
            if(count>=3)fatalToolError="AUDIT_STALLED: repeated missing source path after corrective feedback; inspection incomplete";
          }
        }
        if(['verify_source','verify_python'].includes(call.function.name) && !output.startsWith('Tool error:')) {
          const result=JSON.parse(output);
          const sourcePath=String(call.function.arguments?.path||'');
          const id=await controllerArchive?.append('probe',{
            path:sourcePath,function:call.function.arguments?.query,
            kind:call.function.arguments?.kind,result
          },{source:sourcePath,caseId:typeof result.caseId==='string'?result.caseId:undefined});
          if(id)workflow?.recordEvidence(id);
        }
        workflow?.observe({action:call.function.name,path:String(call.function.arguments?.path || ''),
          query:String(call.function.arguments?.query || ''),answer:String(call.function.arguments?.kind || ''),
          sequence:call.function.arguments?.sequence},output);
        let probeStatus:string|undefined;
        if(["verify_source","verify_python"].includes(call.function.name)){
          const probePath=String(call.function.arguments?.path||'');
          const probeSelector=String(call.function.arguments?.query||'');
          const probeKind=String(call.function.arguments?.kind||'');
          let disposition='failed';
          let dispositionReason=output.slice(0,240);
          try {
            const result=JSON.parse(output);
            disposition=String(result.status||'unknown');
            dispositionReason=String(result.detail||result.limitation||result.error||'verifier_completed').slice(0,240);
          }catch{}
          await recordProbeDisposition(probePath,probeSelector,probeKind,disposition,dispositionReason);
          try {
            const probeResult=JSON.parse(output);
            probeStatus=String(probeResult.status || "unknown").slice(0,100);
            // A successful reproduction is not the end of the investigation:
            // require independently inspected caller/reachability evidence now,
            // before the model can spend 80 turns on empty conclusions.
            if(workflow && probeStatus==='behavior_observed') {
              // Only the controller can appoint the next caller and lock a
              // verified case. A model's invented paths or negative tests
              // cannot supersede an earlier verified observation.
              let handoff: {callers:string[];promoted?:{caseId:string;path:string;selector:string;kind:string}}|null=null;
              if(typeof probeResult.caseId==='string' && limits.onVerifiedCase && process.env.LOCAL_CONTROLLER_OWNED_ACTIONS!=='false') {
                handoff=await limits.onVerifiedCase(
                  probeResult.caseId,String(call.function.arguments?.path||''),
                  String(call.function.arguments?.query||''),
                  String(call.function.arguments?.kind||''));
              }
              if(handoff?.promoted) {
                const promoted=handoff.promoted;
                workflow.observe({action:'verify_source',path:promoted.path,query:promoted.selector,
                  answer:promoted.kind} as any,
                  JSON.stringify({status:'behavior_observed',behavior_observed:true,caseId:promoted.caseId}));
              }
              const authoritativeCallers=handoff?.callers||null;
              const focusId=handoff?.promoted?.caseId||probeResult.caseId;
              if(authoritativeCallers?.length && workflow.focusVerifiedEvidence(focusId)) {
                const readPaths=new Set(workflow.snapshot().readPaths);
                workflow.requireSources(authoritativeCallers);
                requireInvestigationAfterEmpty=false;
                emptyFinals=0;
                await appendFile(logFile,'[CONTROLLER_VERIFIED_CASE_FOCUS] '+
                  JSON.stringify({caseId:focusId,sourceCaseId:probeResult.caseId,callers:authoritativeCallers,
                    promoted:!!handoff?.promoted,
                    alreadyRead:authoritativeCallers.filter(path=>readPaths.has(path))})+'\n');
              }
              const testedPath=String(call.function.arguments?.path||'');
              const readPaths=new Set(workflow.snapshot().readPaths);
              const candidates=(limits.initialSourcePaths||[]).filter(p=>
                p.startsWith('source-') && p!==testedPath &&
                /\.(?:py|js|mjs|cjs|java|sol)$/.test(p));
              candidates.sort((a,b)=>
                Number(/(?:caller|handler|route|controller|entry|server)/i.test(b))-
                Number(/(?:caller|handler|route|controller|entry|server)/i.test(a)));
              const caller=authoritativeCallers?.[0] || candidates[0];
              if(caller && !workflow.snapshot().verifiedEvidenceFocus) {
                const callerAlreadyRead=readPaths.has(caller);
                workflow.requireSource(caller);
                // A completed caller read satisfies the source requirement.
                // Do not suppress final forever when the controller already
                // holds its exact source and observed probe evidence.
                if(!callerAlreadyRead) {
                  requireInvestigationAfterEmpty=true;
                  emptyFinals=0;
                } else {
                  requireInvestigationAfterEmpty=false;
                }
                await appendFile(logFile,'[POST_PROBE_CALLER_REQUIRED] '+
                  JSON.stringify({testedPath,caller,alreadyRead:callerAlreadyRead})+'\n');
              }
            }

            // A negative isolated probe is useful evidence about one method,
            // not grounds to abandon the connected source graph. Move to the
            // next ranked unread candidate instead of spending turns on the
            // same disproved helper or an unsupported final.
            if(workflow && probeStatus==='behavior_not_observed') {
              const next=workflow.requireNextUnreadSource(limits.initialSourcePaths||[]);
              if(next) {
                await appendFile(logFile,'[NEGATIVE_PROBE_SOURCE_HANDOFF] '+JSON.stringify({
                  testedPath:String(call.function.arguments?.path||''),next})+'\n');
              }
            }
            await appendFile(logFile,"[PROBE_RESULT] "+JSON.stringify({path:call.function.arguments?.path,function:call.function.arguments?.query,kind:call.function.arguments?.kind,status:probeStatus,caseId:probeResult.caseId||null,evidenceFile:probeResult.evidenceFile,detail:String(probeResult.detail||probeResult.limitation||probeResult.reason||probeResult.error||"").slice(-700)})+"\n");
          }catch{}
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
        if(workflow && probeStatus==='invalid_probe' && String(call.function.arguments?.path || '').endsWith('.java')) {
          try {
            const full=await safePath(String(call.function.arguments?.path));
            const eligible=await supportedJavaProbeHints(full);
            if(eligible.length) {
              messages.push({role:'user',content:'The previous Java probe signature was rejected by the isolated verifier. Compatible one-input text/byte methods declared in this same file: '+eligible.join(', ')+'. Select a relevant method and supported probe kind only if its source behavior warrants a test; otherwise continue source inspection. /no_think'});
              await appendFile(logFile,'[JAVA_PROBE_ELIGIBLE_HINTS] '+JSON.stringify({path:call.function.arguments?.path,selectors:eligible})+'\n');
            }
          }catch{}
        }
        // Give the model actual indexed Solidity declarations after a completed
        // paginated read. This does not plan or execute a probe: candidates still
        // have to pass the existing declaration, workflow and verifier gates.
        if(workflow && call.function.name==='read_file' && !output.startsWith('Tool error:')) {
          try {
            const page=JSON.parse(output);
            const path=String(call.function.arguments?.path || '');
            if(path.endsWith('.sol') && page.nextOffset===null) {
              const full=await safePath(path);
              const outline=await solidityIndex.outline(full,0,1200);
              const declarations=JSON.stringify(outline);
              const guidance='Completed Solidity source: '+path+
                '. Indexed declarations (use exact Contract.function IDs where eligible): '+declarations+
                '. Choose only a supported, declared probe target; otherwise inspect the next prioritized source. /no_think';
              if(JSON.stringify(messages).length+guidance.length<messageBudget-800) {
                messages.push({role:'user',content:guidance});
                await appendFile(logFile,'[SOLIDITY_DECLARATIONS_GUIDED] '+JSON.stringify({path,characters:declarations.length})+'\n');
              } else {
                await appendFile(logFile,'[SOLIDITY_DECLARATIONS_DEFERRED] Context budget; use outline_solidity explicitly\n');
              }
            }
          }catch(error) {
            await appendFile(logFile,'[SOLIDITY_DECLARATIONS_UNAVAILABLE] '+String(error).slice(0,160)+'\n');
          }
        }
        if(completedActionKey)recentActions.get(completedActionKey)!.response=responseMessage;
        if(call.function.name==='read_file'){
          const sourcePath=String(call.function.arguments?.path||'');
          const terminal=terminalReadPages.get(sourcePath);
          if(terminal && terminal.offset===pageOffset(call.function.arguments?.offset))terminal.response=responseMessage;
        }
        await persistMemory();
        // The independent reviewer may have supplied a valid conservative
        // verdict before its mandatory pagination completed. If subsequent
        // reads now satisfy every validator, preserve that judgment instead
        // of forcing Qwen to regenerate identical JSON until timeout.
        if(limits.recoverFinal) {
          const recovered=await limits.recoverFinal();
          if(recovered) {
            controller.signal.throwIfAborted();
            finalAnswer=recovered;
            stoppingReason="Controller recovered validated final after evidence reads";
            await appendFile(logFile,'[CONTROLLER_FINAL_RECOVERED] '+JSON.stringify({turn:turn+1})+'\n');
            return recovered;
          }
        }
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
