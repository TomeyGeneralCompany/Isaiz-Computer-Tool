import { randomBytes, createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { eq, and, inArray } from "drizzle-orm";
import { z } from "zod";
import { authorizedSourceUrls, assertAuthorizedTarget, getConfig, getDb, schema, createLogger,
  readSubmissionOutbox, submitOnce, type SecurityProgram, type SecurityFinding } from "@bounty/core";
import { fetchProgramScopes, fetchProgramPolicy, fetchProgramSignalRequirement, prepareSubmission, submitReport } from "@bounty/security-discovery";
import { cloneAuthorizedSource } from "./authorized-source";
import { runLocalAudit } from "./local-ollama-runner";
import { createProbeSession, readSourceCase, replaySourceCase, type SourceCase, type ProbeRepository } from "./source-reproduction";
import { writeSecuritySolverStatus, clearSecuritySolverStatus, writeAdversarialReviewStatus, clearAdversarialReviewStatus } from "./status";
import type { SecuritySolveResult, ParsedFinding } from "./claude-runner";
const log=createLogger("local-program-flow");
const sha=z.string().regex(/^[a-f0-9]{64}$/);
const candidateSchema=z.object({caseId:sha,title:z.string().min(10).max(200),
  impact:z.string().min(20).max(2000),callerFile:z.string().min(1).max(4096),callerLine:z.number().int().positive(),
  falsification:z.string().min(40).max(2000)}).strict();
const huntSchema=z.object({findings:z.array(candidateSchema).max(3)}).strict();
const score=z.number().int().min(0).max(3);
const reviewSchema=z.object({verdict:z.enum(["approve","reject"]),recommendation:z.enum(["submit","submit_cautiously","dont_submit"]),
  bet100:z.boolean(),rubric:z.object({exploitability:score,impactSeverity:score,evidenceQuality:score,novelty:score,scopeAlignment:score}).strict(),
  issues:z.array(z.object({category:z.string(),severity:z.enum(["fatal","warning","info"]),description:z.string()})).max(20),reasoning:z.string().min(20).max(4000)}).strict();
async function workspace(prefix:string):Promise<string> {
  const base=join(process.env.PROJECT_ROOT || process.cwd(),".workspaces");await mkdir(base,{recursive:true,mode:0o700});
  return mkdtemp(join(base,prefix));
}
function scopes(program:SecurityProgram):unknown {const parsed=JSON.parse(program.scopeSummary || "{}");return Array.isArray(parsed)?parsed:parsed.scopes;}
function sourceFileInWorkspace(repo:ProbeRepository,file:string,root:string):string {return relative(root,join(repo.directory,file)).split(sep).join("/");}
function report(candidate:z.infer<typeof candidateSchema>,record:SourceCase,id:string,caller:string):string {
  return `## Summary\n${candidate.title}\n\n${candidate.impact}\n\n## Affected Source\n${record.repositoryUrl}/${record.spec.file}\nCommit: ${record.commit}\nSource SHA256: ${record.sourceSha256}\nCaller: ${caller}:${candidate.callerLine}\n\n## Steps to Reproduce\nCall ${record.spec.function} in ${record.spec.file} with the control and probe inputs below.\nProbe kind: ${record.spec.kind}\nReproduction case: ${id}\n\n## Observed Results\n${JSON.stringify(record.result.observations,null,2)}\n\n## Falsification Attempts\n${candidate.falsification}\n\n## Evidence Limits\n${record.result.limitation}\nThis is an isolated source-function reproduction; no production endpoint was tested.\n\n## Impact\n${candidate.impact}\n`;
}
export async function runLocalProgramHunt(program:SecurityProgram):Promise<SecuritySolveResult> {
  const root=await workspace("local-hunt-");
  const directory=join(process.env.PROJECT_ROOT || process.cwd(),"data","logs");await mkdir(directory,{recursive:true});
  const logFile=join(directory,"local-hunt-"+randomBytes(8).toString("hex")+".log");await writeFile(logFile,"",{mode:0o600});
  try {
    await writeSecuritySolverStatus({active:true,programId:program.id,programName:program.name,stage:"hunting",startedAt:new Date().toISOString(),timeoutMinutes:getConfig().SECURITY_SOURCE_CODE_TIMEOUT_MINUTES,pid:process.pid});
    const repos:ProbeRepository[]=[];
    for(const [i,url] of authorizedSourceUrls(scopes(program)).slice(0,2).entries()) {
      const destination=join(root,"source-"+(i+1));
      try {await cloneAuthorizedSource(url,destination);repos.push({directory:destination,url});}
      catch(error){log.warn({error,url},"Source acquisition failed");}
    }
    if(!repos.length)throw new Error("No authorized source repository was acquired; hunt cannot inspect target code");
    const session=await createProbeSession(program,root,repos);
    const reads=new Set<string>();
    const prompt=`Audit these acquired repositories: ${JSON.stringify(repos.map(repo=>({directory:relative(root,repo.directory),url:repo.url})))}.
Program: ${program.name}. Policy: ${String(JSON.parse(program.scopeSummary || "{}").policy || "").slice(0,4000)}
Find real source issues. For Python functions taking one string and returning a string, verify_python can measure html_reflection or path_construction. Unsupported cases are not reproduced. Do not invent execution.
For each reported candidate, successfully use verify_python, read the source and a real calling file, and inspect mitigations. A function behavior alone does not establish exploitability. An empty findings array is valid.
Return a final answer containing ONLY JSON in this shape:
{"findings":[{"caseId":"actual returned case ID","title":"specific title","impact":"supported impact and reachability","callerFile":"workspace-relative file you read","callerLine":1,"falsification":"actual mitigation/disproof checks, including limitations"}]}
Do not claim production testing, JavaScript execution, file access or other effects not demonstrated. You have up to 20 read/probe turns.`;
    let parsed:z.infer<typeof huntSchema> | undefined;
    const answer=await runLocalAudit(prompt,logFile,getConfig().SECURITY_SOURCE_CODE_TIMEOUT_MINUTES*60000,root,
      process.env.LOCAL_OLLAMA_MODEL || "qwen3:4b",undefined,{
        numCtx:8192,numThreads:4,numPredict:1024,onRead:path=>reads.add(path),verifyPython:session.probe,
        validateFinal:text=>{
          try {
            const value=huntSchema.parse(JSON.parse(text));
            for(const finding of value.findings) {
              const record=session.cases.get(finding.caseId);if(!record)return "Use a successful verify_python result from this hunt; an invented case ID is invalid.";
              const repo=repos.find(repo=>repo.url===record.repositoryUrl)!;
              if(!reads.has(sourceFileInWorkspace(repo,record.spec.file,root)) || !reads.has(finding.callerFile))return "Read the tested source file and the claimed caller file before reporting.";
            }
            parsed=value;return null;
          }catch{return "Return only the requested findings JSON. Omit findings that lack supported reproduction and source evidence.";}
        },
      });
    if(!parsed)throw new Error("Local hunt did not return validated findings");
    const findings:ParsedFinding[]=[];
    for(const candidate of parsed.findings) {
      const record=session.cases.get(candidate.caseId)!;
      const repo=repos.find(repo=>repo.url===record.repositoryUrl)!;
      const callerPath=candidate.callerFile;
      const callerRelative=relative(repo.directory,join(root,callerPath)).split(sep).join("/");
      if(callerRelative.startsWith("../") || callerRelative==="..")throw new Error("Caller is outside reproduced repository");
      const callerText=await readFile(join(repo.directory,callerRelative),"utf8");
      const callerLine=callerText.split("\n")[candidate.callerLine-1];
      if(!callerLine || !callerLine.includes(record.spec.function))throw new Error("Claimed caller line does not reference the probed function");
      const targetAsset=record.repositoryUrl+"/"+record.spec.file;assertAuthorizedTarget(program.scopeSummary,targetAsset);
      findings.push({title:candidate.title,severity:"medium",vulnerabilityType:record.spec.kind==="html_reflection"?"CWE-116":"CWE-22",targetAsset,confidence:0.8,
        reproductionCaseId:candidate.caseId,reproductionFingerprint:createHash("sha256").update(JSON.stringify({programId:program.id,repositoryUrl:record.repositoryUrl,commit:record.commit,file:record.spec.file,function:record.spec.function,kind:record.spec.kind})).digest("hex"),reportBody:report(candidate,record,candidate.caseId,callerRelative)});
    }
    return {success:true,findings,rawOutput:answer};
  }catch(error:any){return {success:false,findings:[],rawOutput:"",error:error.message || "Local hunt failed"};}
  finally {await clearSecuritySolverStatus().catch(()=>{});await rm(root,{recursive:true,force:true});}
}

async function independentReview(finding:SecurityFinding,program:SecurityProgram,id:string) {
  const record=await readSourceCase(id,program);
  if(finding.targetAsset!==record.repositoryUrl+"/"+record.spec.file)throw new Error("Finding target does not match its reproduction");
  const observationText=JSON.stringify(record.result.observations,null,2);
  if(!finding.reportBody?.includes(id) || !finding.reportBody.includes(record.commit) || !finding.reportBody.includes(record.sourceSha256) || !finding.reportBody.includes(observationText))throw new Error("Report does not preserve its recorded reproduction evidence");
  const caller=/^Caller: (.+):(\d+)$/m.exec(finding.reportBody);
  if(!caller || caller[1].includes(".."))throw new Error("Report has no valid recorded caller");
  const root=await workspace("local-review-");
  try {
    const repository=join(root,"source");await cloneAuthorizedSource(record.repositoryUrl,repository);
    const replay=await replaySourceCase(record,repository);
    const logFile=join(process.env.PROJECT_ROOT || process.cwd(),"data","logs","local-review-"+finding.id+".log");
    await writeFile(logFile,"",{mode:0o600});
    const reads=new Set<string>();let review:z.infer<typeof reviewSchema> | undefined;
    const {policy,disclosedReports}=program.provider==="hackerone" && program.providerProgramId
      ? await fetchProgramPolicy(program.providerProgramId)
      : {policy:JSON.parse(program.scopeSummary || "{}").policy || null,disclosedReports:[]};
    const prompt=`Independently review this report against actual source in source/. Read source/${record.spec.file}, its callers and mitigations. A fresh sandbox replay returned: ${JSON.stringify(replay)}.
Report:\n${finding.reportBody}\nPolicy:\n${policy || "No policy text available"}\nKnown reports:\n${JSON.stringify(disclosedReports).slice(0,4000)}
The probe proves only a local function behavior. Reject unsupported reachability, intended behavior, missing runtime mitigation checks or exaggerated impact. html_reflection does not establish JavaScript execution; path_construction does not establish file access. No production requests were made.
Return final JSON only:
{"verdict":"approve|reject","recommendation":"submit|submit_cautiously|dont_submit","bet100":true,"rubric":{"exploitability":0,"impactSeverity":0,"evidenceQuality":0,"novelty":0,"scopeAlignment":0},"issues":[{"category":"reason","severity":"fatal|warning|info","description":"specific issue"}],"reasoning":"specific evidence-based conclusion"}
Use one enum value per string. Scores are integers 0..3. bet100=false requires dont_submit. Approval requires a demonstrated reportable issue, not just a passing probe.`;
    await runLocalAudit(prompt,logFile,getConfig().SECURITY_HUNT_TIMEOUT_MINUTES*60000,root,process.env.LOCAL_OLLAMA_MODEL || "qwen3:4b",undefined,{
      numCtx:8192,numThreads:4,numPredict:1024,onRead:path=>reads.add(path),validateFinal:text=>{
        try {
          const value=reviewSchema.parse(JSON.parse(text));
          if(!reads.has("source/"+record.spec.file) || !reads.has("source/"+caller[1]))return "Read the reproduced source and caller before giving a review verdict.";
          review=value;return null;
        }catch{return "Return the requested review JSON with actual enum values and integer rubric scores.";}
      },
    });
    if(!review)throw new Error("No validated independent review");
    return {review,replay,caseId:id,policy,sourceSha256:record.sourceSha256,replayedAt:new Date().toISOString()};
  }finally {await rm(root,{recursive:true,force:true});}
}

let reviewing=false;
export async function processLocalReviewQueue(programId?:string):Promise<void> {
  if(reviewing)return;reviewing=true;
  try {
    const db=getDb();const config=getConfig();
    const pending=db.select().from(schema.securityFindings).where(programId
      ? and(eq(schema.securityFindings.programId,programId),inArray(schema.securityFindings.status,["report_ready","reviewing"]))
      : inArray(schema.securityFindings.status,["report_ready","reviewing"])).all();
    for(const finding of pending) {
      try {
        if(finding.id.startsWith("offline-"))continue;
        const program=finding.programId?db.select().from(schema.securityPrograms).where(eq(schema.securityPrograms.id,finding.programId)).get():null;
        if(!program || program.status!=="active")continue;
        const notes=JSON.parse(finding.analysisNotes || "{}");
        if(!notes.reproductionCaseId)continue;
        const outbox=readSubmissionOutbox()[finding.id];
        if(outbox) {
          if(outbox.programHandle!==program.providerProgramId)throw new Error("Outbox program does not match finding");
          if(outbox.state==="confirmed" && outbox.reportId && outbox.reportUrl)db.update(schema.securityFindings).set({status:"submitted",reportId:outbox.reportId,reportUrl:outbox.reportUrl,submittedAt:new Date(outbox.updatedAt),updatedAt:new Date()}).where(eq(schema.securityFindings.id,finding.id)).run();
          continue;
        }
        // Every automatic submission gets a fresh independent replay and review.
        await writeAdversarialReviewStatus({active:true,total:pending.length,completed:0,currentFindingId:finding.id,currentFindingTitle:finding.title,startedAt:new Date().toISOString()});
        const evidence=await independentReview(finding,program,sha.parse(notes.reproductionCaseId));
        const review=evidence.review;
        const total=Object.values(review.rubric).reduce((a,b)=>a+b,0);
        const accepted=review.verdict==="approve" && review.bet100 && total>=config.SECURITY_MIN_RUBRIC_SCORE &&
          review.rubric.exploitability>=2 && review.rubric.evidenceQuality>=2 && !review.issues.some(issue=>issue.severity==="fatal");
        const recommendation=accepted?review.recommendation:"dont_submit";
        const nextNotes={...notes,localReproduction:{caseId:evidence.caseId,sourceSha256:evidence.sourceSha256,replayedAt:evidence.replayedAt},
          adversarialReview:{...review,recommendation,rubricTotal:total,reviewedAt:new Date().toISOString(),repoCloned:true,toolEnabled:true}};
        db.update(schema.securityFindings).set({status:accepted && recommendation!=="dont_submit"?"reviewing":"bot_rejected",analysisNotes:JSON.stringify(nextNotes),updatedAt:new Date()}).where(eq(schema.securityFindings.id,finding.id)).run();
        if(!accepted || recommendation!=="submit" || !config.SECURITY_AUTO_SUBMIT || !config.HACKERONE_ENABLED || program.provider!=="hackerone" || !program.providerProgramId)continue;
        const [freshScopes,signal]=await Promise.all([fetchProgramScopes(program.providerProgramId),fetchProgramSignalRequirement(program.providerProgramId)]);
        if(config.SKIP_SIGNAL_REQUIRED && (signal===true || signal===null && program.requiresSignal))continue;
        assertAuthorizedTarget(JSON.stringify({scopes:freshScopes}),finding.targetAsset || "");
        const payload=await prepareSubmission({teamHandle:program.providerProgramId,finding:{title:finding.title,reportBody:finding.reportBody || "",severity:finding.severity || "medium",vulnerabilityType:finding.vulnerabilityType || undefined,targetAsset:finding.targetAsset || undefined},scopes:freshScopes,policy:evidence.policy || undefined});
        if(payload.policyExcluded)continue;
        const receipt=await submitOnce(finding.id,program.providerProgramId,payload,()=>submitReport({teamHandle:program.providerProgramId!,payload}));
        db.update(schema.securityFindings).set({status:"submitted",reportId:receipt.reportId,reportUrl:receipt.reportUrl,submittedAt:new Date(),updatedAt:new Date()}).where(eq(schema.securityFindings.id,finding.id)).run();
        log.info({findingId:finding.id,reportId:receipt.reportId},"Reproduced and independently reviewed finding submitted");
      }catch(error){log.error({error,findingId:finding.id},"Local reproduction/review/submission incomplete");}
    }
  }finally{reviewing=false;await clearAdversarialReviewStatus().catch(()=>{});}
}
