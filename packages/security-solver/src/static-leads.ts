import { eq, asc } from "drizzle-orm";
import { z } from "zod";
import { getConfig, getDb, schema, claimDailyHuntSlot, programCandidateBlocker, assertAuthorizedTarget, authorizedSourceUrls, createLogger, type SecurityProgram } from "@bounty/core";
import type { StaticLeadFocus } from "./local-program-flow";
const log = createLogger("static-lead-queue");
const record = z.object({source:z.literal("offline_static_triage"),repository:z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/),
  commit:z.string().regex(/^[a-f0-9]{40}$/),lead:z.object({file:z.string().min(1).max(4096),line:z.number().int().positive(),rule:z.string().min(1).max(100)})});
let running = false;
/** Dispatch one imported lead through the existing locked source/reproduction flow.
 * Original leads never become reports; evidence-backed child reports use normal review.
 */
export async function processStaticLeadQueue(investigate?: (program:SecurityProgram, focus:StaticLeadFocus) => Promise<{findingsCreated:number}>):Promise<boolean> {
  const config = getConfig();
  if (running || !config.SECURITY_AUTO_HUNT_ENABLED || !process.env.LOCAL_OLLAMA_MODEL) return false;
  running = true;
  try {
    const db=getDb();
    const pending=db.select().from(schema.securityFindings).orderBy(asc(schema.securityFindings.discoveredAt)).all();
    for (const finding of pending) {
      if (!finding.id.startsWith("offline-") || ["dismissed","submitted","triaged","accepted","rewarded","bot_rejected","duplicate","not_applicable","informative"].includes(finding.status)) continue;
      let notes:any={}; try {const raw=JSON.parse(finding.analysisNotes || "{}");if(raw && typeof raw === "object" && !Array.isArray(raw)) notes=raw;} catch {}
      const prior=notes.staticInvestigation;
      if (["unsupported","completed","invalid"].includes(prior?.state)) continue;
      if (prior?.retryAfter && Date.parse(prior.retryAfter)>Date.now()) continue;
      const save=(state:string,detail:string,extra:Record<string,unknown>={}) => {
        // Re-read to preserve an operator dismissal that happened during inference.
        const current=db.select().from(schema.securityFindings).where(eq(schema.securityFindings.id,finding.id)).get();
        if (!current || current.status === "dismissed") return;
        let currentNotes:any={};try {currentNotes=JSON.parse(current.analysisNotes || "{}");} catch {}
        db.update(schema.securityFindings).set({status:"discovered",analysisNotes:JSON.stringify({...currentNotes,
          submission_eligible:false,verification:"NOT VERIFIED",staticInvestigation:{state,detail,updatedAt:new Date().toISOString(),...extra}}),updatedAt:new Date()})
          .where(eq(schema.securityFindings.id,finding.id)).run();
      };
      const parsed=record.safeParse(notes);
      if (!parsed.success) {save("invalid","Imported lead metadata is incomplete; no verification was performed.");continue;}
      const value=parsed.data;
      const file=value.lead.file;
      if (file.startsWith("/") || file.includes("\\") || file.split("/").some(part=>part === ".." || !part)) {
        save("invalid","Invalid repository-relative source path.");continue;
      }
      if (!file.endsWith(".py")) {
        save("unsupported","Automatic reproduction currently supports Python string functions (HTML reflection/path construction). This lead's language is unsupported; no vulnerability is established.");
        continue;
      }
      const program=finding.programId ? db.select().from(schema.securityPrograms).where(eq(schema.securityPrograms.id,finding.programId)).get() : undefined;
      if (!program) {save("invalid","No associated program exists.");continue;}
      // A new lead can follow a previous hunt, while provider/scope/reward/Signal gates remain.
      const blocker=programCandidateBlocker({...program,lastHuntedAt:null},config,true);
      if (blocker) {save("blocked","Current program eligibility: "+blocker,{retryAfter:new Date(Date.now()+300000).toISOString()});continue;}
      const repositoryUrl="https://github.com/"+value.repository;
      try {
        const data=JSON.parse(program.scopeSummary || "{}");
        if (!authorizedSourceUrls(Array.isArray(data)?data:data.scopes).includes(repositoryUrl)) throw new Error("Repository is not a current source asset");
        assertAuthorizedTarget(program.scopeSummary,repositoryUrl+"/"+file);
      } catch {save("blocked","Lead source is outside current program scope.",{retryAfter:new Date(Date.now()+300000).toISOString()});continue;}
      const {isSecuritySolving,huntProgram}=await import("./index");
      if (isSecuritySolving()) return false;
      if (!claimDailyHuntSlot(config.SECURITY_MAX_DAILY_HUNTS)) return false;
      save("running","Investigating source at the recorded commit; no report is approved.");
      const focus:StaticLeadFocus={id:finding.id,repositoryUrl,commit:value.commit,file,line:value.lead.line,rule:value.lead.rule};
      try {
        const result=await (investigate ? investigate(program,focus) : huntProgram(program,"auto",focus));
        save("completed",result.findingsCreated ? "Evidence-backed reports created; independent review follows separately." : "Investigation completed without a qualifying report; this is not proof the source is vulnerability-free.",{reportsCreated:result.findingsCreated});
      } catch (error:any) {
        const detail=String(error?.message || error).slice(0,1000);
        const attempts=Math.min(10,(Number(prior?.attempts)||0)+1);
        save(/No supported function reproduction completed/.test(detail)?"unsupported":"retry",detail,{attempts,retryAfter:new Date(Date.now()+Math.min(3600000,60000*2**attempts)).toISOString()});
        log.warn({findingId:finding.id,detail},"Static lead investigation did not produce verified evidence");
      }
      return true;
    }
    return false;
  } finally {running=false;}
}
