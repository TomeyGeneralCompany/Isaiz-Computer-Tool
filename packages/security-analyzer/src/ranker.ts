import { withPipeline } from "@bounty/core";
import { eq, sql, desc } from "drizzle-orm";
import {
  getDb,
  getConfig,
  programCandidateBlocker,
  schema,
  createLogger,
  generateTraceId,
  classifyError,
  type SecurityProgram,
  type SecurityFinding,
} from "@bounty/core";
import { assessProgram, assessFinding } from "./assessor";

const log = createLogger("security-ranker");

/**
 * Analyze a security program — assess its scope for vulnerability opportunity.
 * Updates the program's assessment data in the database.
 */
async function analyzeProgramImpl(program: SecurityProgram): Promise<void> {
  const db = getDb();

  log.info({ name: program.name, id: program.id }, "Analyzing program");

  try {
    const result = await assessProgram(program);

    // Store assessment in scopeSummary alongside existing scope data, policy, and disclosed reports
    let existing: any = {};
    try {
      const parsed = JSON.parse(program.scopeSummary || "{}");
      // Handle both old array format and new object format
      if (Array.isArray(parsed)) {
        existing = { scopes: parsed };
      } else {
        existing = parsed;
      }
    } catch {}

    const enrichedSummary = JSON.stringify({
      ...existing,
      scopes: existing.scopes ?? [],
      assessment: {
        opportunityScore: result.opportunityScore,
        rubric: result.rubric,
        targetCount: result.targetCount,
        topTargets: result.topTargets,
        techStack: result.techStack,
        attackSurface: result.attackSurface,
        hasSourceCode: result.hasSourceCode,
        recommendedApproach: result.recommendedApproach,
        assessedAt: new Date().toISOString(),
      },
    });

    db.update(schema.securityPrograms)
      .set({
        scopeSummary: enrichedSummary,
        updatedAt: new Date(),
      })
      .where(eq(schema.securityPrograms.id, program.id))
      .run();

    log.info(
      { name: program.name, opportunityScore: result.opportunityScore },
      "Program analysis complete",
    );
  } catch (err: any) {
    log.error({ err, name: program.name }, "Program analysis failed");
    throw err;
  }
}

/**
 * Analyze and rank a security finding — assess difficulty, confidence, severity.
 */
async function analyzeAndRankFindingImpl(finding: SecurityFinding): Promise<void> {
  if (finding.id.startsWith("offline-")) return; // The evidence queue owns static leads.
  const db = getDb();
  const traceId = generateTraceId();

  // Get the program for context
  const program = finding.programId
    ? db.select().from(schema.securityPrograms).where(eq(schema.securityPrograms.id, finding.programId)).get()
    : null;

  if (!program) {
    log.warn({ findingId: finding.id }, "Finding has no associated program, skipping");
    return;
  }

  // Update status to analyzing
  db.update(schema.securityFindings)
    .set({ status: "analyzing", traceId, updatedAt: new Date() })
    .where(eq(schema.securityFindings.id, finding.id))
    .run();

  try {
    const result = await assessFinding(finding, program);

    // Priority: high confidence + high severity + low difficulty = best opportunity
    const severityMultiplier: Record<string, number> = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      informational: 1,
    };
    const sevMult = severityMultiplier[result.severity] ?? 1;

    db.update(schema.securityFindings)
      .set({
        status: "validated",
        severity: result.severity,
        vulnerabilityType: result.vulnerabilityType,
        confidenceScore: result.confidence,
        analysisNotes: JSON.stringify({
          difficulty: result.difficulty,
          approach: result.approach,
          riskFactors: result.riskFactors,
          estimatedRewardCents: result.estimatedRewardCents,
          severityMultiplier: sevMult,
          traceId,
        }),
        updatedAt: new Date(),
      })
      .where(eq(schema.securityFindings.id, finding.id))
      .run();

    log.info(
      {
        traceId,
        title: finding.title,
        confidence: result.confidence,
        severity: result.severity,
        difficulty: result.difficulty,
      },
      "Finding analysis complete",
    );
  } catch (err: any) {
    const classified = classifyError(err);
    log.error({ traceId, err, findingId: finding.id }, "Finding analysis failed");

    db.update(schema.securityFindings)
      .set({
        status: "failed",
        retryCount: (finding.retryCount ?? 0) + 1,
        analysisNotes: JSON.stringify({
          error: classified.message,
          errorCategory: classified.category,
          traceId,
        }),
        updatedAt: new Date(),
      })
      .where(eq(schema.securityFindings.id, finding.id))
      .run();

    throw err;
  }
}

/**
 * Process the analysis queue for security programs.
 * Analyzes all unassessed active programs.
 */
async function processSecurityProgramQueueImpl(opts?: {
  skipSignalRequired?: boolean;
  onProgramAssessed?: (programId: string) => void;
  snapshot?: boolean;
  shouldContinue?: ()=>boolean;
  onProgress?: (total:number,completed:number,name:string)=>void;
}): Promise<number> {
  const db = getDb();
  let analyzed = 0;
  const attempted = new Set<string>();
  const local = process.env.OLLAMA_DISCOVERY_DIRECT === "true";
  let catalog:Set<string>|undefined;
  let completed=0;
  // Refresh the catalog between small batches, so initial HackerOne discovery
  // is not stranded behind a snapshot of hundreds of older entries.
  while (true) {
    if (opts?.shouldContinue && !opts.shouldContinue()) break;
    const config = getConfig();
    const eligible = db.select().from(schema.securityPrograms)
      .where(eq(schema.securityPrograms.status,"active"))
      .orderBy(desc(schema.securityPrograms.rewardMaxCents)).all().filter(program => {
        if ((catalog && !catalog.has(program.id)) || attempted.has(program.id) || programCandidateBlocker(program,config,!!process.env.LOCAL_OLLAMA_MODEL)) return false;
        // An explicit per-call filter is still honored. The default automatic
        // local queue may inspect source even when submission needs Signal.
        if (opts?.skipSignalRequired && program.requiresSignal) return false;
        try {return JSON.parse(program.scopeSummary || "{}").assessment?.opportunityScore == null;} catch {return true;}
      }).sort((a,b) => Number(b.provider === "hackerone") - Number(a.provider === "hackerone"));
    if (opts?.snapshot && !catalog) catalog=new Set(eligible.map(p=>p.id));
    const batch = eligible.slice(0,local ? 1 : 5);
    if (!batch.length) break;
    batch.forEach(program => attempted.add(program.id));
    opts?.onProgress?.(catalog?.size ?? eligible.length+completed,completed,batch.map(p=>p.name).join(", "));
    const results = await Promise.allSettled(batch.map(program => analyzeProgram(program)));
    for (let i = 0; i < results.length; i++) {
      completed++;
      opts?.onProgress?.(catalog?.size ?? eligible.length+completed-results.length,completed,batch[i].name);
      if (results[i].status === "fulfilled") {
        analyzed++;
        opts?.onProgramAssessed?.(batch[i].id);
      } else {
        log.error({err:(results[i] as PromiseRejectedResult).reason,programId:batch[i].id},"Error analyzing program, continuing");
      }
    }
  }
  return analyzed;
}

/**
 * Process the analysis queue for security findings.
 * Analyzes all discovered findings, highest confidence first.
 */
export async function processSecurityFindingQueue(): Promise<number> {
  const db = getDb();
  let analyzed = 0;

  const pending = db
    .select()
    .from(schema.securityFindings)
    .where(eq(schema.securityFindings.status, "discovered"))
    .all();

  // Process in concurrent batches of 5
  const CONCURRENCY = process.env.OLLAMA_DISCOVERY_DIRECT === "true" ? 1 : 5;
  for (let i = 0; i < pending.length; i += CONCURRENCY) {
    const batch = pending.slice(i, i + CONCURRENCY).filter(finding => !finding.id.startsWith("offline-"));
    const results = await Promise.allSettled(
      batch.map((finding) => analyzeAndRankFinding(finding)),
    );

    for (let j = 0; j < results.length; j++) {
      if (results[j].status === "fulfilled") {
        analyzed++;
      } else {
        log.error({ err: (results[j] as PromiseRejectedResult).reason, findingId: batch[j].id }, "Error analyzing finding, continuing");
      }
    }
  }

  return analyzed;
}

export function analyzeProgram(...args:Parameters<typeof analyzeProgramImpl>):ReturnType<typeof analyzeProgramImpl> { return withPipeline(()=>analyzeProgramImpl(...args)); }

export function analyzeAndRankFinding(...args:Parameters<typeof analyzeAndRankFindingImpl>):ReturnType<typeof analyzeAndRankFindingImpl> { return withPipeline(()=>analyzeAndRankFindingImpl(...args)); }

export function processSecurityProgramQueue(...args:Parameters<typeof processSecurityProgramQueueImpl>):ReturnType<typeof processSecurityProgramQueueImpl> { return withPipeline(()=>processSecurityProgramQueueImpl(...args)); }
