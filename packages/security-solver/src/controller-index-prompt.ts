/** Small fixed instruction envelope for the controller-first full-index path.
 * Complete source facts belong in pageable workspace files, not Qwen's pinned
 * 8192-token prompt. The established non-indexed prompt remains unchanged.
 */
export function controllerIndexedAuditPrompt(input:{
  program:string; maxTurns:number;
  candidates:Array<{path:string;risk:number;declarations:string[]}>;
}):string {
  const candidates=input.candidates.slice(0,3).map(c=>({
    path:c.path.slice(0,180),risk:c.risk,
    declaration:(c.declarations[0]||'').slice(0,130)
  }));
  const message=[
    'The deterministic controller has inspected and indexed the entire eligible source repository before model inference.',
    'Controller facts are stored in audit-controller-source-index.json. The bounded current evidence selection is in audit-controller-evidence-packet.json. These files contain source facts, not proven vulnerabilities.',
    'Prioritize these source-derived candidates: '+JSON.stringify(candidates)+'.',
    'Use the existing supported source-read, plan_probe, verify_source, and final actions. Inspect exact source, callers, guards and impact before a hypothesis or report. The controller owns navigation, probe execution and evidence; do not invent paths, effects or case IDs.',
    'Read audit-policy.txt completely before reporting. audit-context.json contains acquisition/scope; audit-candidates.json, audit-static-leads.json and audit-source-map.json are additional navigation records.',
    'For Solidity use outline_solidity/read_solidity as relevant. Supported Java, Python, JavaScript and Solidity probes and declarative sequences retain their existing verifier semantics. An observation or assertion mismatch is not proof of a vulnerability.',
    'A verified finding needs its actual returned caseId, source-backed caller or direct Solidity transaction, reproducible behavior, impact and falsification checks. Preserve independent review. Otherwise return findings=[] and outcome=no_testable_candidate with a grounded reason.',
    'Final JSON keys: findings (array of {caseId,severity,confidence,ratingReason,title,impact,callerFile,callerLine,falsification}); or empty findings, outcome, reason. No unsupported reports.',
    'Program: '+input.program.slice(0,120)+'. Initial budget: '+input.maxTurns+' turns; the controller may extend turns and time when warranted. Work on the highest-priority evidence, not sequential file-reading.'
  ].join('\n');
  if(message.length>2400)throw new Error('Controller audit envelope exceeded the bounded instruction budget');
  return message;
}
