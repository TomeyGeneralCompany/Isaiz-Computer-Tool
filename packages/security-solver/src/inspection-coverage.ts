/** A bounded pass is partial even when its selected probes succeed. */
export function selectSourceBatch(urls: string[], pass: number, size = 2): string[] {
  if (!urls.length) return [];
  const start = ((Number.isSafeInteger(pass) && pass >= 0 ? pass : 0) * size) % urls.length;
  return Array.from({length: Math.min(size, urls.length)}, (_, i) => urls[(start + i) % urls.length]);
}
export function incompleteProbeCoverage(session: {failedProbes:number; unsupportedProbes:number}): "failed" | "unsupported" {
  return session.failedProbes > 0 || session.unsupportedProbes === 0 ? "failed" : "unsupported";
}

/** A model's empty "inspected" final is not a completed audit when no probe ran.
 * Convert only that classification into the existing scoped-incomplete outcome.
 * The caller still enforces the selected-source coverage gate and hunt schema.
 * Never change a finding, a recorded probe, or an explicit blocked outcome.
 */
export function recoverEmptyUnprobedFinal(value:unknown, completedProbes:number, blockedReason?:string|null):unknown {
  if(!value || typeof value!=='object' || Array.isArray(value) || completedProbes!==0 || blockedReason)return value;
  const result=value as Record<string,unknown>;
  if(!Array.isArray(result.findings) || result.findings.length!==0 || result.outcome!=='inspected')return value;
  const reason=typeof result.reason==='string' && result.reason.trim().length>=20
    ? result.reason : 'No supported source probe completed in this bounded inspection; coverage remains incomplete.';
  return {...result,outcome:'no_testable_candidate',reason};
}

/** Drop unsupported extras only when at least one independently grounded
 * candidate survives. If none is grounded, preserve the original rejection
 * path; the controller never manufactures or upgrades a finding.
 */
export function retainGroundedCandidates<T>(candidates:T[],grounded:T[]):T[] {
  return candidates.length>1 && grounded.length>0 && grounded.length<candidates.length
    ? grounded : candidates;
}
