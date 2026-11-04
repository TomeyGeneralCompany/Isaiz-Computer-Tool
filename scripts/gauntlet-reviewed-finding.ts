/** Blind Gauntlet grading: the answer key is used only here, after independent
 * reviews have already run for all reported findings.
 */
export function reviewedTargetFinding(
  findings:Array<{reproductionCaseId?:string|null;reportBody?:string|null;title?:string|null}>,
  reviews:Array<{verdict?:string;caseId?:string}>,
  expected:{file:string;selector:string},
):boolean {
  const method=expected.selector.split('.').at(-1)||expected.selector;
  return findings.some(f=>!!f.reproductionCaseId &&
    reviews.some(r=>r.verdict==='approve' && r.caseId===f.reproductionCaseId) &&
    (String(f.reportBody||'')+' '+String(f.title||'')).includes(method) &&
    (String(f.reportBody||'')+' '+String(f.title||'')).includes(expected.file));
}
