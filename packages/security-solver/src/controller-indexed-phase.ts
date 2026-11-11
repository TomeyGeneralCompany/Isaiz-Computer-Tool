/** One source-coverage gate for Solidity, Java, Python and JavaScript.
 * A path being visited is NOT sufficient: the last delivered page must be
 * observed by the controller before experimentation can begin.
 * Progress is calculated from the indexed working set, not model claims.
 */
export type IndexedPhaseStatus={eligible:number;completed:number;remaining:string[];ready:boolean};
export function indexedPhaseStatus(indexed:Iterable<string>,terminal:Iterable<string>):IndexedPhaseStatus {
  const eligible=[...new Set(indexed)].filter(path=>
    /^source-[0-9]+\//.test(path) && /\.(?:sol|java|py|js|mjs|cjs)$/.test(path));
  const done=new Set(terminal);
  const remaining=eligible.filter(path=>!done.has(path));
  return {eligible:eligible.length,completed:eligible.length-remaining.length,
    remaining,ready:eligible.length>0 && remaining.length===0};
}
