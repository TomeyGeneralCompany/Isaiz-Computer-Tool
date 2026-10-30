import {readFile,realpath,stat} from 'node:fs/promises';
import {relative,resolve,sep} from 'node:path';
import {sourcePriority} from './source-capability';

/** Candidates guide navigation only; reading/testing still supplies all evidence. */
export async function prioritizeSourceCandidates(root:string,eligible:string[],fallback:string[],leads:Array<{path:string;line:number;rule?:string;message?:string}>,focus?:string) {
  const allowed=new Set(eligible),base=await realpath(root);
  const selected=leads.filter(lead=>allowed.has(lead.path)&&Number.isSafeInteger(lead.line)&&lead.line>0);
  // A detector match in deployment tooling must not crowd actual application
  // contracts out of the eight-file navigation window. Prefer production
  // source consistently for detector hits and fallbacks, without discarding
  // eligible files or treating a detector hit as verified evidence.
  const candidates=[...new Set([...(focus?[focus]:[]),...selected.map(lead=>lead.path),...fallback])].filter(path=>allowed.has(path));
  const paths=focus ? candidates.slice(0,8) : candidates
    .sort((a,b)=>sourcePriority(b)-sourcePriority(a) || (a.endsWith('.sol')? -1:0) - (b.endsWith('.sol')? -1:0))
    .slice(0,8);
  const locations:Array<{path:string;offset:number;line:number;rule?:string;hypothesis?:string}>=[];
  for(const path of paths) {
    try {
      const full=await realpath(resolve(base,path)),local=relative(base,full);
      if(local==='..'||local.startsWith('..'+sep)||(await stat(full)).size>256000)continue;
      const lead=selected.find(item=>item.path===path);
      const source=await readFile(full,'utf8'),lines=source.split('\n');
      // Read a little context before the matched line. Offsets are UTF-16 units,
      // matching read_file, not byte offsets or a claim of inspected coverage.
      const line=lead&&lead.line<=lines.length?Math.max(1,lead.line-3):1;
      const offset=line===1?0:lines.slice(0,line-1).join('\n').length+1;
      locations.push({path,offset,line,...(lead?{rule:lead.rule?.slice(0,160),hypothesis:lead.message?.slice(0,300)}:{})});
    }catch{}
  }
  return {kind:'navigation_only',paths:locations.map(item=>item.path),locations,
    limitation:'Detector matches are hypotheses. A source read, compatible test, reachability and impact evidence are still required. Unselected files remain uninspected.'};
}
