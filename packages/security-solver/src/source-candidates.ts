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
  const candidates=[...new Set([...(focus?[focus]:[]),...selected.map(lead=>lead.path),...fallback,...eligible])].filter(path=>allowed.has(path));
  // Rank a bounded navigation pool by demonstrably probe-compatible signatures.
  // Lexical hints are not evidence; an actual source read and isolated probe
  // still determine whether any candidate is testable or vulnerable.
  const ranked=candidates.sort((a,b)=>sourcePriority(b)-sourcePriority(a) ||
    (a.endsWith('.sol')? -1:0) - (b.endsWith('.sol')? -1:0));
  const rankedPool=focus ? ranked.filter(path=>path===focus) : ranked.slice(0,192);
  const signatureScores=new Map<string,number>();
  if(!focus) {
    let examinedBytes=0;
    for(const path of rankedPool) {
      try {
        const full=await realpath(resolve(base,path)),local=relative(base,full);
        if(local==='..'||local.startsWith('..'+sep))continue;
        const size=(await stat(full)).size;
        if(size>128000 || examinedBytes+size>4000000)continue;
        examinedBytes+=size;
        const source=await readFile(full,'utf8');
        // Match exactly one supported argument and a supported return type;
        // avoid ranking ByteString setters and getters without arguments as probe targets.
        // Permits ordinary Java modifiers and optional final on the parameter.
        const javaCandidate=path.endsWith('.java') &&
          /\bpublic\s+(?:(?:static|final|synchronized|abstract)\s+)*(?:String|byte\s*\[\s*\]|CharSequence|StringBuilder|StringBuffer|ByteBuffer|Path|File|URI)\s+\w+\s*\(\s*(?:final\s+)?(?:String|byte\s*\[\s*\]|CharSequence|StringBuilder|StringBuffer|ByteBuffer|Path|File|URI|Object)\s+\w+\s*\)/.test(source);
        const solidityCandidate=path.endsWith('.sol') &&
          /\bfunction\s+\w+\s*\(\s*string\b[^)]*\)\s+[^;{]*\b(?:pure|view)\b[^;{]*\breturns\s*\(\s*string\b/.test(source);
        if(javaCandidate||solidityCandidate)signatureScores.set(path,1);
      }catch{}
    }
  }
  const paths=focus ? rankedPool : rankedPool
    .sort((a,b)=>(signatureScores.get(b)||0)-(signatureScores.get(a)||0) ||
      sourcePriority(b)-sourcePriority(a))
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
