import {readFile,realpath} from 'node:fs/promises';
import {resolve,relative,sep} from 'node:path';
import type {SourceSymbol} from './source-map';

/** Controller-owned, bounded source citations for the investigation.
 * Every quoted line comes from an authorized current workspace file.
 * Lexical caller matches are *possible* edges, never verified taint or impact.
 */
export async function sourceCandidateEvidence(root:string,symbols:SourceSymbol[],limit=8) {
  const base=await realpath(root);
  const citations:Array<{path:string;line:number;code:string;role:string}>=[];
  const seen=new Set<string>();
  const add=async(path:string,line:number,role:string)=>{
    if(!path || path.startsWith('/') || path.split(/[\\/]/).includes('..') ||
       !Number.isSafeInteger(line)||line<1)return;
    try {
      const file=await realpath(resolve(base,path));
      const rel=relative(base,file);
      if(rel==='..'||rel.startsWith('..'+sep))return;
      const content=await readFile(file,'utf8');
      if(content.length>256000)return;
      const code=content.split('\n')[line-1];
      if(typeof code!=='string'||!code.trim())return;
      const key=path+':'+line;
      if(seen.has(key))return;
      seen.add(key);citations.push({path,line,code:code.slice(0,400),role});
    }catch{}
  };
  for(const symbol of symbols.slice(0,limit)) {
    await add(symbol.path,symbol.line,'declaration: '+symbol.name);
    for(const caller of symbol.callers.slice(0,2))
      await add(caller.path,caller.line,'possible lexical caller of '+symbol.name);
  }
  return {kind:'source_citations_not_findings',citations,
    rule:'Actual source lines; lexical caller links may be false positives. Check data flow, argument control, mitigations and replay before interpreting security impact.'};
}

/** Compact persistent facts from the controller verifier, not model memory. */
export function verifiedProbeSummary(cases:Iterable<[string,{
  spec:{file:string;function:string;kind:string};
  result:{behavior_observed?:boolean;observations?:unknown}
}]>, limit=3):string {
  const rows:string[]=[];
  for(const [caseId,record] of cases) {
    if(rows.length>=limit)break;
    if(!record.result.behavior_observed)continue;
    rows.push(JSON.stringify({
      caseId,source:record.spec.file,selector:record.spec.function,kind:record.spec.kind,
      observed:true,observations:record.result.observations
    }).slice(0,620));
  }
  return rows.length?'CONTROLLER VERIFIED REPRODUCTIONS (local behavior; impact and reachability unproven): '+rows.join(' '):
    'No successful reproduction case yet; do not invent case identifiers.';
}
