import {readFile,realpath} from 'node:fs/promises';
import {join,relative,sep} from 'node:path';
import {traceSourceCalls} from './source-flow-facts';

export type TracedSourceCandidate={path:string;selector:string;kind:'html_reflection';score:number;
  chain:string[];hypothesis:string};

/** Analyze actual source-backed helper chains before consulting the model.
 * A bounded trace only nominates a verifier-compatible hypothesis. No text
 * in this ranking is accepted as evidence of an exploitable vulnerability.
 */
export async function rankTracedSourceCandidates(
  workspace:string,paths:string[],maxFiles=192
):Promise<TracedSourceCandidate[]> {
  const root=await realpath(workspace);
  const candidates:TracedSourceCandidate[]=[];
  let checked=0;
  for(const path of [...new Set(paths)]) {
    if(checked>=maxFiles)break;
    if(!/^source-[0-9]+\//.test(path)||!/\.(?:py|js|mjs|cjs|java)$/.test(path))continue;
    checked++;
    const repositoryName=path.split('/')[0];
    const repository=join(root,repositoryName);
    const relativeFile=path.slice(repositoryName.length+1);
    let source:string;
    try {
      const full=await realpath(join(repository,relativeFile));
      const rel=relative(repository,full);
      if(rel==='..'||rel.startsWith('..'+sep))continue;
      source=await readFile(full,'utf8');
      if(source.length>128000)continue;
    }catch{continue;}
    if(/(?:http.handler|http_handler|route|entry|server)/i.test(path) &&
       /(?:searchParams|urlsplit|parse_qs|URL\s*\()/i.test(source))continue;
    const selectors:string[]=[];
    if(path.endsWith('.py')){
      for(const m of source.matchAll(/^def\s+([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*(?:->\s*str\s*)?:/gm))
        selectors.push(m[1]);
    }else if(path.endsWith('.java')){
      const cls=path.split('/').at(-1)!.slice(0,-5);
      for(const m of source.matchAll(/\bpublic\s+(?:static\s+)?(?:java\.lang\.)?String\s+([A-Za-z_]\w*)\s*\(\s*(?:java\.lang\.)?String\s+[A-Za-z_]\w*\s*\)/g))
        selectors.push(cls+'.'+m[1]);
    }else {
      for(const m of source.matchAll(/\bexports\.([A-Za-z_$][\w$]*)\s*=\s*function\s*(?:[A-Za-z_$][\w$]*)?\s*\(\s*[A-Za-z_$][\w$]*\s*\)/g))
        selectors.push(m[1]);
      for(const m of source.matchAll(/\bexport\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(\s*[A-Za-z_$][\w$]*\s*\)/g))
        selectors.push(m[1]);
    }
    for(const selector of [...new Set(selectors)].slice(0,12)){
      const method=selector.split('.').at(-1)||'';
      if(/^(?:inspect|test|debug|mock)/i.test(method))continue;
      try {
        const trace=await traceSourceCalls(repository,relativeFile,selector,5);
        const implementation=trace.facts.map(f=>f.source).join('\n');
        // Require an actual source-traced HTML result. Sanitizers in any
        // inspected hop defeat this particular unsanitized-reflection hint.
        if(!/<p>/i.test(implementation)||!/<\/p>/i.test(implementation) ||
           !/\breturn\b/.test(implementation))continue;
        if(/\b(?:escape|escapeHtml|htmlspecialchars|sanitize|DOMPurify)\s*\(|\.replace\s*\(/i.test(implementation))continue;
        const chain=[...new Set(trace.facts.map(f=>f.path))];
        const score=10+chain.length*4+
          // Sink-adjacent renderers outrank HTTP wrapper functions.
          // Handler inputs remain crucial reachability/caller evidence but
          // they do not necessarily implement the vulnerable HTML sink.
          (/^(?:render|renderHtml)$/i.test(method)?12:0)+
          (chain.length>1?8:0);
        candidates.push({path,selector,kind:'html_reflection',score,
          chain:chain.map(p=>repositoryName+'/'+p),
          hypothesis:'Verify whether the exact exported single-input function passes untrusted markup through the source-traced helper chain without HTML escaping. Escaped output defeats this hypothesis.'});
      }catch{}
    }
  }
  return candidates.sort((a,b)=>b.score-a.score || a.path.localeCompare(b.path)).slice(0,24);
}
