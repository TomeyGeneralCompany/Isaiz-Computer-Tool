import {readFile,realpath,stat} from 'node:fs/promises';
import {relative,resolve,sep} from 'node:path';
import {sourcePriority} from './source-capability';

/** Candidates guide navigation only; reading/testing still supplies all evidence. */
export async function prioritizeSourceCandidates(root:string,eligible:string[],fallback:string[],leads:Array<{path:string;line:number;rule?:string;message?:string}>,focus?:string) {
  const allowed=new Set(eligible),base=await realpath(root);
  const selected=leads.filter(lead=>allowed.has(lead.path)&&Number.isSafeInteger(lead.line)&&lead.line>0);
  // A detector match in vendored, generated, test, or dependency code must not
  // crowd application source out of the eight-file navigation window, for any
  // supported language. Preserve every eligible source for later inspection;
  // detector leads are navigation hints, not evidence of a vulnerability.
  const candidates=[...new Set([...(focus?[focus]:[]),...selected.map(lead=>lead.path),...fallback,...eligible])].filter(path=>allowed.has(path));
  // Rank a bounded navigation pool using application ownership and supported signatures.
  // Lexical hints are not evidence; an actual source read and isolated probe
  // still determine whether any candidate is testable or vulnerable.
  const ranked=candidates.sort((a,b)=>sourcePriority(b)-sourcePriority(a) ||
    (a.endsWith('.sol')? -1:0) - (b.endsWith('.sol')? -1:0));
  const rankedPool=focus ? ranked.filter(path=>path===focus) : ranked.slice(0,192);
  const signatureScores=new Map<string,number>();
  const sourceTexts=new Map<string,string>();
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
        sourceTexts.set(path,source);
        // Match exactly one supported argument and a supported return type;
        // avoid ranking ByteString setters and getters without arguments as probe targets.
        // Permits concrete Java modifiers and optional final on the parameter.
        const javaCandidate=path.endsWith('.java') &&
          /\bpublic\s+(?:(?:static|final|synchronized)\s+)*(?:String|byte\s*\[\s*\]|CharSequence|StringBuilder|StringBuffer|ByteBuffer|Path|File|URI)\s+\w+\s*\(\s*(?:final\s+)?(?:String|byte\s*\[\s*\]|CharSequence|StringBuilder|StringBuffer|ByteBuffer|Path|File|URI|Object)\s+\w+\s*\)/.test(source);
        const solidityCandidate=path.endsWith('.sol') &&
          /\bfunction\s+\w+\s*\(\s*string\b[^)]*\)\s+[^;{]*\b(?:pure|view)\b[^;{]*\breturns\s*\(\s*string\b/.test(source);
        // Stateful Solidity contracts can be exercised by the declarative
        // solidity_sequence adapter. Do not limit navigation to view/pure
        // string-returning functions (the original lexical scoring did).
        // Prefer concrete contracts with externally callable functions and
        // primitive ABI parameters; never infer that this makes a probe valid.
        const statefulSolidity=path.endsWith('.sol') &&
          /\bcontract\s+[A-Za-z_]\w*\b(?:\s+is\s+[^\{]+)?\s*\{/.test(source) &&
          /\bfunction\s+[A-Za-z_]\w*\s*\([^)]*\b(?:uint\d*|int\d*|address|bool|bytes\d*|string)\b[^)]*\)\s+[^;{]*\b(?:public|external)\b/.test(source) &&
          !/\babstract\s+contract\b/.test(source);
        if(javaCandidate||solidityCandidate||statefulSolidity)
          signatureScores.set(path,statefulSolidity ? 2 : 1);
      }catch{}
    }
  }
  // Prefer source connected by references from *other* files over isolated
  // same-signature helpers. This gives caller->callee chains a fair opening
  // in large Python/JS/Java/Solidity projects without marking anything unsafe.
  // Use actual inspected file text for navigation only, never as proof.
  const referenceScores=new Map<string,number>();
  if(!focus) {
    const names=new Map<string,string[]>();
    for(const path of rankedPool) {
      const baseName=path.split('/').at(-1)!.replace(/\.(?:sol|java|py|js|mjs|cjs)$/,'');
      if(baseName==='__init__'||baseName==='index'||baseName.length<4)continue;
      const match=names.get(baseName)||[];
      match.push(path);names.set(baseName,match);
    }
    for(const [sourcePath,source] of sourceTexts) {
      // Cross-file references to a source basename/class suggest a genuine
      // call chain. Count each referencing file at most once per target.
      for(const [name,targets] of names) {
        const escaped=name.replace(/[^A-Za-z0-9_$]/g,'');
        if(escaped!==name)continue;
        const token=new RegExp('(?:^|[^A-Za-z0-9_$])'+escaped+'(?:[^A-Za-z0-9_$]|$)');
        if(!token.test(source))continue;
        for(const target of targets) {
          if(target===sourcePath)continue;
          referenceScores.set(target,Math.min(12,(referenceScores.get(target)||0)+1));
        }
      }
    }
  }
  const pathDepth=(path:string)=>path.split('/').length;
  // Keep generated and test-only sources inspectable, but do not let them
  // displace eight available production/dependency candidates. A disconnected
  // generated file may share a basename with application code and receive a
  // misleading inbound lexical reference score.
  const nonGenerated=rankedPool.filter(path=>
    !/(?:^|\\/)(?:test|tests|__tests__|generated|build|dist)(?:\\/|$)/i.test(path) &&
    !/(?:^|\\/)(?:Generated|Mock)[A-Z][^/]*\\.(?:java|sol|py|js|mjs|cjs)$/i.test(path));
  const navigationPool=nonGenerated.length>=8 ? nonGenerated : rankedPool;
  const paths=focus ? rankedPool : navigationPool
    // Application ownership takes precedence over a probe-compatible dependency
    // signature across Solidity, Python, JavaScript, and Java. The overnight
    // 88mph run paginated a supporting ERC1155 library before application code.
    .sort((a,b)=>sourcePriority(b)-sourcePriority(a) ||
      (referenceScores.get(b)||0)-(referenceScores.get(a)||0) ||
      pathDepth(a)-pathDepth(b) ||
      (signatureScores.get(b)||0)-(signatureScores.get(a)||0))
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
