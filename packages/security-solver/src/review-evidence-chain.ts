import {readFile} from 'node:fs/promises';
import {dirname,join,relative,resolve,sep} from 'node:path';
import {createHash} from 'node:crypto';
import {inspectSourceCapability} from './source-capability';
import {controllerCallerChain,solidityDependentSources} from './source-flow-facts';

export type ReviewLink = {file:string;line:number;code:string;relationship:string};
export type ReviewEvidence = {
  language:string;kind:string;reachabilityRequirement:string;
  links:ReviewLink[];unresolved:string[];sourceDigest:string;
  summary:string;
};

/** Source-derived call edges, NOT an inferred vulnerability or an exploitability proof.
 * Only quote actual in-repository lines; limit traversal and never follow traversal/symlinks.
 */
export async function buildReviewEvidence(repository:string,input:{
  testedFile:string;testedFunction:string;callerFile:string;callerLine:number;
  kind:string;reachability:string
}):Promise<ReviewEvidence> {
  const base=resolve(repository);
  const language=input.testedFile.endsWith('.java')?'java':
    input.testedFile.endsWith('.py')?'python':
    /\.(?:cjs|mjs|js|ts)$/.test(input.testedFile)?'javascript':
    input.testedFile.endsWith('.sol')?'solidity':'other';
  const requirements:Record<string,string>={
    java:'Establish the calling Java method, trace the supplied argument through invoked methods into an HTML/string output, check effective escaping and input trust. A blockchain transaction is NOT a prerequisite for Java source-level reachability.',
    python:'Establish the input origin and subsequent data flow to the relevant output or filesystem operation; distinguish request parsing from sanitization.',
    javascript:'Establish attacker-influenced input, dynamic output context, and actual encoding or validation before the sink.',
    solidity:'Establish transaction entry, reachable state changes, privileges and concrete transaction/state sequence.',
    other:'Establish the language-appropriate input origin, concrete call chain, relevant sink, and any mitigation.'
  };
  const links:ReviewLink[]=[]; const unresolved:string[]=[];
  const seen=new Set<string>();
  const selector=input.testedFunction.split('.').at(-1)||input.testedFunction;
  const safeRead=async (file:string):Promise<string|null>=>{
    if(!file || file.startsWith('/') || file.split(/[\\/]/).includes('..'))return null;
    const absolute=resolve(base,file);
    if(!absolute.startsWith(base+sep))return null;
    try {
      const {realpath}=await import('node:fs/promises');
      const canonical=await realpath(absolute);
      if(!canonical.startsWith(base+sep))return null;
      return await readFile(canonical,'utf8');
    }catch{return null;}
  };
  const appendLines=(file:string,source:string,lo:number,hi:number,relationship:string)=>{
    const lines=source.split('\n');
    for(let i=Math.max(0,lo);i<Math.min(hi,lines.length);i++){
      const code=lines[i].trim();
      if(!code)continue;
      const key=file+':'+(i+1);
      if(seen.has(key))continue;
      seen.add(key);
      links.push({file,line:i+1,code:lines[i],relationship});
    }
  };
  const caller=await safeRead(input.callerFile);
  if(caller){
    appendLines(input.callerFile,caller,input.callerLine-3,input.callerLine+2,'recorded caller context');
  }else unresolved.push('Recorded caller file cannot be read');
  const target=await safeRead(input.testedFile);
  if(target){
    const lines=target.split('\n'),ix=lines.findIndex(x=>x.includes(selector+'(')||x.includes(selector+' ('));
    appendLines(input.testedFile,target,Math.max(0,ix-2),Math.max(0,ix)+12,'reproduced function and nearby source');
    if(ix<0)unresolved.push('Selector not textually found in tested source');
  }else unresolved.push('Tested source file cannot be read');
  if(language==='java' && target) {
    const queue:[string,string][]=[[input.testedFile,target]];
    const visited=new Set<string>();
    while(queue.length && visited.size<8){
      const [file,body]=queue.shift()!;
      if(visited.has(file))continue;
      visited.add(file);
      for(const match of body.matchAll(/\b([A-Z][A-Za-z0-9_]*)\.([a-zA-Z][A-Za-z0-9_]*)\s*\(/g)){
        const helper=join(dirname(file),match[1]+'.java').split(sep).join('/');
        if(helper===file||visited.has(helper))continue;
        const helperCode=await safeRead(helper);
        if(!helperCode){unresolved.push('Unresolved potential call '+match[1]+'.'+match[2]+' in '+file);continue;}
        const methodLines=helperCode.split('\n');
        const methodAt=methodLines.findIndex(line=>line.includes(match[2]+'('));
        if(methodAt>=0){
          appendLines(helper,helperCode,Math.max(0,methodAt-1),methodAt+12,'referenced Java helper: '+match[1]+'.'+match[2]);
          queue.push([helper,helperCode]);
        }else unresolved.push('Java helper method not found in '+helper+': '+match[2]);
      }
    }
  }
  // Reconstruct caller reachability from committed source for every language,
  // rather than stopping at the first caller named in the report. This is
  // deterministic navigation evidence, not model-supplied taint assertions.
  try {
    const capability=await inspectSourceCapability(repository,undefined,false);
    const paths=capability.sourcePaths.slice(0,256);
    if(['java','python','javascript'].includes(language)){
      const upstream=await controllerCallerChain(repository,'',input.testedFile,
        input.testedFunction,paths,4);
      for(const edge of upstream){
        const body=await safeRead(edge.path);
        if(!body)continue;
        appendLines(edge.path,body,edge.line-12,edge.line+2,
          'import-resolved upstream caller of '+edge.selector);
      }
      if(!upstream.length)unresolved.push('No additional import-resolved upstream callers found in bounded committed source');
    }else if(language==='solidity'){
      const contract=input.testedFunction.split('.')[0];
      const dependents=await solidityDependentSources(repository,input.testedFile,
        contract,paths,6);
      for(const file of dependents){
        const body=await safeRead(file);
        if(!body)continue;
        const lines=body.split('\n');
        const indices=lines.map((line,index)=>
          /\b(?:import|is\s+|msg\.sender|require\s*\(|onlyOwner|onlyAdmin|operator|administrator)\b/.test(line)?index:-1)
          .filter(index=>index>=0).slice(0,8);
        for(const index of indices)appendLines(file,body,Math.max(0,index-1),index+2,
          'dependent Solidity contract; independently verify role enforcement');
      }
    }
  }catch(error){
    unresolved.push('Bounded upstream source scan unavailable: '+String(error).slice(0,180));
  }
  // Source lines and their digest persist as immutable review facts. A static call
  // edge alone does not prove that the argument can be controlled by an attacker.
  const sourceDigest=createHash('sha256').update(JSON.stringify(links)).digest('hex');
  const summary=[
    'Language: '+language+'; probe: '+input.kind+'; reachability: '+input.reachability,
    'Required evidence: '+(requirements[language]||requirements.other),
    'Source-backed lines (quoted verbatim; no inferred taint or exploitability):',
    ...links.map(x=>x.file+':'+x.line+' ['+x.relationship+'] '+x.code),
    'Unresolved edges: '+(unresolved.length?unresolved.join('; '):'none detected by this bounded scan'),
    'Evidence SHA256: '+sourceDigest,
    'A local reproduction supports behavior only. Judge attacker control, mitigation, context and real impact independently.'
  ].join('\n');
  return {language,kind:input.kind,reachabilityRequirement:requirements[language]||requirements.other,
    links,unresolved,sourceDigest,summary};
}

/** Reject unspecific/contradictory objections; do not auto-approve findings. */
export function reviewRejectionDefect(review:{
  verdict:string;issues:{category:string;severity:string;description:string}[];reasoning:string
},evidence:ReviewEvidence):string|null {
  if(review.verdict!=='reject')return null;
  const fatal=review.issues.filter(issue=>issue.severity==='fatal');
  if(!fatal.length)return 'For rejection, identify at least one specific fatal technical defect in issues, tied to an actual source location or missing evidence. Do not rely on a general impression.';
  const prose=[...fatal.map(i=>i.description),review.reasoning].join(' ');
  if(evidence.language!=='solidity' &&
    /\b(?:blockchain|on.chain|contract transaction|production transaction|transaction (?:path|trace|sequence|entry))\b/i.test(prose))
    return 'Transaction-chain reachability is a Solidity criterion, not a requirement for this '+evidence.language+' source review. Name the actual missing input/sink link or mitigation instead.';
  if(/\b(?:no production (?:endpoint|request|deployment)|not deployed|local (?:probe|test) only)\b/i.test(prose) &&
    !/\b(?:mitigation|sanitiz|escape|unreachable|untrusted|attacker|input origin|sink)\b/i.test(prose))
    return 'A local reproduction is not proof of full impact, but lack of production testing alone is not a specific source-level technical defect. Identify the missing source link or effective mitigation.';
  // A positive assertion that a sanitizer exists must be backed by source,
  // not merely by the helper's reassuring name. Missing evidence is a request
  // for further inspection, NEVER grounds for automatic approval.
  const mitigationAsserted=fatal.some(i=>/\b(?:effective (?:saniti[sz]er|escap(?:ing|er))|saniti[sz]es? (?:the|user|input|value)|escapes? (?:the|user|input|value|html)|mitigated by (?:escap|saniti[sz]))/i.test(i.description));
  if(mitigationAsserted) {
    const matching=evidence.links.filter(link=>/\b(?:replace\s*\(|escape(?:Html|XML|ForHTML)?\s*\(|sanitize\s*\(|encodeForHTML\s*\(|StringEscapeUtils\.)/i.test(link.code));
    if(!matching.length)return 'The fatal rejection asserts an effective sanitizer, but the recorded source chain contains no source-backed sanitization operation. Read the alleged sanitizer implementation and cite its actual file and line before rejecting.';
  }
  const deniesRecordedCaller=fatal.some(i=>/\b(?:no caller (?:calls|invokes|references)|caller does not (?:call|invoke|reference))\b/i.test(i.description));
  if(deniesRecordedCaller && evidence.links.some(x=>x.relationship==='recorded caller context' && /\b(?:render|wrap|invoke|call)\s*\(/i.test(x.code)))
    return 'The recorded caller contains an actual invocation. Distinguish an untrusted-input/reachability gap from a claim that no call exists, citing the missing link.';
  // The verifier's fixed probe strings do not imply the application accepts
  // only hardcoded input. A demonstrated request-parameter source and an
  // import-resolved renderer call contradict that specific rejection premise.
  // This requests a more precise technical explanation; it NEVER approves.
  const dismissesAsHardcoded=/\b(?:hardcoded (?:test )?input|only (?:static|fixed) (?:test )?input|no (?:external|attacker) (?:input|influence))\b/i.test(prose);
  const hasRequestInput=evidence.links.some(link=>
    /\b(?:searchParams\.get\s*\(|parse_qs\s*\(|req\.query\b|request\.(?:GET|args|query)\b)/.test(link.code));
  const hasRenderedCall=evidence.links.some(link=>
    /\b(?:return|res\.(?:send|end))\b[^\n]*\b(?:render|responseBody|wrapFragment)\s*\(/.test(link.code));
  if(dismissesAsHardcoded && hasRequestInput && hasRenderedCall)
    return 'The source packet contains a request-parameter extraction and a source-resolved call into the renderer. Fixed isolated probe tokens do not establish that application inputs are hardcoded. Name the actual missing source-to-sink edge or effective mitigation and cite its file and line before rejecting.';
  // Reject factual contradictions in the review itself, NOT negative verdicts.
  // These are source-derived sanity checks; the reviewer must still decide
  // exploitability and can reject for a genuinely missing security boundary.
  if(evidence.kind==='html_reflection') {
    const lines=evidence.links.map(link=>link.code).join('\n');
    const actualEscape=/\b(?:escape\s*\(|sanitize\s*\(|encodeForHTML\s*\(|StringEscapeUtils\.|replace\s*\(\s*["'][&<>])/i.test(lines);
    const requestControlled=/\b(?:searchParams\.get\s*\(|parse_qs\s*\(|req\.query\b|request\.(?:GET|args|query)\b)/.test(lines);
    // Test positive mitigation ASSERTIONS only. The previous broad co-occurrence
    // regex also rejected accurate reviewer statements such as "parsing does not
    // sanitize", exhausting the three independent review attempts.
    const parserMitigationClaim=fatal.some(issue=>{
      const claim=issue.description;
      const asserted=/\b(?:parsing|parsed|parse_qs|searchParams(?:\.get)?|URL\.searchParams)\b.{0,120}\b(?:saniti[sz](?:es|ed|ing)?|escap(?:es|ed|ing)?|validat(?:es|ed|ion)?)\b|\b(?:saniti[sz](?:es|ed|ing)?|escap(?:es|ed|ing)?|validat(?:es|ed|ion)?)\b.{0,120}\b(?:parsing|parsed|parse_qs|searchParams)\b/i.test(claim);
      const negated=/\b(?:does not|do not|cannot|can't|not|no|without|doesn't)\b.{0,90}\b(?:saniti[sz]|escap|validat)\w*|\b(?:saniti[sz]|escap|validat)\w*.{0,80}\b(?:not|absent|missing|none)\b/i.test(claim);
      return asserted && !negated;
    });
    if(requestControlled && parserMitigationClaim && !actualEscape)
      return 'The observed request-parameter parser extracts input; parsing does not HTML-escape or sanitize. The recorded source contains no matching escaping operation. Identify a real validation/escaping line or revise the asserted mitigation; independently assess actual reachability and impact.';
    const unsupportedValidation=/\b(?:explicitly validated|validated by the caller|input is sanitized by (?:the application.?s )?context|safe HTML fragment handler)\b/i.test(prose);
    if(unsupportedValidation && !actualEscape)
      return 'The review attributes safety to validation, HTML context or a helper name without identifying a source-backed escaping or validation operation. Cite the actual protection and source line, or assess the unescaped output and attacker-control requirements separately.';
    const identityDisprovesRisk=/\b(?:returns? (?:the )?input unmodified|does not modify the input|no sanitization|without any sanitization|without any escaping)\b[\s\S]{0,240}\b(?:no (?:actual )?security (?:risk|impact|vulnerability)|safe|not vulnerable)\b/i.test(prose);
    if(identityDisprovesRisk && !actualEscape)
      return 'Returning unescaped user data does not itself mitigate HTML reflection. If rejecting, identify the actual absent input-to-sink edge, rendering context, or source-backed mitigation rather than treating identity encoding as proof of safety.';
  }
  const grounds=/\b(?:unreachab\w*|reachab\w*|untrusted|attacker|input|source|sink|saniti[sz]\w*|escap\w*|mitigat\w*|guard\w*|access|privilege|authorization|state|sequence|replay|observ\w*|scope|impact|evidence|caller|path)\b/i;
  if(!fatal.some(i=>grounds.test(i.description)))
    return 'Fatal rejection must name a specific missing source-to-sink link, mitigation, untrusted-input issue, reproduction discrepancy, or other technical defect.';
  return null;
}
