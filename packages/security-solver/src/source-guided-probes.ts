import {join,relative,sep} from 'node:path';
import {sourceDeclarationHints,supportedJavaProbeHints,declaredProbeTarget} from './probe-target-validation';
import {traceSourceCalls} from './source-flow-facts';
/**
 * Narrow, syntax-guided hints for the fixed source reproduction API.
 * Hints are not findings. Every selected function must be executed in the
 * existing isolated verifier, and its actual observation must be reviewed.
 *
 * Only recognize narrow, inspectable Python and Java one-string functions that
 * explicitly constructs paragraph markup. Leave other code to normal review.
 */
export type GuidedProbe={path:string;functionName:string;kind:'html_reflection';hypothesis:string};
export function guidedSourceProbe(path:string,code:string):GuidedProbe|null {
  if(path.endsWith('.java') && code.length<=256000) {
    // Only offer methods matching the isolated Java text probe's one-input contract.
    const className=path.split('/').at(-1)!.replace(/\.java$/,'');
    const declaration=/\bpublic\s+(?:static\s+)?(?:java\.lang\.)?String\s+([A-Za-z][A-Za-z0-9_]{0,79})\s*\(\s*(?:final\s+)?(?:java\.lang\.)?String\s+[A-Za-z_$][\w$]*\s*\)\s*\{/g;
    for(const match of code.matchAll(declaration)) {
      const end=code.indexOf('}',match.index!+match[0].length);
      if(end<0 || end-match.index!>6000)continue;
      const body=code.slice(match.index!+match[0].length,end);
      if(!/\breturn\b/.test(body)||!/<p>/i.test(body)||!/<\/p>/i.test(body))continue;
      return {path,functionName:className+'.'+match[1],kind:'html_reflection',
        hypothesis:'Check whether input HTML survives this Java paragraph renderer; escaped output disproves the suspected reflection.'};
    }
    return null;
  }
  if(/\.(?:js|mjs|cjs)$/.test(path) && code.length<=256000) {
    // Exported one-input CommonJS or ESM functions whose literal returned
    // expression produces HTML are eligible for the same isolated verifier.
    // A source-level match is only a hypothesis, never vulnerability proof.
    const declarations=[
      /\bexports\.([A-Za-z_$][\w$]*)\s*=\s*function\s*(?:[A-Za-z_$][\w$]*)?\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{/g,
      /\bexport\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\{/g
    ];
    for(const declaration of declarations)for(const match of code.matchAll(declaration)) {
      const end=code.indexOf('}',match.index!+match[0].length);
      if(end<0 || end-match.index!>6000)continue;
      const body=code.slice(match.index!+match[0].length,end);
      if(!/\breturn\b/.test(body) || !/<p>/i.test(body) || !/<\/p>/i.test(body))continue;
      return {path,functionName:match[1],kind:'html_reflection',
        hypothesis:'Check whether source-provided HTML input survives this exported renderer; escaped markup disproves reflection.'};
    }
    return null;
  }
  if(!path.endsWith('.py') || code.length>256000)return null;
  const declaration=/^def ([A-Za-z][A-Za-z0-9_]{0,79})\(([A-Za-z][A-Za-z0-9_]*)\)\s*(?:->\s*(?:str|String)\s*)?:\s*$/gm;
  for(const match of code.matchAll(declaration)) {
    const start=match.index!+match[0].length;
    const end=code.indexOf('\ndef ',start);
    const body=code.slice(start,end<0?code.length:end);
    // Require a plain return constructing a paragraph; don't pretend to
    // understand decorators, nested functions, arbitrary call graphs or aliases.
    if(!/^\s+return\s+/m.test(body))continue;
    if(!/<p>/i.test(body)||!/<\/p>/i.test(body))continue;
    if(body.length>6000)continue;
    return {path,functionName:match[1],kind:'html_reflection',
      hypothesis:'Check whether user markup survives paragraph construction; safely escaped output disproves the suspected reflection.'};
  }
  return null;
}

/** Look through source-resolved helper calls before the model chooses a probe.
 * The returned proposal must still pass the normal verifier; static traces
 * cannot establish runtime reachability or a vulnerability.
 */
export async function guidedProbeAcrossSourceChain(root:string,path:string,code:string):Promise<GuidedProbe|null> {
  const direct=guidedSourceProbe(path,code);
  if(direct)return direct;
  if(!/\.(?:java|py|js|mjs|cjs)$/.test(path))return null;
  const prefix=path.split('/')[0];
  if(!/^source-[0-9]+$/.test(prefix))return null;
  const repoRoot=join(root,prefix);
  const relativeFile=path.split('/').slice(1).join('/');
  const full=join(root,path);
  const names=path.endsWith('.java')?
    await supportedJavaProbeHints(full,12):await sourceDeclarationHints(full,12);
  for(const selector of names) {
    if(!(await declaredProbeTarget(full,selector)))continue;
    const trace=await traceSourceCalls(repoRoot,relativeFile,selector,4);
    const files=new Set(trace.facts.map(f=>f.path));
    if(files.size<2)continue;
    const lines=trace.facts.map(f=>f.source).join('\n');
    if(!/<p>/i.test(lines)||!/<\/p>/i.test(lines))continue;
    return {path,functionName:selector,kind:'html_reflection',
      hypothesis:'Source-resolved helper constructs HTML output; test whether input markup survives the full exported entry and whether escaping defeats it.'};
  }
  return null;
}
