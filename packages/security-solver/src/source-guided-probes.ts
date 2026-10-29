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
