import {readFile} from 'node:fs/promises';
import {sourceCodeOnly} from './source-function-reference';

/** Declaration preflight across supported languages; reproduction remains authoritative. */
export async function declaredProbeTarget(path:string,selector:string):Promise<boolean> {
  const text=await readFile(path,'utf8');
  if(text.length>512000)return false;
  const code=sourceCodeOnly(text);
  const parts=selector.split('.');
  const name=parts.at(-1)||'';
  if(!/^[A-Za-z_$][\w$]*$/.test(name) || ['function','method','unknown','test','probe'].includes(name.toLowerCase()))return false;
  const escaped=name;
  if(path.endsWith('.py'))return parts.length===1 &&
    new RegExp('(?:^|\\n)\\s*(?:async\\s+)?def\\s+'+escaped+'\\s*\\(','m').test(code);
  if(path.endsWith('.java'))return parts.length===2 &&
    new RegExp('\\b(?:class|interface|record|enum)\\s+'+parts[0]+'\\b').test(code) &&
    new RegExp('\\b'+escaped+'\\s*\\([^;{}]*\\)\\s*(?:throws\\s+[\\w.,\\s]+)?\\s*\\{').test(code);
  if(/\.(?:js|mjs|cjs)$/.test(path))return parts.length===1 &&
    (new RegExp('(?:\\bfunction\\s+|\\b(?:const|let|var)\\s+|\\bexports\\.|\\bmodule\\.exports\\.|\\bexport\\s+(?:async\\s+)?function\\s+)'+escaped+'\\b').test(code) ||
    new RegExp('\\b'+escaped+'\\s*[:=(]\\s*(?:async\\s*)?(?:function|\\([^)]*\\)\\s*=>)').test(code));
  return false;
}


/**
 * Provide evidence-backed declaration names after an invalid probe selector.
 * Names are navigation hints, NOT claims that a method has an eligible runtime
 * signature. The normal declaration preflight and isolated reproduction still
 * decide eligibility and findings.
 */
export async function sourceDeclarationHints(path:string,limit=16):Promise<string[]> {
  const text=await readFile(path,'utf8');
  if(text.length>512000)return [];
  const code=sourceCodeOnly(text);
  const found=new Set<string>();
  const add=(selector:string)=>{if(found.size<limit && selector.length<160)found.add(selector);};
  if(path.endsWith('.java')) {
    const cls=code.match(/\b(?:class|record|enum)\s+([A-Za-z_$][\w$]*)\b/)?.[1];
    if(!cls)return [];
    const re=/\b(?:public|protected)\s+(?:(?:static|final|synchronized|native|abstract|default)\s+)*(?:<[^>\n]+>\s*)?(?:[\w$<>,.?[\]]+\s+)+([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws\s+[\w.,\s]+)?\s*\{/g;
    for(const m of code.matchAll(re))add(cls+'.'+m[1]);
  } else if(path.endsWith('.py')) {
    for(const m of code.matchAll(/(?:^|\n)\s*(?:async\s+)?def\s+([A-Za-z_$][\w$]*)\s*\(/g))add(m[1]);
  } else if(/\.(?:js|mjs|cjs)$/.test(path)) {
    for(const m of code.matchAll(/\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g))add(m[1]);
    for(const m of code.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>)/g))add(m[1]);
  }
  return [...found];
}


/** Java declarations eligible for the fixed reproduction adapter's one-input API.
 * Runtime compilation and reflection remain authoritative.
 * This inspects source; it never executes the target. */
export async function supportedJavaProbeHints(path:string,limit=32):Promise<string[]> {
  if(!path.endsWith('.java'))return [];
  const text=await readFile(path,'utf8');
  if(text.length>256000)return [];
  const code=sourceCodeOnly(text);
  const cls=path.split(/[\\/]/).at(-1)!.slice(0,-5);
  if(!/^[A-Za-z_$][\w$]*$/.test(cls))return [];
  if(!new RegExp('\\bpublic\\s+(?:(?:final|abstract)\\s+)?class\\s+'+cls+'\\b').test(code))return [];
  const types='(?:String|byte\\s*\\[\\s*\\]|CharSequence|StringBuilder|StringBuffer|ByteBuffer|Path|File|URI|Object)';
  // Reflection only selects public one-parameter methods. Match the same
  // declared input and output types as java-probe.py's runtime adapter.
  const re=new RegExp('\\bpublic\\s+((?:(?:static|final|synchronized)\\s+)*)('+types+')\\s+([A-Za-z_$][\\w$]*)\\s*\\(\\s*(?:final\\s+)?'+types+'\\s+[A-Za-z_$][\\w$]*\\s*\\)\\s*(?:throws\\s+[\\w.,\\s]+)?\\s*\\{','g');
  const constructors=[...code.matchAll(new RegExp('\\b(?:public|protected|private)\\s+'+cls+'\\s*\\(', 'g'))];
  const hasExplicitConstructor=constructors.length>0;
  const hasPublicNoArg=!hasExplicitConstructor || new RegExp('\\bpublic\\s+'+cls+'\\s*\\(\\s*\\)').test(code);
  const eligible:string[]=[];
  for(const match of code.matchAll(re)) {
    const isStatic=/\bstatic\b/.test(match[1]);
    if(!isStatic && !hasPublicNoArg)continue;
    const selector=cls+'.'+match[3];
    if(!eligible.includes(selector))eligible.push(selector);
    if(eligible.length>=limit)break;
  }
  return eligible;
}

/** Same compatibility rules feed both suggestions and preflight. */
export async function javaProbeSelectorCompatible(path:string,selector:string):Promise<boolean> {
  if(!path.endsWith('.java'))return false;
  return (await supportedJavaProbeHints(path,256)).includes(selector);
}


export type ProbeChoice={selector:string;kind:'html_reflection'|'path_construction'|'solidity_sequence';format:string};
/** Shared source-derived probe menu. A choice describes a supported request;
 * only the isolated verifier determines whether it executes successfully. */
export async function probeChoices(path:string,kind:'html_reflection'|'path_construction'|'solidity_sequence',limit=24):Promise<ProbeChoice[]> {
  if(kind==='solidity_sequence')return [];
  const names=path.endsWith('.java') ? await supportedJavaProbeHints(path,limit) : await sourceDeclarationHints(path,limit);
  const eligible:string[]=[];
  for(const name of names) {
    if(path.endsWith('.java') || await declaredProbeTarget(path,name))eligible.push(name);
    if(eligible.length>=limit)break;
  }
  return eligible.map(selector=>({selector,kind,format:JSON.stringify({
    action:'plan_probe',path:'<inspected workspace path>',query:selector,answer:kind,
    hypothesis:'Specific suspected behavior and a disconfirming observation'
  })}));
}
