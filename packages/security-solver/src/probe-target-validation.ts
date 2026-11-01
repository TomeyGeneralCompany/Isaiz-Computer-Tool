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


/** Report only Java declarations matching the one-argument text probe contract. */
export async function supportedJavaProbeHints(path:string,limit=12):Promise<string[]> {
  if(!path.endsWith('.java'))return [];
  const text=await readFile(path,'utf8');
  if(text.length>512000)return [];
  const code=sourceCodeOnly(text);
  const cls=code.match(/\bclass\s+([A-Za-z_$][\w$]*)\b/)?.[1];
  if(!cls)return [];
  const found=new Set<string>();
  const re=/\bpublic\s+static\s+(String|byte\s*\[\s*\])\s+([A-Za-z_$][\w$]*)\s*\(\s*(?:final\s+)?(String|byte\s*\[\s*\])\s+[A-Za-z_$][\w$]*\s*\)\s*\{/g;
  for(const m of code.matchAll(re)) {
    found.add(cls+'.'+m[2]);
    if(found.size>=limit)break;
  }
  return [...found];
}


/** Preflight the exact Java method signature before scheduling a supported
 * one-input reproduction. Unknown signatures remain unapproved, not findings. */
export async function javaProbeSelectorCompatible(path:string,selector:string):Promise<boolean> {
  if(!path.endsWith('.java'))return false;
  const text=await readFile(path,'utf8');
  if(text.length>512000)return false;
  const code=sourceCodeOnly(text);
  const [cls,name,extra]=selector.split('.');
  if(extra || !cls || !name || !/^[A-Za-z_$][\w$]*$/.test(name))return false;
  if(!new RegExp('\\bclass\\s+'+cls+'\\b').test(code))return false;
  const safeName=name.replace(/[$]/g,'\\$&');
  const declaration=new RegExp('\\bpublic\\s+static\\s+(?:String|byte\\s*\\[\\s*\\])\\s+'+
    safeName+'\\s*\\(\\s*(?:final\\s+)?(?:String|byte\\s*\\[\\s*\\])\\s+[A-Za-z_$][\\w$]*\\s*\\)\\s*\\{');
  return declaration.test(code);
}
