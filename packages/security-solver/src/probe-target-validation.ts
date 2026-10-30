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
