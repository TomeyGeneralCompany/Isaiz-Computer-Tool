/** Controller-owned full source inventory. Indexing is NOT a reproduction or finding.
 * Every eligible in-scope file is inspected before model inference, with
 * compact source facts retained outside the model's context window.
 */
import {createHash} from 'node:crypto';
import {readFile,realpath,stat} from 'node:fs/promises';
import {resolve,relative,sep} from 'node:path';
import {controllerSourceRiskSignal} from './source-candidates';
import {sourcePriority} from './source-capability';

export type IndexedSourceFact={
  path:string;sha256:string;bytes:number;risk:number;
  declarations:string[];dependencies:string[];excerpt:string;
};
export type ControllerSourceIndex={
  version:1;kind:'controller_navigation_only';complete:boolean;
  eligibleFiles:number;indexedFiles:number;skipped:Array<{path:string;reason:string}>;
  files:IndexedSourceFact[];rankedPaths:string[];
  limitation:string;
};
const extension=/\.(?:py|js|mjs|cjs|java|sol)$/;
const declaration=/^\s*(?:(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(|(?:export\s+)?(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\(|(?:public|external|protected|private)\s+(?:(?:static|final)\s+)*(?:(?:String|void|[A-Za-z_$][\w$<>]*)\s+)?[A-Za-z_$][\w$]*\s*\(|(?:function|contract)\s+[A-Za-z_]\w*\s*[({])/gm;
const relation=/\b(?:import|from|require\s*\(|extends|implements|is\s+[A-Z])/;
const rank=(entry:IndexedSourceFact)=>entry.risk*100+sourcePriority(entry.path)*10+
  (/(?:gateway|handler|controller|router|entry|server)/i.test(entry.path)?30:0);
export async function buildControllerSourceIndex(
  root:string,paths:string[],signal?:AbortSignal
):Promise<ControllerSourceIndex>{
  const base=await realpath(root);
  const files:IndexedSourceFact[]=[],skipped:Array<{path:string;reason:string}>=[];
  const unique=[...new Set(paths)].filter(path=>extension.test(path));
  for(const path of unique){
    signal?.throwIfAborted();
    if(path.startsWith('/')||path.split(/[\\/]/).includes('..')){
      skipped.push({path,reason:'outside_scope'});continue;
    }
    try{
      const full=await realpath(resolve(base,path));
      const local=relative(base,full);
      if(local==='..'||local.startsWith('..'+sep)||local===''){
        skipped.push({path,reason:'outside_scope'});continue;
      }
      const size=(await stat(full)).size;
      if(size>256000){skipped.push({path,reason:'oversize'});continue;}
      const content=await readFile(full,'utf8');
      const lines=content.split('\n');
      const declarations=[...content.matchAll(declaration)].slice(0,36)
        .map(m=>m[0].trim().slice(0,170));
      const dependencies=lines.filter(x=>relation.test(x)).slice(0,24).map(x=>x.trim().slice(0,180));
      const risk=controllerSourceRiskSignal(path,content);
      // Persist short verbatim source excerpts around source-derived sinks,
      // not model-written hypotheses. Full source remains at the exact path.
      const interesting=lines.findIndex(line=>/<p\b|innerHTML|operator\s*=|project\s*\(/i.test(line));
      const at=Math.max(0,interesting>=0?interesting:0);
      const excerpt=lines.slice(at,Math.min(lines.length,at+9)).join('\n').slice(0,1400);
      files.push({path,sha256:createHash('sha256').update(content).digest('hex'),
        bytes:size,risk,declarations,dependencies,excerpt});
    }catch{
      skipped.push({path,reason:'unreadable'});
    }
  }
  const rankedPaths=files.slice().sort((a,b)=>rank(b)-rank(a)||
    a.path.localeCompare(b.path)).map(item=>item.path);
  return {version:1,kind:'controller_navigation_only',
    complete:skipped.length===0&&files.length===unique.length,
    eligibleFiles:unique.length,indexedFiles:files.length,skipped,files,rankedPaths,
    limitation:'Full eligible source inventory with lexical relationships and exact hashes. Rankings and excerpts are navigation facts only; no caller reachability, runtime exploitability or security impact is proven.'};
}
export function controllerEvidencePacket(index:ControllerSourceIndex,limit=8){
  const byPath=new Map(index.files.map(f=>[f.path,f]));
  return {kind:index.kind,eligibleFiles:index.eligibleFiles,indexedFiles:index.indexedFiles,
    complete:index.complete,unreadable:index.skipped.length,
    candidates:index.rankedPaths.slice(0,Math.min(16,Math.max(1,limit)))
      .map(path=>byPath.get(path)).filter((x):x is IndexedSourceFact=>!!x)
      .map(f=>({path:f.path,sha256:f.sha256,risk:f.risk,
        declarations:f.declarations.slice(0,8),
        dependencies:f.dependencies.slice(0,6),excerpt:f.excerpt.slice(0,900)})),
    limitation:index.limitation};
}
