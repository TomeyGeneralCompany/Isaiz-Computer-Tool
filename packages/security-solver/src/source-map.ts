import {readFile,realpath,stat} from 'node:fs/promises';
import {resolve,relative,sep} from 'node:path';
import {sourceCodeOnly} from './source-function-reference';
export type SourceSymbol={path:string;name:string;offset:number;line:number;signature:string;probeHint:string;callers:Array<{path:string;line:number}>};
/** Bounded lexical navigation map, never a substitute for source or compiler binding. */
export async function buildSourceMap(root:string,paths:string[]) {
  const base=await realpath(root),symbols:SourceSymbol[]=[],sources:Array<{path:string;code:string}>=[];
  let bytes=0,skipped=0;
  for(const path of paths.slice(0,128)) {
    try {
      const full=await realpath(resolve(base,path)),rel=relative(base,full);
      if(rel==='..'||rel.startsWith('..'+sep)) {skipped++;continue;}
      const size=(await stat(full)).size;
      if(size>256000 || bytes+size>2000000){skipped++;continue;}
      const text=await readFile(full,'utf8');bytes+=size;
      const code=sourceCodeOnly(text);sources.push({path,code});
      const declarations=/\b(?:def|function)\s+([A-Za-z_$][\w$]*)\s*\([^\n)]*\)|\b(?:public\s+)?(?:static\s+)?String\s+([A-Za-z_$][\w$]*)\s*\([^\n)]*\)|\b(?:const|let)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^\n)]*\)\s*=>/g;
      for(const match of code.matchAll(declarations)) {
        if(symbols.length>=256)break;
        const signature=text.slice(match.index!,match.index!+match[0].length);
        const probeHint=path.endsWith('.sol')?'Solidity: inspect ABI/constructor and state assertions':
          path.endsWith('.java')&&!/public\s+static\s+String/.test(signature)?'Not a supported public static String entrypoint; inspect caller or choose another candidate':
          'Candidate only: string probes require one string argument and a string result; inspect body, exports, dependencies and caller';
        symbols.push({path,name:match[1]||match[2]||match[3],offset:match.index!,line:text.slice(0,match.index).split('\n').length,signature,probeHint,callers:[]});
      }
    }catch{skipped++;}
  }
  for(const symbol of symbols) {
    const pattern=new RegExp('\\b'+symbol.name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'\\s*\\(','g');
    for(const source of sources)for(const match of source.code.matchAll(pattern)) {
      if(symbol.callers.length>=4)break;
      const prefix=source.code.slice(Math.max(0,match.index!-35),match.index);
      if(/(?:def|function|String)\s+$/.test(prefix))continue;
      symbol.callers.push({path:source.path,line:source.code.slice(0,match.index).split('\n').length});
    }
  }
  return {kind:'navigation_only',complete:false,scannedFiles:sources.length,skippedFiles:skipped+Math.max(0,paths.length-128),symbols,
    limitation:'Lexical candidates and possible callers; aliases, overloads and dynamic calls may be missed or misidentified. Read source to verify. No vulnerability or execution is established.'};
}
