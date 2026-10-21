import { readdir, readFile, stat } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";

export interface ReadSpan { start: number; end: number }
export class SourceReads {
  private spans = new Map<string, ReadSpan[]>();
  add(path:string, span:ReadSpan) { this.spans.set(path, [...(this.spans.get(path) || []), span]); }
  has(path:string) { return this.spans.has(path); }
  sawLine(path:string, text:string, line:number):boolean {
    if (!Number.isSafeInteger(line) || line < 1) return false;
    const lines = text.split("\n");
    if (line > lines.length || !lines[line-1].trim()) return false;
    const start = lines.slice(0,line-1).reduce((n,s)=>n+s.length+1,0);
    const end = start + lines[line-1].length;
    let covered = start;
    for (const span of [...(this.spans.get(path) || [])].sort((a,b)=>a.start-b.start)) {
      if (span.start > covered) break;
      if (span.end > covered) covered = span.end;
      if (covered >= end) return true;
    }
    return false;
  }
}
export function pageOffset(value:unknown):number {
  const offset = value ?? 0;
  if (!Number.isSafeInteger(offset) || Number(offset) < 0) throw new Error("offset must be a nonnegative integer");
  return Number(offset);
}
/** Offsets count UTF-16 characters, matching JS string slices and evidence spans. */
export async function readSourcePage(full:string, offset=0, pageSize=12000) {
  const info = await stat(full);
  if (!info.isFile() || info.size > 2_000_000) throw new Error("Not a readable source file under 2MB");
  const text = await readFile(full,"utf8");
  if (offset > text.length) throw new Error("Read offset exceeds file length");
  const end = Math.min(offset+pageSize,text.length);
  return {start:offset,end,totalCharacters:text.length,nextOffset:end<text.length?end:null,text:text.slice(offset,end)};
}
/** Sorted, scoped traversal. Each page states whether more files or matches remain. */
export async function searchSourcePage(root:string, full:string, query:string, offset=0, signal?:AbortSignal) {
  if (query.length < 3 || query.length > 120) throw new Error("Search query must contain 3..120 characters");
  let visited=0, scanned=0, skippedLargeFiles=0, traversed=0;
  const results:string[]=[];
  let nextOffset:number|null=null;
  let matchesTruncatedInFile:string|null=null;
  async function* files(dir:string):AsyncGenerator<string> {
    signal?.throwIfAborted();
    if (++traversed>100000) throw new Error("Search directory limit reached; choose a narrower path");
    const info = await stat(dir);
    if (info.isFile()) {yield dir;return;}
    const entries=(await readdir(dir,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name,"en"));
    for(const entry of entries) {
      signal?.throwIfAborted();
      if(entry.isSymbolicLink() || entry.name.startsWith(".") || ["node_modules","dist","build","vendor"].includes(entry.name))continue;
      const path=resolve(dir,entry.name);
      if(entry.isDirectory())yield* files(path);
      else if(entry.isFile() && /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|php|rb|sol|json|yaml|yml)$/.test(entry.name))yield path;
    }
  }
  for await (const path of files(full)) {
    if(visited++<offset)continue;
    if(scanned>=300 || results.length>=40) {nextOffset=visited-1;break;}
    scanned++;
    if((await stat(path)).size>2_000_000) {skippedLargeFiles++;continue;}
    const lines=(await readFile(path,"utf8")).split("\n");
    for(let i=0;i<lines.length;i++) {
      if(!lines[i].includes(query))continue;
      if(results.length>=40) {matchesTruncatedInFile=relative(root,path).split(sep).join("/");break;}
      results.push(relative(root,path).split(sep).join("/")+":"+(i+1)+": "+lines[i].slice(0,240));
    }
  }
  return {results,scannedFiles:scanned,skippedLargeFiles,nextOffset,matchesTruncatedInFile,
    complete:nextOffset===null && matchesTruncatedInFile===null && skippedLargeFiles===0,
    note:"Search excludes hidden paths, symlinks, node_modules, dist, build and vendor. Use read_file for remaining matches in a truncated file; nextOffset continues with subsequent files."};
}
