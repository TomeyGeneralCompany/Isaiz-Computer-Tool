import {posix} from 'node:path';
/** Navigation hints only. Evidence still comes exclusively from executed tools. */
export class AuditNavigation {
  private pending=new Map<string,{action:string;path:string;offset:number;query?:string}>();
  private visited=new Set<string>();
  private recent:Array<Record<string,unknown>>=[];
  observe(action:string,path:string,offset:number,query:string,result:any) {
    path=path.replaceAll('\\','/');
    const key=JSON.stringify([action,path,query]);
    this.visited.add(key);this.pending.delete(key);
    if(Number.isSafeInteger(result?.nextOffset) && result.nextOffset>offset)
      this.pending.set(key,{action,path,offset:result.nextOffset,...(query?{query}:{})});
    if(action==='list_files' && Array.isArray(result?.entries)) {
      for(const entry of result.entries) {
        if(typeof entry!=='string')continue;
        const directory=entry.startsWith('dir '),file=entry.startsWith('file ');
        const entryName=entry.slice(directory?4:5);
        if((!directory && !file) || entryName.includes('/') || entryName==='..')continue;
        if(file && !/\.(sol|py|js|mjs|cjs|ts|tsx|rs|go)$/.test(entryName))continue;
        const target=posix.join(path,entryName),next=directory?'list_files':'read_file';
        const nextKey=JSON.stringify([next,target,'']);
        if(!this.visited.has(nextKey) && this.pending.size<256)this.pending.set(nextKey,{action:next,path:target,offset:0});
      }
    }
    this.recent.push({action,path,offset,...(result?.end!==undefined?{end:result.end}:{}),
      ...(action==='verify_source'||action==='verify_python'?{query,status:result?.status}:{}),nextOffset:result?.nextOffset});
    this.recent=this.recent.slice(-12);
    while(this.visited.size>512)this.visited.delete(this.visited.values().next().value!);
  }
  hint():string {
    const next=this.pending.values().next().value;
    return next ? 'Next available navigation action: '+JSON.stringify(next)+'. This is navigation guidance, not inspected evidence.'
      : 'No known unread page remains. If there is no testable candidate, use the task’s incomplete-inspection outcome; otherwise inspect a relevant caller or run the supported probe.';
  }
  snapshot() {return {recent:this.recent,next:[...this.pending.values()].slice(0,8)};}
}
