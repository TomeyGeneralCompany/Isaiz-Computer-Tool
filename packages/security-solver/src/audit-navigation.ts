import {posix} from 'node:path';
/** Navigation hints only. Evidence still comes exclusively from executed tools. */
export class AuditNavigation {
  private pending=new Map<string,{action:string;path:string;offset:number;query?:string}>();
  private visited=new Set<string>();
  private recent:Array<Record<string,unknown>>=[];
  seed(paths:string[]) {
    for(const path of paths.slice(0,32)) {
      if(!path || posix.isAbsolute(path) || path.split('/').includes('..'))continue;
      this.pending.set(JSON.stringify(['read_file',path,'']),{action:'read_file',path,offset:0});
    }
  }
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
        if(file && !/\.(sol|py|js|jsx|mjs|cjs|ts|tsx|rs|go|java|kt|kts|c|h|cpp|hpp|cs|php|rb)$/.test(entryName))continue;
        const target=posix.join(path,entryName),next=directory?'list_files':'read_file';
        const nextKey=JSON.stringify([next,target,'']);
        if(!this.visited.has(nextKey) && this.pending.size<256)this.pending.set(nextKey,{action:next,path:target,offset:0});
      }
    }
    if(result?.shortcut && typeof result.shortcut.path==='string' &&
      !posix.isAbsolute(result.shortcut.path) && !result.shortcut.path.split('/').includes('..')) {
      const target=posix.join(path,result.shortcut.path);
      const next=result.shortcut.action;
      const nextKey=JSON.stringify([next,target,'']);
      if(['list_files','read_file'].includes(next) && !this.visited.has(nextKey) && this.pending.size<256)
        this.pending.set(nextKey,{action:next,path:target,offset:0});
    }
    this.recent.push({action,path,offset,...(result?.end!==undefined?{end:result.end}:{}),
      ...(action==='verify_source'||action==='verify_python'?{query,status:result?.status}:{}),nextOffset:result?.nextOffset});
    this.recent=this.recent.slice(-12);
    while(this.visited.size>512)this.visited.delete(this.visited.values().next().value!);
  }
  hint():string {
    const choices=[...this.pending.values()];
    const next=choices.find(item=>item.action==='read_file') || choices.at(-1);
    return next ? 'Next available navigation action: '+JSON.stringify(next)+'. This is navigation guidance, not inspected evidence.'
      : 'No known unread page remains. If there is no testable candidate, use the task’s incomplete-inspection outcome; otherwise inspect a relevant caller or run the supported probe.';
  }
  snapshot() {return {recent:this.recent,next:[...this.pending.values()].slice(0,8)};}
}
