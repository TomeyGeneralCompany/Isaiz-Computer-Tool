/** Progress is credited from delivered evidence, never from the model's claims. */
export class AuditAllowance {
  turns: number;
  deadline: number;
  readonly hardDeadline: number;
  private spans = new Map<string, Array<[number, number]>>();
  private probes = new Set<string>();
  private credits: number[] = [];
  constructor(readonly initialTurns:number, readonly started:number, readonly timeoutMs:number,
    readonly dynamic=false, readonly hardTurns=640) {
    this.turns=initialTurns;
    this.deadline=started+timeoutMs;
    this.hardDeadline=started+Math.max(timeoutMs,24*60*60*1000);
  }
  read(path:string,start:number,end:number,turn:number):boolean {
    if(end<=start)return false;
    const ranges=this.spans.get(path)||[];
    let cursor=start;
    for(const [a,b] of ranges) {if(a>cursor)break;cursor=Math.max(cursor,b);}
    const novel=cursor<end;
    ranges.push([start,end]);ranges.sort((a,b)=>a[0]-b[0]);
    const merged:Array<[number,number]>=[];
    for(const range of ranges) {
      const last=merged.at(-1);
      if(last && range[0]<=last[1])last[1]=Math.max(last[1],range[1]);
      else merged.push([...range]);
    }
    this.spans.set(path,merged);
    if(novel && this.credits.at(-1)!==turn)this.credits.push(turn);
    return novel;
  }
  probe(key:string,turn:number) {
    if(this.probes.has(key))return;
    this.probes.add(key);
    if(this.credits.at(-1)!==turn)this.credits.push(turn);
  }
  extend(turn:number,now:number) {
    if(!this.dynamic || now>=this.deadline || now>=this.hardDeadline || turn>=this.hardTurns)return null;
    this.credits=this.credits.filter(t=>t>=turn-20);
    if(this.credits.length<10 || this.credits.at(-1)!<turn-3)return null;
    if(this.turns-turn>5 && this.deadline-now>Math.min(this.timeoutMs/5,15*60000))return null;
    const oldTurns=this.turns,oldDeadline=this.deadline;
    this.turns=Math.min(this.hardTurns,this.turns+40);
    this.deadline=Math.min(this.hardDeadline,this.deadline+60*60000);
    if(this.turns===oldTurns && this.deadline===oldDeadline)return null;
    const reason={turn,newEvidenceTurns:this.credits.length,oldTurns,turns:this.turns,
      oldDeadline:new Date(oldDeadline).toISOString(),deadline:new Date(this.deadline).toISOString()};
    this.credits=[];
    return reason;
  }
  snapshot() {return {dynamicEnabled:this.dynamic,extensionRule:{minimumEvidenceTurns:10,windowTurns:20,recentWithinTurns:3},creditedTurns:this.credits.slice(-20),hardTurns:this.hardTurns,turnAllowance:this.turns,deadline:new Date(this.deadline).toISOString(),
    files:[...this.spans].map(([path,ranges])=>({path,ranges})),completedDistinctProbes:this.probes.size};}
}
