/** Normalize investigation telemetry regardless of whether the controller or
 * the model initiated a read/probe. The answer key is consumed only by the
 * offline grader after the production run and independent review.
 */
export interface ProbeTelemetry {
 path:string; function:string; kind?:string; status?:string; caseId?:string;
}
function taggedEvents(log:string,tag:string):Array<Record<string,unknown>> {
 const out:Array<Record<string,unknown>>=[];
 for(const line of log.split('\n')) {
   const start=line.indexOf('['+tag+']');
   if(start<0)continue;
   const payload=line.slice(start+tag.length+2).trim();
   try {
     const parsed=JSON.parse(payload);
     if(parsed && typeof parsed==='object' && !Array.isArray(parsed))out.push(parsed);
   }catch{}
 }
 return out;
}
export function inspectGauntletEvents(log:string,expected:{file:string;selector:string},reviewedFinding:boolean) {
 const targetSuffix='/'+expected.file;
 const matchesPath=(path:unknown)=>typeof path==='string' &&
   (path===expected.file||path.endsWith(targetSuffix));
 const sameSelector=(selector:unknown)=>typeof selector==='string' &&
   (selector===expected.selector||selector.endsWith('.'+expected.selector));
 const reads=taggedEvents(log,'READ_OK');
 const prefetched=taggedEvents(log,'INITIAL_SOURCE_READ');
 const sourceReads=[...reads,...prefetched].filter(record=>typeof record.path==='string');
 // READ_OK has a legacy plain-text format, not JSON.
 const actualReadPaths=log.split('\n').flatMap(line=>{
   const idx=line.indexOf('[READ_OK] ');
   if(idx<0)return [];
   const tail=line.slice(idx+'[READ_OK] '.length);
   const cursor=tail.search(/\s+offset=/);
   return cursor<0?[]:[tail.slice(0,cursor)];
 });
 const sourceRead=actualReadPaths.length>0 || sourceReads.length>0;
 const targetRead=actualReadPaths.some(matchesPath) ||
   sourceReads.some(record=>matchesPath(record.path));
 const planned=taggedEvents(log,'PROBE_PLANNED');
 const executed=taggedEvents(log,'PROBE_RESULT');
 const guided=taggedEvents(log,'GUIDED_SOURCE_PROBE');
 const promoted=taggedEvents(log,'CONTROLLER_CALLER_PROBE');
 const probes:Array<ProbeTelemetry>=[
   ...executed.map(e=>({path:String(e.path||''),function:String(e.function||''),kind:String(e.kind||''),status:String(e.status||''),caseId:String(e.caseId||'')})),
   ...guided.map(e=>({path:String(e.path||''),function:String(e.function||''),kind:String(e.kind||''),status:String(e.status||''),caseId:String(e.caseId||'')})),
   ...promoted.map(e=>({path:String(e.path||''),function:String(e.function||''),kind:String(e.kind||''),status:String(e.status||''),caseId:String(e.caseId||'')}))
 ];
 const targetProbe=probes.some(p=>matchesPath(p.path)&&sameSelector(p.function)&&
   ['behavior_observed','behavior_not_observed','observation_only'].includes(String(p.status)));
 const completed=probes.filter(p=>['behavior_observed','behavior_not_observed','observation_only'].includes(String(p.status)));
 const plannedAny=planned.length>0||guided.length>0||promoted.length>0;
 return {
   sourceRead,
   targetRead,
   targetProbe,
   plannedAny,
   executedAny:probes.length>0,
   completedCount:completed.length,
   attempts:probes.length,
   verifiedFinding:reviewedFinding,
   counters:{
     controllerGuidedProbes:guided.length,controllerCallerProbes:promoted.length,modelOrControllerPlanned:planned.length,
     modelOrControllerExecuted:executed.length,
     completed:completed.length,sourcePages:actualReadPaths.length+sourceReads.length
   }
 };
}
