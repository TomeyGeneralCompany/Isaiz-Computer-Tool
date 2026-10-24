/** Summarize controller markers only. Never return model prose or source contents. */
export function summarizeAuditLog(text:string) {
 const counts={requests:0,reads:0,pageAdvances:0,contextRereads:0,duplicateRequests:0,rejectedFinals:0,probeRequests:0};
 const durations={queueMs:0,loadMs:0,promptMs:0,generationMs:0};
 let timings=0;
 const pages=new Set<string>();
 for(const line of text.split('\n')) {
  if(/^\[OLLAMA\].*request started/.test(line))counts.requests++;
  if(line.startsWith('[READ_OK] ')) {counts.reads++;pages.add(line.slice(10));}
  if(line.startsWith('[PAGE_ADVANCE] '))counts.pageAdvances++;
  if(line.startsWith('[CONTEXT_REREAD] '))counts.contextRereads++;
  if(line.startsWith('[NO_PROGRESS] '))counts.duplicateRequests++;
  if(line.startsWith('[FINAL_REJECTED] '))counts.rejectedFinals++;
  if(/^\[TOOL\] verify_(source|python)$/.test(line))counts.probeRequests++;
  if(line.startsWith('[TIMING] '))try {
   const timing=JSON.parse(line.slice(9));timings++;
   for(const key of Object.keys(durations) as Array<keyof typeof durations>)
    if(typeof timing[key]==='number' && Number.isFinite(timing[key]) && timing[key]>=0)durations[key]+=timing[key];
  }catch{}
 }
 return {...counts,distinctReadMarkers:pages.size,repeatedReadMarkers:counts.reads-pages.size,timings,durations,
  limitation:'Counts describe retained log markers; repeated reads can be intentional. Durations total recorded responses only, excluding any unfinished request.'};
}
