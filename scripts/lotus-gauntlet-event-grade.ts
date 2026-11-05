/** Grade actual controller and model actions by observed source/probe evidence,
 * not by which actor emitted them. No ground-truth path is sent to the hunt.
 */
export function gradeInvestigationEvents(log:string,answer:{file:string;selector:string}){
  const lines=log.split('\n');
  const target='source-1/'+answer.file;
  const targetMethod=answer.selector.split('.').at(-1);
  const matchingSelector=(value:unknown)=>typeof value==='string'&&value.split('.').at(-1)===targetMethod;
  const containsTarget=(s:string)=>s.includes(target);
  const lineOf=(line:string,marker:string)=>{
    const i=line.indexOf(marker);
    if(i<0)return null;
    const body=line.slice(i+marker.length).trim();
    try{return JSON.parse(body) as Record<string,unknown>;}catch{return null;}
  };
  const read=lines.some(line=>{
    const readOk=lineOf(line,'[READ_OK] ');
    if(readOk)return readOk.path===target;
    if(line.includes('[READ_OK] '))return line.includes('[READ_OK] '+target+' ');
    const prefetched=lineOf(line,'[INITIAL_SOURCE_READ] ');
    if(prefetched?.path===target)return true;
    // A proposed model action is not evidence of a completed read.
    return false;
  });
  const plan=lines.some(line=>{
    const p=lineOf(line,'[PROBE_PLANNED] ')||lineOf(line,'[CONTROLLER_SOURCE_PROBE_SELECTED] ');
    return p?.path===target && (matchingSelector(p.query)||matchingSelector(p.selector));
  });
  const attempts=lines.map(line=>lineOf(line,'[PROBE_RESULT] ')||lineOf(line,'[GUIDED_SOURCE_PROBE] ')).filter(Boolean) as Array<Record<string,unknown>>;
  const targetAttempts=attempts.filter(p=>p.path===target && matchingSelector(p.function));
  const observed=targetAttempts.some(p=>p.status==='behavior_observed');
  const anyAttempt=attempts.length>0;
  const anySuccessful=attempts.some(p=>p.status==='behavior_observed'||p.status==='behavior_not_observed'||p.status==='observation_only');
  const anyPlans=lines.some(line=>line.includes('[PROBE_PLANNED]')||line.includes('[CONTROLLER_SOURCE_PROBE_SELECTED]')||line.includes('[GUIDED_SOURCE_PROBE]'));
  return {targetRead:read,targetPlan:plan||targetAttempts.length>0,targetAttempt:targetAttempts.length>0,
    targetBehaviorObserved:observed,anyAttempt,anySuccessful,anyPlans,
    counters:{guidedProbes:lines.filter(l=>l.includes('[GUIDED_SOURCE_PROBE]')).length,
      controllerPlans:lines.filter(l=>l.includes('[CONTROLLER_SOURCE_PROBE_SELECTED]')).length,
      modelPlans:lines.filter(l=>l.includes('[PROBE_PLANNED]')).length,
      recordedProbeResults:attempts.length}};
}
