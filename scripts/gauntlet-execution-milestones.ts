/** Grade observed controller + model execution, not who requested an action.
 * Only successful tool results count as source reads; a planned probe is not a
 * completed verifier observation. The hidden answer key is never model input.
 */
export function gauntletExecutionMilestones(log:string,target:{file:string;selector:string}) {
  const events=log.split('\n');
  const recorded=(marker:string)=>events.flatMap(line=>{
    const at=line.indexOf(marker);
    if(at<0)return [];
    try {return [JSON.parse(line.slice(at+marker.length).trim())];}catch{return [];}
  }) as Array<Record<string,unknown>>;
  const reads=[
    ...recorded('[INITIAL_SOURCE_READ]'),
    ...recorded('[READ_OK_JSON]'),
  ];
  // [READ_OK] uses a compact human-readable syntax, rather than JSON.
  const sourceReadLines=events.filter(line=>
    line.includes('[READ_OK]') || line.includes('[INITIAL_SOURCE_READ]'));
  const sourceRead=sourceReadLines.length>0;
  const readTarget=sourceReadLines.some(line=>line.includes(target.file));
  const plans=[...recorded('[PROBE_PLANNED]')];
  const guided=recorded('[GUIDED_SOURCE_PROBE]');
  const results=recorded('[PROBE_RESULT]');
  const attempts=[...guided,...results];
  const selected=(entry:Record<string,unknown>)=>String(entry.query||entry.function||'')===target.selector ||
    String(entry.query||entry.function||'').split('.').at(-1)===target.selector.split('.').at(-1) &&
    String(entry.path||'').includes(target.file);
  const completedStatuses=new Set(['behavior_observed','behavior_not_observed','observation_only']);
  const completed=attempts.filter(entry=>completedStatuses.has(String(entry.status||'')));
  const targetAttempted=attempts.some(selected);
  const targetCompleted=completed.some(selected);
  return {
    sourceRead,
    relevantCandidateInspected:readTarget,
    hypothesisExamined:targetCompleted,
    probePlanned:plans.length>0 || guided.length>0,
    probeExecuted:attempts.length>0,
    probeCompleted:completed.length>0,
    targetProbeAttempted:targetAttempted,
    targetProbeCompleted:targetCompleted,
    counters:{guided:guided.length,planned:plans.length,attempted:attempts.length,
      completed:completed.length,failed:attempts.length-completed.length}
  };
}
