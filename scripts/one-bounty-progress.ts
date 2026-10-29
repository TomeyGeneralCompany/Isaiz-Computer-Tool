/** Tracks tangible log/source-processing activity, not elapsed wall-clock time.
 * A one-bounty run is bounded by program count; timeouts apply only to inactivity.
 */
export interface BountyProgress {
  lastActivityAt:number;
  logPath:string|null;
  logBytes:number;
  stage:string;
}
export function advanceBountyProgress(previous:BountyProgress,now:number,
  observation:{logPath?:string|null;logBytes?:number;stage?:string}):BountyProgress {
  let changed=false;
  const next={...previous};
  if(typeof observation.logPath==='string'&&observation.logPath!==previous.logPath){
    next.logPath=observation.logPath;
    next.logBytes=0;
    changed=true;
  }
  if(Number.isFinite(observation.logBytes)&&observation.logBytes!>=0&&next.logPath){
    const bytes=observation.logBytes!;
    if(bytes!==next.logBytes){
      // A log can be rotated/replaced, both are observable activity.
      changed=true;next.logBytes=bytes;
    }
  }
  if(observation.stage&&observation.stage!==previous.stage){
    next.stage=observation.stage;
    changed=true;
  }
  if(changed)next.lastActivityAt=now;
  return next;
}
export function idleBountyExpired(state:BountyProgress,now:number,idleMinutes:number):boolean {
  return now-state.lastActivityAt>=idleMinutes*60_000;
}
