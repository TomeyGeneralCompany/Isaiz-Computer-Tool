/** Tracks tangible log/source-processing activity, not elapsed wall-clock time.
 * A one-bounty run is bounded by program count; timeouts apply only to inactivity.
 */
export interface BountyProgress {
  lastActivityAt:number;
  logPath:string|null;
  logBytes:number;
  stage:string;
}

const ACTION_EVENT_RE=/^\[(?:ACQUISITION_[A-Z0-9_]+|CAPABILITY_[A-Z0-9_]+|STATIC_LEADS|SOURCE_MAP|INDEX_COMPLETE|STAGE_UNLOCK|STAGE_READ_CURSOR|STAGE_TERMINAL|INDEXED_[A-Z0-9_]+|READ_COMPLETE|ANALYSIS_COMPLETE|STAGED_EXPERIMENT_RESULT|EXPERIMENT_COMPLETE|REVIEW_COMPLETE|REPORT_COMPLETE|MODEL_START|MODEL_ACTION|CONTROLLER_[A-Z0-9_]+|ACTION|READ_OK|GUIDED_SOURCE_PROBE|PROBE_[A-Z0-9_]+|EVIDENCE_ONLY_REVIEW_[A-Z0-9_]+|ACTION_REJECTED|WORKFLOW_REJECTED|STAGE_ACTION_REJECTED|FINAL_[A-Z0-9_]+|REPEATED_READ_BLOCKED|STAGE_CONTROLLER_NO_PROGRESS|AUDIT_NO_PROGRESS_TERMINATED|INITIAL_SOURCE_[A-Z0-9_]+|ALLOWANCE_EXTENDED|TOOL)\]/;
const HEARTBEAT_FALLBACK_RE=/^\[(?:OLLAMA|MODEL_PROGRESS)\]/;

function sanitizeTelemetryLine(line:string,maxLength=240):string {
  return line
    .replace(/github_pat_[A-Za-z0-9_]+/g,'github_pat_[REDACTED]')
    .replace(/ghp_[A-Za-z0-9]+/g,'ghp_[REDACTED]')
    .replace(/(Bearer\s+)[A-Za-z0-9._-]+/gi,'$1[REDACTED]')
    .replace(/\s+/g,' ')
    .trim()
    .slice(0,maxLength);
}

export function isLiveTelemetryLine(line:string):boolean {
  const trimmed=line.trimStart();
  return ACTION_EVENT_RE.test(trimmed)||HEARTBEAT_FALLBACK_RE.test(trimmed);
}

export function pickLatestProgressEvent(text:string):string {
  const lines=text.split(/\r?\n/).map(line=>line.trimStart()).filter(Boolean);
  for(let i=lines.length-1;i>=0;i--) {
    if(ACTION_EVENT_RE.test(lines[i]))return sanitizeTelemetryLine(lines[i],220);
  }
  for(let i=lines.length-1;i>=0;i--) {
    if(HEARTBEAT_FALLBACK_RE.test(lines[i]))return sanitizeTelemetryLine(lines[i],220);
  }
  return '';
}

export interface TelemetryChunkResult {
  lines:string[];
  remainder:string;
  omitted:number;
}

export function consumeTelemetryChunk(
  pendingRemainder:string,
  chunk:string,
  options?:{maxLines?:number}
):TelemetryChunkResult {
  const combined=pendingRemainder+chunk;
  const endsWithNewline=/\r?\n$/.test(combined);
  const parts=combined.split(/\r?\n/);
  const remainder=endsWithNewline?'':(parts.pop()??'');
  const rawMatches:string[]=[];
  for(const raw of parts) {
    const trimmed=raw.trimStart();
    if(!isLiveTelemetryLine(trimmed))continue;
    rawMatches.push(sanitizeTelemetryLine(trimmed,240));
  }
  // Collapse repeated streaming [MODEL_PROGRESS] ticks when multiple arrive together
  // or when the turn already produced a completion / concrete action in the same slice.
  const compacted:string[]=[];
  for(let i=0;i<rawMatches.length;i++) {
    const line=rawMatches[i];
    if(line.startsWith('[MODEL_PROGRESS]')) {
      const next=rawMatches[i+1];
      if(next&&(next.startsWith('[MODEL_PROGRESS]')||next.startsWith('[OLLAMA]')||ACTION_EVENT_RE.test(next))) {
        continue;
      }
    }
    compacted.push(line);
  }
  const maxLines=Math.max(1,options?.maxLines??12);
  if(compacted.length<=maxLines) {
    return {lines:compacted,remainder,omitted:0};
  }
  return {
    lines:compacted.slice(-maxLines),
    remainder,
    omitted:compacted.length-maxLines
  };
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
  if(Number.isFinite(observation.logBytes)&&(observation.logBytes ?? -1)>=0&&next.logPath){
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
