/**
 * One authorized bounty program, once. Uses the real hunt and independent
 * review functions, not a second engine or a background dispatch loop.
 * The per-run report records observed results, including failures.
 */
import 'dotenv/config';
import {mkdirSync, writeFileSync, readdirSync, statSync, readFileSync, openSync, readSync, closeSync} from 'node:fs';
import {advanceBountyProgress,idleBountyExpired,type BountyProgress} from './one-bounty-progress';
import {join, resolve} from 'node:path';
import {eq} from 'drizzle-orm';
import {ensureOneBountyLocalModel} from './one-bounty-settings';

type Args={list:boolean; program?:string; timeoutMin:number; help:boolean};
export function parseOneBountyArgs(argv:string[]):Args {
  const args:Args={list:false,timeoutMin:35,help:false};
  for(let i=0;i<argv.length;i++) {
    const v=argv[i];
    if(v==='--list')args.list=true;
    else if(v==='--help'||v==='-h')args.help=true;
    else if(v==='--program'||v==='--timeout-min') {
      const next=argv[++i];
      if(!next||next.startsWith('--'))throw new Error('Missing value for '+v);
      if(v==='--program')args.program=next;
      else {
        args.timeoutMin=Number(next);
        if(!Number.isSafeInteger(args.timeoutMin)||args.timeoutMin<5||args.timeoutMin>120)
          throw new Error('--timeout-min must be an integer from 5 to 120');
      }
    } else throw new Error('Unknown option: '+v);
  }
  if(args.list&&args.program)throw new Error('Use --list or --program, not both');
  return args;
}
const usage=`Usage:
  bash scripts/run-one-bounty.sh --list
  bash scripts/run-one-bounty.sh [--program ID_OR_HANDLE] [--timeout-min 35]

Runs exactly one already-assessed, eligible program and its normal review.
The time limit applies to INACTIVITY, not to total time while work continues.
No automatic bounty submission. No program discovery, scheduler or loop.
The result is saved in data/one-bounty/ for inspection.`;

/** Prefer a recent, successfully checked runnable-source repository over an untested program. */
function confirmedSourceCapability(summary:string|null):number {
  try {
    const tracking=JSON.parse(summary||'{}');
    const evidence=tracking.sourceCapabilities;
    if(evidence?.scopes!==JSON.stringify(tracking.scopes||[]))return 0;
    const checks=Object.values(evidence.checks||{}) as Array<{blocked?:boolean;checkedAt?:number}>;
    return checks.some(c=>c.blocked===false && Number.isFinite(c.checkedAt) && Date.now()-(c.checkedAt as number)<24*3600000)?1:0;
  }catch{return 0;}
}
async function main() {
  const options=parseOneBountyArgs(process.argv.slice(2));
  if(options.help){console.log(usage);return;}
  const root=resolve(process.cwd());
  process.env.PROJECT_ROOT=root;
  // This opt-out is process-local; never alter the operator's saved settings.
  process.env.AUTOHACK_SINGLE_BOUNTY_DIAGNOSTIC='1';
  // Match the configured application's Qwen3 default when .env omits the optional name.
  ensureOneBountyLocalModel(process.env);
  const {getDb,schema}=await import('../packages/core/src/index');
  const {rankEligiblePrograms,huntProgram,processAdversarialQueue,getProgramSelectionSummary}=await import('../packages/security-solver/src/index');
  const {requestLocalJobCancellation}=await import('../packages/security-solver/src/local-job');
  const ranked=rankEligiblePrograms();
  if(options.list){
    if(!ranked.length)console.log('No currently eligible, assessed programs. Selection: '+JSON.stringify(getProgramSelectionSummary()));
    else for(const {program,difficulty} of ranked.slice(0,30))
      console.log([program.id,program.provider,program.providerProgramId||'',program.name,'difficulty='+difficulty].join(' | '));
    return;
  }
  const matches=options.program?ranked.filter(x=>[x.program.id,x.program.providerProgramId||'',x.program.name]
    .some(s=>s.toLowerCase()===options.program!.toLowerCase())): [...ranked].sort((a,b)=>confirmedSourceCapability(b.program.scopeSummary)-confirmedSourceCapability(a.program.scopeSummary)).slice(0,1);
  if(matches.length!==1)throw new Error(options.program?
    'No unique eligible program matches '+options.program+'. Run --list and choose one listed ID.':
    'No eligible, assessed programs available. Run --list to inspect the selection result.');
  const program=matches[0].program;
  const db=getDb();
  const id=new Date().toISOString().replace(/[:.]/g,'-');
  const directory=join(root,'data','one-bounty');
  mkdirSync(directory,{recursive:true,mode:0o700});
  const summaryPath=join(directory,id+'.json');
  const startedAt=Date.now();
  let timedOut=false;
  let cancelled=false;
  const summary:any={version:1,runId:id,program:{id:program.id,provider:program.provider,
    name:program.name,handle:program.providerProgramId},startedAt:new Date(startedAt).toISOString(),
    idleTimeoutMinutes:options.timeoutMin,timeoutPolicy:'no productive log or stage activity',automaticSubmission:false,status:'started'};
  const save=()=>writeFileSync(summaryPath,JSON.stringify(summary,null,2)+'\n',{mode:0o600});
  save();
  const onSignal=()=>{cancelled=true;console.error('Cancellation requested. Stopping the active local hunt.');requestLocalJobCancellation();};
  process.on('SIGINT',onSignal);
  process.on('SIGTERM',onSignal);
  // Logs from the real controller include source acquisition, scanner progress,
  // streaming Ollama tokens, source reads and verification results. Never kill
  // a run merely because it has been active for 35 minutes.
  let progress:BountyProgress={lastActivityAt:startedAt,logPath:null,logBytes:0,stage:'starting'};
  let lastProgressDisplay=startedAt;
  let lastProgressNote='';
  const observe=()=>{
    if(timedOut||cancelled)return;
    const now=Date.now();
    let stage=progress.stage;
    try {
      const status=JSON.parse(readFileSync(join(root,'data','security-solver-status.json'),'utf8'));
      if(status.active&&status.programId===program.id)stage=String(status.stage||'hunting');
    }catch {}
    let file=progress.logPath;
    if(stage==='reviewing'&&file?.includes('/local-hunt-'))file=null;
    let bytes:number|undefined;
    try {
      const logs=join(root,'data','logs');
      if(!file) {
        let newest=startedAt-1000;
        for(const name of readdirSync(logs)) {
          if(!(stage==='reviewing'?/^local-review-[^/]+\.log$/:/^local-hunt-[a-f0-9]+\.log$/).test(name))continue;
          const path=join(logs,name);
          const stamp=statSync(path).mtimeMs;
          if(stamp>newest){file=path;newest=stamp;}
        }
      }
      if(file)bytes=statSync(file).size;
    }catch {}
    const prior=progress;
    progress=advanceBountyProgress(progress,now,{logPath:file,logBytes:bytes,stage});
    // Keep the useful current step visible, without echoing untrusted source.
    let note='';
    if(progress.logPath&&progress.logBytes!==prior.logBytes){
      try {
        const fd=openSync(progress.logPath,'r');
        let text:string;
        try {
          const length=Math.min(5000,statSync(progress.logPath).size);
          const buffer=Buffer.alloc(length);
          readSync(fd,buffer,0,length,Math.max(0,progress.logBytes-length));
          text=buffer.toString('utf8');
        } finally {closeSync(fd);}
        const events=text.split('\n').filter(line=>/^\[(?:ACQUISITION_[A-Z_]+|CAPABILITY_[A-Z_]+|STATIC_LEADS|SOURCE_MAP|MODEL_START|MODEL_PROGRESS|OLLAMA|READ_OK|GUIDED_SOURCE_PROBE|PROBE_[A-Z_]+|FINAL_[A-Z_]+|TOOL)/.test(line));
        const last=events.at(-1)||'';
        note=last.slice(0,220);
      }catch {}
    }
    if(note)lastProgressNote=note;
    if(now-lastProgressDisplay>=15000 || (prior.stage!==progress.stage)){
      const elapsed=Math.floor((now-startedAt)/60000);
      const quiet=Math.floor((now-progress.lastActivityAt)/1000);
      console.log('[one-bounty] elapsed='+elapsed+'m stage='+progress.stage+
        ' idle='+quiet+'s '+(lastProgressNote?'event='+lastProgressNote:'waiting for stage telemetry'));
      lastProgressDisplay=now;
    }
    if(idleBountyExpired(progress,now,options.timeoutMin)){
      timedOut=true;
      console.error('One-bounty investigation stalled: no new source/model/probe activity for '+
        options.timeoutMin+' minutes. Cancelling; see '+(progress.logPath||summaryPath));
      requestLocalJobCancellation();
    }
  };
  const watcher=setInterval(observe,5000);
  console.log('Single-bounty investigation: '+program.name+' ('+program.id+')');
  console.log('Review enabled; automatic submission disabled. Inactivity watchdog: '+options.timeoutMin+' minutes. No fixed run deadline.');
  console.log('Summary: '+summaryPath);
  try {
    const outcome=await huntProgram(program,'manual');
    summary.findingsCreated=outcome.findingsCreated;
    if(timedOut||cancelled)throw new Error('Run cancelled before review could start');
    console.log('Hunt completed: '+outcome.findingsCreated+' new candidate finding(s). Starting independent review.');
    progress={...progress,stage:'reviewing',lastActivityAt:Date.now(),logPath:null,logBytes:0};
    await processAdversarialQueue(program.id);
    summary.status=timedOut?'timed_out':cancelled?'cancelled':'completed';
    console.log('Independent review finished.');
  }catch(error) {
    summary.status=timedOut?'timed_out':cancelled?'cancelled':'failed';
    summary.error=String(error instanceof Error?error.message:error).slice(0,1000);
    throw error;
  }finally {
    clearInterval(watcher);
    process.off('SIGINT',onSignal);process.off('SIGTERM',onSignal);
    summary.finishedAt=new Date().toISOString();
    summary.elapsedSeconds=Math.round((Date.now()-startedAt)/1000);
    summary.lastActivityAt=new Date(progress.lastActivityAt).toISOString();
    summary.lastHuntLog=progress.logPath?progress.logPath.slice(root.length+1):null;
    summary.lastStage=progress.stage;
    summary.coverage=(()=>{try{return JSON.parse(db.select().from(schema.securityPrograms)
      .where(eq(schema.securityPrograms.id,program.id)).get()?.scopeSummary||'{}').huntCoverage||null;}catch{return null;}})();
    summary.findings=db.select().from(schema.securityFindings).where(eq(schema.securityFindings.programId,program.id)).all()
      .filter(f=>f.discoveredAt.getTime()>=startedAt-1000)
      .map(f=>({id:f.id,title:f.title,severity:f.severity,status:f.status,
        reportRecorded:!!f.reportBody,reportUrl:f.reportUrl||null}));
    save();
    console.log('One-bounty result: '+summary.status+'; '+summary.findings.length+' new records. See '+summaryPath);
  }
}
main().catch(error=>{console.error('One-bounty run failed: '+String(error));process.exitCode=1;});
