/**
 * One authorized bounty program, once. Uses the real hunt and independent
 * review functions, not a second engine or a background dispatch loop.
 * The per-run report records observed results, including failures.
 */
import 'dotenv/config';
import {mkdirSync, writeFileSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {eq} from 'drizzle-orm';

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
No automatic bounty submission. No program discovery, scheduler or loop.
The result is saved in data/one-bounty/ for inspection.`;

async function main() {
  const options=parseOneBountyArgs(process.argv.slice(2));
  if(options.help){console.log(usage);return;}
  const root=resolve(process.cwd());
  process.env.PROJECT_ROOT=root;
  // This opt-out is process-local; never alter the operator's saved settings.
  process.env.AUTOHACK_SINGLE_BOUNTY_DIAGNOSTIC='1';
  const {getDb,schema}=await import('../packages/core/src/index');
  const {rankEligiblePrograms,huntProgram,processAdversarialQueue,getProgramSelectionSummary}=await import('../packages/security-solver/src/index');
  const {requestLocalJobCancellation}=await import('../packages/security-solver/src/local-job');
  if(!process.env.LOCAL_OLLAMA_MODEL?.trim())
    throw new Error('LOCAL_OLLAMA_MODEL is missing. This command requires the configured local Ollama engine.');
  const ranked=rankEligiblePrograms();
  if(options.list){
    if(!ranked.length)console.log('No currently eligible, assessed programs. Selection: '+JSON.stringify(getProgramSelectionSummary()));
    else for(const {program,difficulty} of ranked.slice(0,30))
      console.log([program.id,program.provider,program.providerProgramId||'',program.name,'difficulty='+difficulty].join(' | '));
    return;
  }
  const matches=options.program?ranked.filter(x=>[x.program.id,x.program.providerProgramId||'',x.program.name]
    .some(s=>s.toLowerCase()===options.program!.toLowerCase())):ranked.slice(0,1);
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
    timeoutMinutes:options.timeoutMin,automaticSubmission:false,status:'started'};
  const save=()=>writeFileSync(summaryPath,JSON.stringify(summary,null,2)+'\n',{mode:0o600});
  save();
  const onSignal=()=>{cancelled=true;console.error('Cancellation requested. Stopping the active local hunt.');requestLocalJobCancellation();};
  process.on('SIGINT',onSignal);
  process.on('SIGTERM',onSignal);
  const timer=setTimeout(()=>{timedOut=true;console.error('One-bounty time limit reached; cancelling the active hunt.');requestLocalJobCancellation();},options.timeoutMin*60000);
  console.log('Single-bounty investigation: '+program.name+' ('+program.id+')');
  console.log('Review enabled; automatic submission disabled. Time cap: '+options.timeoutMin+' minutes.');
  console.log('Summary: '+summaryPath);
  try {
    const outcome=await huntProgram(program,'manual');
    summary.findingsCreated=outcome.findingsCreated;
    if(timedOut||cancelled)throw new Error('Run cancelled before review could start');
    console.log('Hunt completed: '+outcome.findingsCreated+' new candidate finding(s). Starting independent review.');
    await processAdversarialQueue(program.id);
    summary.status=timedOut?'timed_out':cancelled?'cancelled':'completed';
    console.log('Independent review finished.');
  }catch(error) {
    summary.status=timedOut?'timed_out':cancelled?'cancelled':'failed';
    summary.error=String(error instanceof Error?error.message:error).slice(0,1000);
    throw error;
  }finally {
    clearTimeout(timer);
    process.off('SIGINT',onSignal);process.off('SIGTERM',onSignal);
    summary.finishedAt=new Date().toISOString();
    summary.elapsedSeconds=Math.round((Date.now()-startedAt)/1000);
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
