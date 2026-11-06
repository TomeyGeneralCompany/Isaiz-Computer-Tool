/** Level 6 grader-side independent replay adjudication.
 * This consumes observations from an isolated replay runner, not model prose.
 * It never executes a target, creates evidence, or promotes an unobserved effect.
 * Keep sealed answer keys outside the production investigator process.
 */
import {createHash} from 'node:crypto';
import type {CrucibleAnswerKey} from './lotus-crucible-contract';

export type CrucibleReplayObservation={
  caseId:string;
  sourceSha256:string;
  entryPath:string;
  chainPaths:string[];
  probeKind:string;
  selector:string;
  effect:string;
  executionId:string;
  independentlyReplayed:boolean;
  authorizedScope:boolean;
};
export type CrucibleReplayVerdict={
  qualified:boolean;
  matchedDefects:string[];
  missingDefects:string[];
  unprovenDefects:string[];
  unexpectedClaims:string[];
  negativeControlViolations:string[];
  replayDigest:string;
};
const unique=(xs:string[])=>new Set(xs).size===xs.length;
const nonempty=(s:string)=>typeof s==='string'&&s.trim().length>0;
/** A strict, complete challenge-level verdict: ALL mandatory defects require
 * independent runtime evidence; clean trials must make zero claims.
 * Matching a key's selector or expected text alone is never enough.
 */
export function adjudicateCrucibleReplay(input:{
  key:CrucibleAnswerKey;
  sourceSha256:string;
  claims:CrucibleReplayObservation[];
  independentObservations:CrucibleReplayObservation[];
}):CrucibleReplayVerdict {
  const {key,sourceSha256,claims,independentObservations:replays}=input;
  if(!/^[a-f0-9]{64}$/.test(sourceSha256))throw new Error('Crucible invalid source digest');
  if(!unique(key.defects.map(d=>d.id))||!unique(claims.map(c=>c.caseId))||
     !unique(replays.map(c=>c.executionId)))
    throw new Error('Crucible ambiguous duplicate evidence identity');
  const negativePaths=new Set(key.negativeControls.flatMap(c=>c.affectedPaths));
  const negativeControlViolations:string[]=[];
  const unexpectedClaims:string[]=[];
  const matchedDefects:string[]=[];
  const missingDefects:string[]=[];
  const unprovenDefects:string[]=[];
  const known=new Map(key.defects.map(d=>[d.id,d]));
  const replayById=new Map(replays.map(r=>[r.caseId,r]));
  const exact=(a:CrucibleReplayObservation,b:CrucibleReplayObservation)=>
    a.sourceSha256===b.sourceSha256&&a.entryPath===b.entryPath&&
    JSON.stringify(a.chainPaths)===JSON.stringify(b.chainPaths)&&
    a.probeKind===b.probeKind&&a.selector===b.selector&&a.effect===b.effect;
  for(const claim of claims){
    const d=known.get(claim.caseId);
    if(!d){unexpectedClaims.push(claim.caseId);continue;}
    if(claim.chainPaths.some(p=>negativePaths.has(p))){
      negativeControlViolations.push(claim.caseId);continue;
    }
    const replay=replayById.get(claim.caseId);
    const chainValid=d.requiredChains.some(chain=>
      JSON.stringify(chain)===JSON.stringify(claim.chainPaths));
    const grounded=!!replay&&exact(claim,replay)&&
      claim.sourceSha256===sourceSha256&&
      claim.entryPath===d.entryPath&&chainValid&&
      claim.probeKind===d.reproduction.kind&&
      claim.selector===d.reproduction.selector&&
      claim.effect===d.reproduction.expectedEffect&&
      replay.independentlyReplayed===true&&replay.authorizedScope===true&&
      nonempty(replay.executionId)&&nonempty(claim.executionId)&&
      replay.executionId!==claim.executionId;
    if(grounded)matchedDefects.push(d.id);
    else unprovenDefects.push(d.id);
  }
  for(const d of key.defects)if(!claims.some(c=>c.caseId===d.id))
    missingDefects.push(d.id);
  const qualified=unexpectedClaims.length===0&&negativeControlViolations.length===0&&
    unprovenDefects.length===0&&missingDefects.length===0&&
    (key.kind==='clean'?claims.length===0:matchedDefects.length===key.defects.length);
  const digest=createHash('sha256').update(JSON.stringify({
    sourceSha256,claims,replays,qualified
  })).digest('hex');
  return {qualified,matchedDefects,missingDefects,unprovenDefects,
    unexpectedClaims,negativeControlViolations,replayDigest:digest};
}
