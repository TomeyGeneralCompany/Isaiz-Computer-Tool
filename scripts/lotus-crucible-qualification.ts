/** Grader-side qualification gate. This does not execute challenges or grant
 * qualification based on source-generation smoke tests. Only independently
 * adjudicated, sealed production executions can enter this ledger.
 */
import {createHash} from 'node:crypto';
import {CRUCIBLE_REQUIREMENTS} from './lotus-crucible-contract';
import type {Language} from './lotus-gauntlet-fixtures';

export type CrucibleTrialReceipt={
  trialId:string;
  language:Language;
  productionCommit:string;
  challengeDigest:string;
  sealedSeedCommitment:string;
  kind:'clean'|'vulnerable';
  generatedSourceFiles:number;
  mandatoryDefectCount:number;
  independentlyReplayedDefectIds:string[];
  reportedDefectIds:string[];
  negativeControlViolations:string[];
  falsePositiveIds:string[];
  fabricatedEvidenceIds:string[];
  firstDivergence:string|null;
  sourceExecutionPassed:boolean;
  independentReviewPassed:boolean;
  graderPassed:boolean;
  externalSubmissionEnabled:boolean;
  productionModel:string;
  cpuOnly:boolean;
  artifactUrl:string;
};
const languages:ReadonlyArray<Language>=['solidity','python','javascript','java'];
const sha=/^[a-f0-9]{40}$/i;
const digest=/^[a-f0-9]{64}$/i;
function unique(values:string[]):boolean{return new Set(values).size===values.length;}
function sameSet(a:string[],b:string[]):boolean{
  return unique(a)&&unique(b)&&a.length===b.length&&a.every(x=>b.includes(x));
}
/** Fail closed. The entire campaign, not merely the passing subset, is graded.
 * A missing language, clean control, replay, or negative-control result fails.
 * Seed commitments are hashes made in the grader's separate environment;
 * never include the underlying seeds in investigator artifacts.
 */
export function assessCrucibleQualification(receipts:readonly CrucibleTrialReceipt[]):{
  qualified:boolean; reasons:string[]; receiptDigest:string;
}{
  const reasons:string[]=[];
  if(receipts.length<CRUCIBLE_REQUIREMENTS.minimumSealedTrials)
    reasons.push('fewer than 33 sealed trials');
  const commits=receipts.map(r=>r.productionCommit);
  if(!unique(receipts.map(r=>r.trialId)))reasons.push('duplicate trial identity');
  if(!unique(receipts.map(r=>r.sealedSeedCommitment)))reasons.push('reused sealed seed');
  if(!unique(receipts.map(r=>r.challengeDigest)))reasons.push('reused challenge source');
  if(new Set(commits).size!==1||commits.some(x=>!sha.test(x)))
    reasons.push('production implementation changed or lacks valid commit');
  for(const language of languages){
    const subset=receipts.filter(r=>r.language===language);
    if(!subset.length)reasons.push('missing language '+language);
    if(!subset.some(r=>r.kind==='clean'))reasons.push('missing clean control '+language);
    if(!subset.some(r=>r.kind==='vulnerable'))reasons.push('missing vulnerable trial '+language);
  }
  for(const r of receipts){
    const bad=(why:string)=>reasons.push(r.trialId+': '+why);
    if(!r.trialId.trim()||!languages.includes(r.language))bad('invalid trial identity or language');
    if(!digest.test(r.challengeDigest)||!digest.test(r.sealedSeedCommitment))
      bad('invalid source digest or sealed commitment');
    if(r.generatedSourceFiles<CRUCIBLE_REQUIREMENTS.minimumSourceFiles||
       r.generatedSourceFiles>CRUCIBLE_REQUIREMENTS.maximumSourceFiles)
      bad('source count outside specification');
    if(r.kind==='clean'){
      if(r.mandatoryDefectCount!==0||r.reportedDefectIds.length||
         r.independentlyReplayedDefectIds.length)bad('clean trial produced findings');
    }else{
      if(r.mandatoryDefectCount<CRUCIBLE_REQUIREMENTS.minimumDefects||
         r.mandatoryDefectCount>CRUCIBLE_REQUIREMENTS.maximumDefects)
        bad('incorrect mandatory defect count');
      if(r.independentlyReplayedDefectIds.length!==r.mandatoryDefectCount||
         !sameSet(r.independentlyReplayedDefectIds,r.reportedDefectIds))
        bad('mandatory replay/report coverage mismatch');
    }
    if(r.negativeControlViolations.length||r.falsePositiveIds.length||
       r.fabricatedEvidenceIds.length)bad('control violation, false positive or fabricated evidence');
    if(r.firstDivergence!==null||!r.sourceExecutionPassed||
       !r.independentReviewPassed||!r.graderPassed)bad('execution, review or grade failed');
    if(r.externalSubmissionEnabled||r.productionModel!=='qwen3:4b'||!r.cpuOnly)
      bad('production scope or model violated');
    if(!/^https:\/\//.test(r.artifactUrl))bad('missing evidence artifact URL');
  }
  const receiptDigest=createHash('sha256').update(JSON.stringify(
    [...receipts].sort((a,b)=>a.trialId.localeCompare(b.trialId))
  )).digest('hex');
  return {qualified:reasons.length===0,reasons,receiptDigest};
}
