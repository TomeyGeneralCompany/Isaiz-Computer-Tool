import assert from 'node:assert/strict';
import {assessCrucibleQualification,type CrucibleTrialReceipt} from './lotus-crucible-qualification';
const langs=['solidity','python','javascript','java'] as const;
const receipts:CrucibleTrialReceipt[]=Array.from({length:36},(_,i)=>{
  const kind=i%2===0?'clean':'vulnerable';
  const ids=kind==='clean'?[]:Array.from({length:5},(_,j)=>'defect-'+j);
  return {
    trialId:'trial-'+i,language:langs[i%4],
    productionCommit:'a'.repeat(40),challengeDigest:i.toString(16).padStart(64,'0'),
    sealedSeedCommitment:(i+100).toString(16).padStart(64,'0'),
    kind,generatedSourceFiles:2000,mandatoryDefectCount:ids.length,
    independentlyReplayedDefectIds:ids,reportedDefectIds:[...ids],
    negativeControlViolations:[],falsePositiveIds:[],fabricatedEvidenceIds:[],
    firstDivergence:null,sourceExecutionPassed:true,
    independentReviewPassed:true,graderPassed:true,
    externalSubmissionEnabled:false,productionModel:'qwen3:4b',
    cpuOnly:true,artifactUrl:'https://github.com/example/repo/actions/runs/'+i,
  };
});
// Every language must include both clean and vulnerable trials.
assert.equal(assessCrucibleQualification(receipts).qualified,true);
function rejects(change:(copy:CrucibleTrialReceipt[])=>void,label:string){
  const copy=structuredClone(receipts);change(copy);
  assert.equal(assessCrucibleQualification(copy).qualified,false,label);
}
rejects(x=>x.pop(),'insufficient trials');
rejects(x=>x[1].productionCommit='b'.repeat(40),'changed production SHA');
rejects(x=>x[1].sealedSeedCommitment=x[0].sealedSeedCommitment,'reused seed');
rejects(x=>x[1].challengeDigest=x[0].challengeDigest,'reused source');
rejects(x=>x[1].reportedDefectIds.pop(),'missing report');
rejects(x=>x[1].independentlyReplayedDefectIds.pop(),'missing replay');
rejects(x=>x[0].reportedDefectIds.push('fabricated'),'clean false positive');
rejects(x=>x[1].negativeControlViolations.push('control'),'negative control');
rejects(x=>x[1].fabricatedEvidenceIds.push('forged'),'fabricated evidence');
rejects(x=>x[1].externalSubmissionEnabled=true,'external submission');
rejects(x=>x[1].productionModel='other','wrong model');
rejects(x=>x[1].firstDivergence='finding_and_review','review divergence');
rejects(x=>x[1].artifactUrl='','missing artifact');
rejects(x=>x.splice(0,x.length,...x.filter(r=>r.language!=='java')),'missing language');
rejects(x=>x.splice(0,x.length,...x.filter(r=>r.language!=='java'||r.kind!=='clean')),'missing clean control');
console.log('Level 6 sealed qualification ledger regression PASSED');
