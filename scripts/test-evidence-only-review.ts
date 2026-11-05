import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runEvidenceOnlyReview} from '../packages/security-solver/src/evidence-only-review';

const dir=await mkdtemp(join(tmpdir(),'lotus-evidence-only-'));
try {
  const logFile=join(dir,'review.log');
  const schema={type:'object',properties:{verdict:{type:'string',enum:['approve','reject']},
    recommendation:{type:'string',enum:['submit','dont_submit']},
    reasoning:{type:'string'}},required:['verdict','recommendation','reasoning']};
  const packets:Array<Record<string,unknown>>=[];
  let calls=0;
  const negative={verdict:'reject',recommendation:'dont_submit',
    reasoning:'The independently replayed input is escaped at the actual output sink.'};
  const value=await runEvidenceOnlyReview({
    prompt:'Reviewer packet includes source, caller and isolated replay; determine security significance.',
    schema,model:'mock',signal:new AbortController().signal,
    logFile,numCtx:8192,numPredict:800,
    validate:answer=>{
      const data=JSON.parse(answer);
      return data.verdict==='reject'&&data.reasoning.includes('escaped')?null:
        'Reject only if an actual mitigation or missing reachability is identified.';
    },
    transport:async(payload)=>{
      packets.push(payload);calls++;
      return {message:{content:calls===1?
        JSON.stringify({action:'final',answer:'No source read'}) : JSON.stringify(negative)}};
    }
  });
  assert.deepEqual(JSON.parse(value),negative);
  assert.equal(calls,2,'One targeted correction, not an action/read loop');
  assert.equal(packets[0].format,schema,'Real verdict schema, not the generic audit action schema');
  assert.equal(packets[0].tools,undefined,'The reviewer has no source-navigation tools');
  assert.equal(packets[0].think,false,'Qwen3 must generate verdict content rather than spending output budget in thinking');
  assert.equal((packets[0].messages as Array<unknown>).length,2);
  assert.equal((packets[1].messages as Array<unknown>).length,4);
  const log=await readFile(logFile,'utf8');
  assert.match(log,/EVIDENCE_ONLY_REVIEW_CORRECTED/);
  assert.match(log,/EVIDENCE_ONLY_REVIEW_ACCEPTED/);
  let failed=false;
  try{
    await runEvidenceOnlyReview({prompt:'Evidence ready',schema,model:'mock',
      signal:new AbortController().signal,logFile,numCtx:8192,numPredict:800,maxAttempts:2,
      validate:()=> 'Invalid evidence conclusion',
      transport:async()=>({message:{content:JSON.stringify(negative)}})
    });
  }catch(error){failed=/after 2 attempts/.test(String(error));}
  assert.ok(failed,'Persistent bad review must fail with a bounded explicit reason');
  // Repeated schema-valid but technically invalid policy verdicts must get a
  // stronger, non-self-reinforcing correction, never an automatic approval.
  const badPolicy=JSON.stringify({verdict:'reject',recommendation:'dont_submit',
    reasoning:'Submission prohibited by benchmark policy; reject on that basis.'});
  const goodTechnical=JSON.stringify({verdict:'approve',recommendation:'dont_submit',
    reasoning:'The independent source evidence establishes a security issue; no submission is allowed.'});
  const escalationPayloads:Array<Record<string,unknown>>=[];
  let policyCalls=0;
  const policyReview=await runEvidenceOnlyReview({
    prompt:'Technical review of a recorded, replayed source case. External reporting disabled.',
    schema,model:'mock',signal:new AbortController().signal,logFile,numCtx:8192,numPredict:800,
    validate:answer=>JSON.parse(answer).reasoning.startsWith('Submission prohibited')?
      'An external submission prohibition is not a technical defect. Reevaluate source and replay; use recommendation=dont_submit if submission is prohibited.':null,
    transport:async payload=>{
      escalationPayloads.push(payload);
      policyCalls++;
      return {message:{content:policyCalls<3?badPolicy:goodTechnical}};
    }
  });
  assert.equal(JSON.parse(policyReview).verdict,'approve',
    'only an independently accepted technical verdict can exit reviewer');
  assert.equal(policyCalls,3);
  const secondMessages=escalationPayloads[1].messages as Array<{role:string;content:string}>;
  assert.ok(secondMessages.some(x=>x.role==='system'&&x.content.includes('SUBMITTED')),
    'a policy-only reject receives targeted technical-review instructions');
  const thirdOptions=escalationPayloads[2].options as {temperature:number};
  assert.ok(thirdOptions.temperature>0,'identical invalid verdicts must change retry strategy');
  assert.equal((escalationPayloads[2].messages as Array<unknown>).length,4,
    'review retry must replace stale rejected verdicts rather than accumulate them');
  console.log('Evidence-only reviewer: schema, no navigation, bounded corrections PASSED');
}finally{await rm(dir,{recursive:true,force:true});}
