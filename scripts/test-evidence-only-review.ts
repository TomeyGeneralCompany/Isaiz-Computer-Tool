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
  console.log('Evidence-only reviewer: schema, no navigation, bounded corrections PASSED');
}finally{await rm(dir,{recursive:true,force:true});}
