import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {readInvestigationRecords} from '../packages/dashboard/src/server/investigation-records';
const root=await mkdtemp(join(tmpdir(),'investigation-record-'));
try {
 const name='local-hunt-0123456789abcdef.log';
 await writeFile(join(root,name),'[AUDIT_PROGRAM] {"id":"owned"}\n[ALLOWANCE_EXTENDED] {"turns":120}\n');
 await writeFile(join(root,name+'.summary.json'),JSON.stringify({endedAt:new Date().toISOString(),turns:86,stoppingReason:'Validated final answer',hypotheses:[{statement:'unverified'}]}));
 await writeFile(join(root,name+'.activity.jsonl'),'[ACTIVITY] {"phase":"completed","tool":"verify_source","status":"behavior_not_observed"}\n');
 const records=await readInvestigationRecords(root,'owned');
 assert.equal(records.length,1);assert.equal(records[0].events[0].status,'behavior_not_observed');
 assert.equal(records[0].extensions[0].turns,120);
 assert.equal((await readInvestigationRecords(root,'other')).length,0);
 await symlink(join(root,name+'.summary.json'),join(root,'local-hunt-aaaaaaaaaaaaaaaa.log.summary.json'));
 assert.equal((await readInvestigationRecords(root,'owned')).length,1);
 console.log('Investigation record identity, events, extensions and symlink rejection PASSED');
}finally{await rm(root,{recursive:true,force:true});}
