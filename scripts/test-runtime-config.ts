import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,writeFileSync,mkdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
const root=mkdtempSync(join(tmpdir(),'runtime-config-'));
process.env.PROJECT_ROOT=root;
process.env.GITHUB_TOKEN='fixture';
process.env.SECURITY_SOURCE_CODE_TIMEOUT_MINUTES='150';
process.env.LOCAL_HUNT_NUM_PREDICT='4096';
try {
 mkdirSync(join(root,'data'));
 writeFileSync(join(root,'data/runtime-overrides.json'),JSON.stringify({SECURITY_HUNT_TIMEOUT_MINUTES:120}));
 const {getConfig,setRuntimeOverride}=await import('../packages/core/src/config');
 assert.equal(getConfig().SECURITY_SOURCE_CODE_TIMEOUT_MINUTES,150,'Unrelated persisted overrides must not reset environment settings');
 assert.equal(getConfig().LOCAL_HUNT_NUM_PREDICT,4096);
 assert.deepEqual(getConfig().EXCLUDE_SECURITY_PROGRAMS,[]);
 setRuntimeOverride('LOCAL_HUNT_NUM_PREDICT',2048);
 assert.equal(getConfig().LOCAL_HUNT_NUM_PREDICT,2048);
 assert.equal(getConfig().SECURITY_SOURCE_CODE_TIMEOUT_MINUTES,150);
 assert.throws(()=>setRuntimeOverride('LOCAL_HUNT_NUM_PREDICT',4097));
 console.log('Runtime overrides preserve environment settings and validate output-token limits PASSED');
} finally {rmSync(root,{recursive:true,force:true});}
