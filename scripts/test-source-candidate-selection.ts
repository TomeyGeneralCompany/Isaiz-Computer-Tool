/** Candidate selection should expose runnable signatures before incompatible capsule setters. */
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {prioritizeSourceCandidates} from '../packages/security-solver/src/source-candidates';

const root=await mkdtemp(join(tmpdir(),'lotus-probe-selection-'));
try {
  const eligible:string[]=[];
  for(let i=0;i<24;i++){
    const path='source-1/src/main/java/org/example/Capsule'+String(i).padStart(2,'0')+'.java';
    eligible.push(path);
    await mkdir(join(root,'source-1/src/main/java/org/example'),{recursive:true});
    await writeFile(join(root,path),
      'public class Capsule'+i+' { public void setUrl(ByteString value) {} public ByteString getUrl() { return null; } }');
  }
  const compatible='source-1/src/main/java/org/example/ZCompatible.java';
  eligible.push(compatible);
  await writeFile(join(root,compatible),
    'public class ZCompatible { public static String normalize(String value) { return value.trim(); } }');
  const result=await prioritizeSourceCandidates(root,eligible,eligible,[]);
  assert.ok(result.paths.includes(compatible),'compatible Java function should reach the initial selection');
  assert.ok(result.paths.length<=8,'retain bounded eight-file navigation');
  const focused=await prioritizeSourceCandidates(root,eligible,eligible,[],eligible[0]);
  assert.deepEqual(focused.paths,[eligible[0]],'an imported lead must remain the only target');
  const outside=await prioritizeSourceCandidates(root,eligible,eligible,[], 'source-1/src/main/java/org/example/NotEligible.java');
  assert.deepEqual(outside.paths,[], 'out-of-scope imported lead must not enter navigation');
  console.log('Candidate signature selection regression PASSED');
}finally{await rm(root,{recursive:true,force:true});}
