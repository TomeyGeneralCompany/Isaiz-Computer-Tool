import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm,symlink} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {prioritizeSourceCandidates} from '../packages/security-solver/src/source-candidates';
import {AuditNavigation} from '../packages/security-solver/src/audit-navigation';
const root=await mkdtemp(join(tmpdir(),'candidate-selection-'));
try {
  const paths=Array.from({length:200},(_,i)=>`file-${i}.py`);
  const source='# Unicode: 🦁\n'+'# unrelated\n'.repeat(100)+'def candidate(value):\n    return value\n';
  await Promise.all(paths.map(path=>writeFile(join(root,path),source)));
  const result=await prioritizeSourceCandidates(root,paths,paths.slice(0,8),[
    {path:paths[199],line:102,rule:'upstream-rule',message:'Inspect input handling'},
    {path:'../outside.py',line:1},{path:paths[198],line:-1}]);
  assert.equal(result.paths[0],paths[199],'A match beyond the old 128-file map must be first');
  assert.equal(result.paths.length,8);
  assert.equal(result.locations[0].line,99);
  assert.equal(source.slice(0,result.locations[0].offset).split('\n').length,99);
  assert(!result.paths.includes('../outside.py'));
  const nav=new AuditNavigation();nav.seed(result.paths,result.locations);
  assert.equal(nav.snapshot().next[0].offset,result.locations[0].offset);
  nav.observe('read_file',paths[199],result.locations[0].offset,'',{nextOffset:result.locations[0].offset+156});
  assert.equal(nav.snapshot().next.find(item=>item.path===paths[199])?.offset,result.locations[0].offset+156,'Chunk continuation remains active');
  const fallback=await prioritizeSourceCandidates(root,paths,paths.slice(8,16),[]);
  assert.deepEqual(fallback.paths,paths.slice(8,16));
  const focused=await prioritizeSourceCandidates(root,paths,[],[{path:paths[199],line:102}],paths[5]);
  assert.equal(focused.paths[0],paths[5]);
  await symlink('/etc/passwd',join(root,'outside.py'));
  assert.equal((await prioritizeSourceCandidates(root,['outside.py'],['outside.py'],[])).paths.length,0);
  console.log('Candidate prioritization, bounded offsets, scope boundaries and chunk continuation PASSED');
} finally {await rm(root,{recursive:true,force:true});}
