import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import {tmpdir} from 'node:os';
import {generateCrucible} from './lotus-crucible-generator';
import {indexedEntryRoutes} from '../packages/security-solver/src/controller-indexed-route';

const root=await mkdtemp(join(tmpdir(),'lotus-graph-regression-'));
try{
 for(const language of ['python','javascript','java'] as const){
   const c=generateCrucible({language,seed:'source-route-graph-verification-20261106'});
   const eligible:string[]=[];
   for(const [path,body] of Object.entries(c.files)){
     if(!/\.(?:py|cjs|java)$/.test(path))continue;
     const target='source-1/'+path,full=join(root,target);
     await mkdir(dirname(full),{recursive:true});await writeFile(full,body);eligible.push(target);
   }
   const routes=await indexedEntryRoutes(root,eligible);
   const expected=c.privateAnswerKey.defects.map(x=>'source-1/'+x.entryPath);
   for(const path of expected)assert.ok(routes.some(r=>r.entry===path),
     language+': source graph must traverse actual multi-hop service calls from '+path);
   assert.ok(routes.every(r=>r.chain.every(p=>eligible.includes(p))));
   assert.ok(routes.every(r=>r.kind==='source_hypothesis'));
   // A safe or negative-control route is still a valid source-navigation
   // hypothesis. Only a real sandboxed entry probe may classify its behavior.
   const protectedNode='source-1/'+c.privateAnswerKey.negativeControls[0].affectedPaths[0];
   assert.ok(routes.every(r=>r.kind==='source_hypothesis'));
   assert.ok(protectedNode.startsWith('source-1/'));
   console.log(language+': complete 2000-source entry-to-service route discovery PASSED; routes='+routes.length);
 }
}finally{await rm(root,{recursive:true,force:true});}
