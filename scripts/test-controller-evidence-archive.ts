import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {ControllerEvidenceArchive,retrieveArchivedAuditExchange} from '../packages/security-solver/src/controller-evidence-archive';
const root=await mkdtemp(join(tmpdir(),'lotus-tiered-memory-'));
try {
 const path=join(root,'archive.jsonl');
 const exchange={role:'user',content:'SOURCE evidence for Solidity, Java, JavaScript, Python'};
 const sha256=createHash('sha256').update(JSON.stringify(exchange)).digest('hex');
 await writeFile(path,JSON.stringify({version:1,sha256,exchange})+'\n');
 assert.deepEqual(await retrieveArchivedAuditExchange(path,sha256),exchange);
 assert.equal(await retrieveArchivedAuditExchange(path,'0'.repeat(64)),null);
 await assert.rejects(()=>retrieveArchivedAuditExchange(path,'invalid'),/Invalid archive digest/);
 await writeFile(path,JSON.stringify({version:1,sha256,exchange:{role:'user',content:'tampered'}})+'\n');
 await assert.rejects(()=>retrieveArchivedAuditExchange(path,sha256),/integrity mismatch/);
 const evidencePath=join(root,'evidence.jsonl');
 const archive=new ControllerEvidenceArchive(evidencePath);
 const id=await archive.append('probe',{language:'Solidity',result:{behavior_observed:true}},
   {source:'contracts/Example.sol',caseId:'case-1'});
 assert.equal(await archive.append('probe',{language:'Solidity',result:{behavior_observed:true}},
   {source:'contracts/Example.sol',caseId:'case-1'}),id);
 assert.equal((await archive.forCase('case-1')).length,1);
 assert.equal((await archive.forSource('contracts/Example.sol')).length,1);
 assert.deepEqual((await archive.retrieve(id))?.payload,{language:'Solidity',result:{behavior_observed:true}});
 assert.equal((await new ControllerEvidenceArchive(evidencePath).retrieve(id))?.id,id);
 await assert.rejects(()=>archive.append('route',{entry:'entry'}, {parentIds:['0'.repeat(64)]}),/Missing controller evidence parent/);
 const route=await archive.append('route',{entry:'entry',sink:'sink'},{caseId:'case-1',parentIds:[id]});
 assert.deepEqual((await archive.retrieve(route))?.parentIds,[id]);
 const excerpts=await archive.retrieveRelevant({caseId:'case-1',maxRecords:1,maxCharacters:256});
 assert.equal(excerpts.length,1);
 assert.equal(excerpts[0].id,route);
 assert.ok(excerpts[0].excerpt.length<=256);
 assert.equal((await archive.retrieve(route))?.kind,'route');
 for(const [language,extension] of [['Java','java'],['JavaScript','js'],['Python','py'],['Solidity','sol']] as const) {
   const source='source-'+language.toLowerCase()+'.'+extension;
   const sourceId=await archive.append('source',{path:source,start:0,end:21,content:'function vulnerable(){}'},{source});
   const probeId=await archive.append('probe',{language,sourceId,behavior_observed:true},{source,caseId:'case-'+language,parentIds:[sourceId]});
   const packetId=await archive.append('review',{language,sourceId,probeId,decision:'pending'},
     {caseId:'case-'+language,parentIds:[sourceId,probeId]});
   const restored=new ControllerEvidenceArchive(evidencePath);
   assert.equal((await restored.retrieve(packetId))?.kind,'review');
   assert.deepEqual((await restored.forCase('case-'+language)).map(x=>x?.id),[probeId,packetId]);
   assert.equal((await restored.forSource(source)).length,2);
 }
 const saved=await import('node:fs/promises').then(fs=>fs.readFile(evidencePath,'utf8'));
 await writeFile(evidencePath,saved.replace('behavior_observed', 'behavior_fabricated'));
 await assert.rejects(()=>new ControllerEvidenceArchive(evidencePath).load(),/integrity mismatch/);
 console.log('Controller indexed evidence archival, retrieval, parent references and tamper detection PASSED');
} finally {await rm(root,{recursive:true,force:true});}
