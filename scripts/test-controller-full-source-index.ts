import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,symlink,rm} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {buildControllerSourceIndex,controllerEvidencePacket} from '../packages/security-solver/src/controller-source-index';

const root=await mkdtemp(join(tmpdir(),'lotus-full-source-index-'));
try {
  const paths:string[]=[];
  for(let i=0;i<300;i++){
    const path='source-1/src/services/service_'+String(i).padStart(4,'0')+'.py';
    const body=i===297
      ? 'def project(value: str) -> str:\n    return "<p data-route=\\\"main\\\">" + value + "</p>"\n'
      : 'from html import escape\ndef project(value: str) -> str:\n    return "<p>" + escape(value) + "</p>"\n';
    const full=join(root,path);await mkdir(dirname(full),{recursive:true});
    await writeFile(full,body);paths.push(path);
  }
  const jsPath='source-1/src/gateway.cjs';
  await writeFile(join(root,jsPath),'module.exports={responseBody};\nfunction responseBody(value){return "<p>"+value+"</p>";}\n');
  paths.push(jsPath);
  const solPath='source-1/contracts/Vault.sol';
  await mkdir(dirname(join(root,solPath)),{recursive:true});
  await writeFile(join(root,solPath),'contract Vault { address public operator; function rotateOperator(address next) public { operator=next; }}');
  paths.push(solPath);
  await symlink('/etc/passwd',join(root,'source-1/outside.py'));
  paths.push('source-1/outside.py');
  const index=await buildControllerSourceIndex(root,paths);
  assert.equal(index.eligibleFiles,303);
  assert.equal(index.indexedFiles,302);
  assert.equal(index.complete,false,'Out-of-scope symlink must prevent complete coverage');
  assert.ok(index.skipped.some(x=>x.path==='source-1/outside.py'));
  assert.ok(index.rankedPaths.slice(0,8).includes('source-1/src/services/service_0297.py'),
    'Actual source far beyond the old 192-file window must receive controller priority');
  assert.ok(index.rankedPaths.slice(0,8).includes(solPath));
  const entry=index.files.find(x=>x.path==='source-1/src/services/service_0297.py')!;
  assert.equal(entry.sha256,createHash('sha256').update(await readFile(join(root,entry.path))).digest('hex'));
  const packet=controllerEvidencePacket(index,5);
  assert.equal(packet.candidates.length,5);
  assert.ok(JSON.stringify(packet).length<9000,'Model context must contain only bounded facts');
  assert.ok(!('files' in packet),'Do not send full inventory to Qwen');
  console.log('Controller full source inventory indexes 300+ sources, ranks late risks, validates paths, hashes and bounds model packets PASSED');
}finally{await rm(root,{recursive:true,force:true});}
