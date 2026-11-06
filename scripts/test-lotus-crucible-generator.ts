/** Executable generator acceptance: every language, seeded reproducibility,
 * hidden oracle boundary and source/runtime checks. Does NOT claim qualification.
 */
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {createRequire} from 'node:module';
import {generateCrucible} from './lotus-crucible-generator';
import {createCrucibleInvestigatorPackage,validateCrucibleChallenge} from './lotus-crucible-contract';
import type {Language} from './lotus-gauntlet-fixtures';
const languages:Language[]=['solidity','python','javascript','java'];
const seen=new Set<string>();
for(const language of languages){
  const challenge=generateCrucible({language,seed:'crucible-acceptance-seed-01'});
  const a=validateCrucibleChallenge(challenge);
  assert.ok(a.sourceFiles>=2000 && a.sourceFiles<=5000);
  assert.equal(a.defects,5);
  assert.equal(a.falseLeads,200);
  assert.equal(a.negativeControls,50);
  const pkg=createCrucibleInvestigatorPackage(challenge);
  const str=JSON.stringify(pkg);
  assert.ok(!str.includes(challenge.privateAnswerKey.seed));
  assert.ok(!str.includes(challenge.privateAnswerKey.defects[0].id));
  assert.equal(pkg.sourceSha256,a.sourceSha256);
  assert.equal(generateCrucible({language,seed:'crucible-acceptance-seed-01'}).privateAnswerKey.challengeId,
    challenge.privateAnswerKey.challengeId);
  const alternate=generateCrucible({language,seed:'crucible-acceptance-seed-02'});
  assert.notEqual(alternate.privateAnswerKey.defects[0].affectedPaths[0],
    challenge.privateAnswerKey.defects[0].affectedPaths[0]);
  assert.ok(!seen.has(a.sourceSha256));seen.add(a.sourceSha256);
  const clean=generateCrucible({language,seed:'crucible-acceptance-clean-01',clean:true});
  assert.equal(clean.privateAnswerKey.defects.length,0);
  const paths=Object.keys(pkg.files);
  assert.ok(paths.some(p=>p.includes('gateways/')));
  if(language==='javascript'){
    const root=await mkdtemp(join(tmpdir(),'crucible-js-'));
    try{
      for(const [path,code] of Object.entries(pkg.files)){
        if(!path.endsWith('.cjs'))continue;
        await mkdir(dirname(join(root,path)),{recursive:true});
        await writeFile(join(root,path),code);
      }
      const requireAt=createRequire(join(root,'run.cjs'));
      for(let i=0;i<5;i++){
        const gateway=requireAt(join(root,'src/gateways/gateway_'+i+'.cjs'));
        const response=gateway.testVector();
        assert.ok(response.includes('<svg>'),'expected vulnerable HTML response');
      }
      for(let i=100;i<108;i++){
        const gateway=requireAt(join(root,'src/gateways/gateway_'+i+'.cjs'));
        const response=gateway.testVector();
        assert.ok(!response.includes('<svg>'),'negative-control raw HTML appeared');
        assert.ok(response.includes('&lt;svg&gt;'),'negative-control not escaped');
      }
    }finally{await rm(root,{recursive:true,force:true});}
  }
  console.log('Level 6 generated '+language+': '+a.sourceFiles+' sources; sealed cases='+
    a.defects+'; decoys='+a.falseLeads+'; safe controls='+a.negativeControls);
}
console.log('Crucible executable generator acceptance PASSED; no production hunt performed');
