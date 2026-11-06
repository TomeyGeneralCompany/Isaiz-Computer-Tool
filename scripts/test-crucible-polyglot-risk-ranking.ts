import assert from 'node:assert/strict';
import {generateCrucible} from './lotus-crucible-generator';
import {controllerSourceRiskSignal} from '../packages/security-solver/src/source-candidates';
import type {Language} from './lotus-gauntlet-fixtures';

for(const language of ['solidity','python','javascript','java'] as Language[]){
  const challenge=generateCrucible({language,seed:'crucible-risk-regression-012345'});
  const expected=new Set(challenge.privateAnswerKey.defects.flatMap(d=>d.affectedPaths.slice(-1)));
  const high=Object.entries(challenge.files)
    .filter(([path,body])=>controllerSourceRiskSignal(path,body)>=20).map(([path])=>path);
  for(const path of expected)
    assert.ok(high.includes(path),language+' missed source-derived candidate '+path);
  for(const control of challenge.privateAnswerKey.negativeControls)
    assert.ok(control.affectedPaths.every(path=>controllerSourceRiskSignal(path,challenge.files[path])<20),
      language+' promoted secured negative control '+control.id);
  for(const decoy of challenge.privateAnswerKey.falseLeads)
    assert.ok(decoy.affectedPaths.every(path=>controllerSourceRiskSignal(path,challenge.files[path])<20),
      language+' promoted false-lead decoy '+decoy.id);
  assert.equal(high.length,5,language+' source risk ranking should nominate exactly 5 independent candidates');
  console.log('Large-source polyglot risk-ranked hypotheses PASSED '+language);
}
console.log('Source risk scanner creates navigation hypotheses only; no exploit verdict or submission');
