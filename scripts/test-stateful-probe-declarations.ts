/** Factory methods must pass declaration validation without accepting invented plans. */
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {sourceStatefulPlans} from '../packages/security-solver/src/controller-stateful-candidates';
import {declaredProbeTarget} from '../packages/security-solver/src/probe-target-validation';
const root=await mkdtemp(join(tmpdir(),'lotus-stateful-declarations-'));
try {
  for(const [name,source] of [
    ['counter.py','class Counter:\n    def __init__(self,start=0): self.value=start\n    def advance(self,by=1):\n        self.value+=by\n        return self.value\ndef make(start=0):\n    return Counter(start)\n'],
    ['counter.cjs','exports.make=function(start){let value=start;return {advance(by){value+=by;return value;}};};']
  ]) {
    const file=join(root,name);await writeFile(file,source);
    const plan=sourceStatefulPlans(file,source)[0];assert.ok(plan,name);
    assert.equal(await declaredProbeTarget(file,plan.selector),false,'object methods do not masquerade as top-level functions');
    assert.equal(await declaredProbeTarget(file,plan.selector,plan.kind,plan.sequence),true,name+': exact source-owned factory sequence is declared');
    assert.equal(await declaredProbeTarget(file,'invented',plan.kind,plan.sequence),false);
    assert.equal(await declaredProbeTarget(file,plan.selector,plan.kind,undefined),false);
    assert.equal(await declaredProbeTarget(file,plan.selector,plan.kind,{...plan.sequence,factory:'unrelated'}),false);
    assert.equal(await declaredProbeTarget(file,plan.selector,plan.kind,{...plan.sequence,constructor:[99]}),false);
    assert.equal(await declaredProbeTarget(file,plan.selector,plan.kind,{...plan.sequence,steps:[{method:'invented',args:[]},...plan.sequence.steps]}),false);
    const other=plan.kind==='python_sequence'?'javascript_sequence':'python_sequence';
    assert.equal(await declaredProbeTarget(file,plan.selector,other,plan.sequence),false,'no cross-language admission');
  }
  const ordinary=join(root,'render.py');await writeFile(ordinary,'def render(value):\n    return value\n');
  assert.equal(await declaredProbeTarget(ordinary,'render'),true,'ordinary declaration checks remain available');
  assert.equal(await declaredProbeTarget(ordinary,'render','python_sequence',{constructor:[],steps:[]}),false,'a text function is not a stateful factory');
  console.log('Source-bound Python/JavaScript factory plan admission and forged-plan rejection PASSED');
} finally {await rm(root,{recursive:true,force:true});}
