import assert from 'node:assert/strict';
import {ControllerScenarioLedger} from '../packages/security-solver/src/controller-scenario-lifecycle';

const ledger=new ControllerScenarioLedger();
const input={id:'source-1/contracts/Vault.sol:Vault.deposit:solidity_sequence',
  path:'source-1/contracts/Vault.sol',selector:'Vault.deposit',
  language:'solidity' as const,property:'Only authorized accounts can withdraw',
  suspectedViolation:'Unauthorized account can withdraw',
  falsification:'Unauthorized account cannot withdraw'};
assert.equal(ledger.register(input).phase,'discovered');
assert.throws(()=>ledger.transition(input.id,'grounded','without source'),/source evidence/);
ledger.record(input.id,{id:'source',kind:'source',
  reference:'source-1/contracts/Vault.sol:10-30',observation:'Inspected role guard'});
ledger.transition(input.id,'grounded','source verified');
ledger.transition(input.id,'preparing','resolve setup');
ledger.addPrerequisite(input.id,{id:'compile',description:'Compile contract',dependsOn:[]});
ledger.addPrerequisite(input.id,{id:'deploy',description:'Deploy isolated contract',dependsOn:['compile']});
ledger.addPrerequisite(input.id,{id:'fund',description:'Fund local sender',dependsOn:['deploy']});
assert.equal(ledger.nextPrerequisite(input.id)?.id,'compile');
assert.throws(()=>ledger.satisfy(input.id,'deploy','unsupported'),/dependencies unresolved/);
assert.throws(()=>ledger.transition(input.id,'ready','premature'),/unresolved prerequisites/);
ledger.satisfy(input.id,'compile','compiler-result');
assert.equal(ledger.nextPrerequisite(input.id)?.id,'deploy');
ledger.satisfy(input.id,'deploy','deployment-receipt');
ledger.satisfy(input.id,'fund','local-test-fixture');
ledger.transition(input.id,'ready','setup complete');
ledger.transition(input.id,'executing','run verifier');
assert.throws(()=>ledger.transition(input.id,'observed','missing result'),/execution evidence/);
ledger.record(input.id,{id:'execution',kind:'execution',
  reference:'case:123',observation:'Unauthorized withdrawal observed'});
ledger.transition(input.id,'observed','isolated test executed');
ledger.transition(input.id,'reviewing','handoff');
assert.throws(()=>ledger.finish(input.id,'verified','without review'),/independent review/);
const snapshot=ledger.snapshot();
const recovered=new ControllerScenarioLedger();
recovered.restore(snapshot);
assert.deepEqual(recovered.snapshot(),snapshot,'full scenario evidence must survive compaction');
recovered.record(input.id,{id:'review',kind:'review',
  reference:'review:456',observation:'Reachability and impact independently confirmed'});
recovered.finish(input.id,'verified','validator accepted');
assert.equal(recovered.get(input.id)?.outcome,'verified');
assert.throws(()=>recovered.transition(input.id,'executing','repeat'),/Invalid controller/);
assert.throws(()=>recovered.record(input.id,{id:'review',kind:'review',
  reference:'forged',observation:'overwrite'}),/Immutable evidence conflict/);
const negative=new ControllerScenarioLedger();
negative.register({...input,id:'source-1/src/Renderer.java:Renderer.render:java_sequence',
  path:'source-1/src/Renderer.java',selector:'Renderer.render',language:'java'});
negative.finish('source-1/src/Renderer.java:Renderer.render:java_sequence',
  'unsupported','No supported runtime setup');
assert.equal(negative.get('source-1/src/Renderer.java:Renderer.render:java_sequence')?.outcome,'unsupported');
const cycle=new ControllerScenarioLedger();
cycle.register({...input,id:'source-1/src/app.py:render:python_sequence',
  path:'source-1/src/app.py',selector:'render',language:'python'});
assert.throws(()=>cycle.addPrerequisite('source-1/src/app.py:render:python_sequence',
  {id:'missing',description:'Broken dependency',dependsOn:['not-there']}),/Unknown prerequisite/);
console.log('Controller scenario lifecycle, prerequisites, recovery, evidence and review PASSED');
