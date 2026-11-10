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

const {InvestigationWorkflow}=await import('../packages/security-solver/src/investigation-workflow');
for(const [extension,language,kind] of [
  ['sol','solidity','solidity_sequence'],['java','java','java_sequence'],
  ['py','python','python_sequence'],['js','javascript','javascript_sequence']
] as const){
  const source='source-1/contracts/Scenario.'+extension;
  const selector=language==='solidity'?'Scenario.update':language==='java'?'Scenario.update':'update';
  const wf=new InvestigationWorkflow();
  wf.read(source);
  const plan={action:'plan_probe',path:source,query:selector,answer:kind,
    hypothesis:'A caller may modify protected state without authorization.'};
  wf.registerControllerPlan(plan,'test-source-digest:'+source,
    'Only approved callers may modify state',
    'A disallowed caller is rejected before state mutation');
  assert.equal(wf.snapshot().scenarioLedger.scenarios[0].phase,'preparing');
  wf.plan(plan);
  assert.equal(wf.snapshot().scenarioLedger.scenarios[0].phase,'preparing');
  const verify={...plan,action:'verify_source'};
  const caseId='a'.repeat(64);
  wf.observe(verify,JSON.stringify({status:'behavior_observed',
    behavior_observed:true,caseId,observations:{steps:[{operation:'call',actual:true}]}}));
  assert.equal(wf.snapshot().scenarioLedger.scenarios[0].phase,'reviewing');
  assert.equal(wf.snapshot().scenarioLedger.scenarios[0].outcome,undefined,
    'an observed behavior must not automatically become a finding');
  wf.acceptedReview(source,selector,kind,'review:case:'+caseId,false);
  assert.equal(wf.snapshot().scenarioLedger.scenarios[0].outcome,'rejected');
}
const dependencies=new InvestigationWorkflow();
dependencies.read('source-1/contracts/Dependencies.sol');
const broken={action:'plan_probe',path:'source-1/contracts/Dependencies.sol',
  query:'Dependencies.settle',answer:'solidity_sequence',
  hypothesis:'Unprotected settlement changes accounting state'};
dependencies.registerControllerPlan(broken,'source-digest','Settlement preserves accounting',
  'Accounting remains consistent');
dependencies.plan(broken);
dependencies.observe({...broken,action:'verify_source'},JSON.stringify({
  status:'unsupported_dependencies',behavior_observed:false,
  detail:'Required pinned repository import could not be prepared'}));
const blockedScenario=dependencies.snapshot().scenarioLedger.scenarios[0];
assert.equal(blockedScenario.outcome,'unsupported');
assert.equal(blockedScenario.prerequisites.find(p=>p.id==='runtime')?.state,'blocked');
assert.equal(blockedScenario.evidence.some(e=>e.kind==='execution'),false,
  'dependency failures must not masquerade as executed security probes');

const stalled=new InvestigationWorkflow();
stalled.read('source-1/contracts/stall.sol');
const blocked={action:'plan_probe',path:'source-1/contracts/stall.sol',
  query:'Vault.withdraw',answer:'solidity_sequence',
  hypothesis:'Hypothesis with rejected authorization'};
stalled.registerControllerPlan(blocked,'source-digest','Protected withdrawal',
  'Unauthorized execution reverts');
stalled.plan(blocked);
assert.ok(stalled.abortPending('Unresolvable runtime preparation'));
assert.equal(stalled.snapshot().scenarioLedger.scenarios[0].outcome,'incomplete');
assert.equal(stalled.snapshot().observations[0].status,'controller_blocked');
assert.equal(stalled.snapshot().scenarioLedger.scenarios[0].evidence.some(e=>e.kind==='execution'),false,
  'a blocked controller must not fabricate verifier evidence');

console.log('Controller scenario lifecycle, prerequisites, recovery, evidence and review PASSED');
