import assert from 'node:assert/strict';
import {InvestigationWorkflow} from '../packages/security-solver/src/investigation-workflow';
import {controllerOwnedNextAction} from '../packages/security-solver/src/controller-next-action';

const flow=new InvestigationWorkflow();
flow.read('source-1/src/services/first.py');
flow.requireSource('source-1/src/services/first.py');
let c=await flow.constraints();
assert.equal(controllerOwnedNextAction(c,flow.snapshot().pending),null);
flow.requireSource('source-1/src/services/second.py');
c=await flow.constraints();
assert.equal(controllerOwnedNextAction(c,flow.snapshot().pending)?.path,'source-1/src/services/second.py');
flow.read('source-1/src/services/second.py');
c=await flow.constraints();
assert.equal(controllerOwnedNextAction(c,flow.snapshot().pending),null);
flow.requireSource('source-1/src/services/second.py');
c=await flow.constraints();
assert.equal(controllerOwnedNextAction(c,flow.snapshot().pending),null);
console.log('Completed-source handoff remains resolved PASSED');
