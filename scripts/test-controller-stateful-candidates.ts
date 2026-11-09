import assert from 'node:assert/strict';
import {sourceStatefulPlans} from '../packages/security-solver/src/controller-stateful-candidates';

const js='exports.make = function(start) {let value=start; return {\n'+
  ' advance(by) {value += by; return value;}\n};};\n';
const py='class Counter:\n'+
  '    def __init__(self,start=0): self.value=start\n'+
  '    def advance(self,by=1):\n'+
  '        self.value+=by\n'+
  '        return self.value\n'+
  'def make(start=0):\n'+
  '    return Counter(start)\n';
const j=sourceStatefulPlans('src/counter.cjs',js);
assert.equal(j.length,1,'source-grounded JS stateful factory must be discovered');
assert.equal(j[0].selector,'advance');
assert.equal(j[0].sequence.factory,'make');
assert.equal(j[0].sequence.steps.length,2);
const p=sourceStatefulPlans('src/counter.py',py);
assert.equal(p.length,1,'source-grounded Python stateful factory must be discovered');
assert.equal(p[0].selector,'advance');
assert.equal(p[0].sequence.factory,'make');
assert.equal(p[0].sequence.steps.length,2);
assert.deepEqual(sourceStatefulPlans('src/plain.py','def render(x):\n    return x\n'),[],
  'no fabricated stateful factory on a plain isolated function');
assert.deepEqual(sourceStatefulPlans('src/decoy.cjs',
  'exports.make = function(x) {return x;};\nexports.advance=function(v){return v;};\n'),[],
  'unrelated exports must not imply the returned object has a method');
const multipleJs='exports.make=function(start){let value=start;return {\n'+
  ' advance(by){value+=by;return value;},\n'+
  ' retreat(by){value-=by;return value;}\n};};\n';
const multiplePy='class Counter:\n'+
  '    def advance(self,by=1):\n        return by\n'+
  '    def retreat(self,by=1):\n        return -by\n'+
  'def make(start=0):\n    return Counter(start)\n';
assert.deepEqual(sourceStatefulPlans('src/counter.cjs',multipleJs).map(p=>p.selector),
  ['advance','retreat'],'JS controller must not hide second executable method');
assert.deepEqual(sourceStatefulPlans('src/counter.py',multiplePy).map(p=>p.selector),
  ['advance','retreat'],'Python controller must not hide second executable method');

console.log('Source-grounded Python JavaScript stateful controller plans PASSED');
