import assert from 'node:assert/strict';
import {controllerPolyglotPlan} from '../packages/security-solver/src/controller-polyglot-plan';

const pythonHtml='def render(value):\n    return "<p>"+value+"</p>"\n';
const javaHtml='public class Renderer {public String render(String value) {return "<p>"+value+"</p>";}}';
const javascriptHtml='exports.render=function(value){return "<p>"+value+"</p>";};';
for(const [path,code,query] of [
  ['src/renderer.py',pythonHtml,'render'],
  ['src/Renderer.java',javaHtml,'Renderer.render'],
  ['src/renderer.cjs',javascriptHtml,'render']
] as const) {
  const p=controllerPolyglotPlan(path,code);
  assert.equal(p?.answer,'html_reflection',path);
  assert.equal(p?.query,query,path);
  assert.equal(controllerPolyglotPlan(path,code,{query:'made_up',answer:'html_reflection'}),null,
    'controller never substitutes an unrelated selector for an invented model request');
}
const pyState='class Counter:\n    def __init__(self,start=0): self.value=start\n'+
 '    def advance(self,by=1):\n        self.value+=by\n        return self.value\n'+
 'def make(start=0):\n    return Counter(start)\n';
const jsState='exports.make = function(start) {let value=start; return {\n'+
 ' advance(by) {value += by; return value;}\n};};\n';
for(const [path,code,kind] of [
 ['src/count.py',pyState,'python_sequence'],
 ['src/count.cjs',jsState,'javascript_sequence']
] as const) {
  const proposal=controllerPolyglotPlan(path,code);
  assert.equal(proposal?.answer,kind);
  assert.equal(proposal?.query,'advance');
  assert.equal((proposal?.sequence as any).steps.length,2);
  assert.deepEqual(controllerPolyglotPlan(path,code,{query:'advance',answer:kind})?.sequence,proposal?.sequence,
    'same source and requested method must have identical controller-owned executable steps');
  assert.equal(controllerPolyglotPlan(path,code,{query:'invented',answer:kind}),null);
}
const javaState='public class Counter { private int value = 0; '+
 'public int advance() {return ++value;} public int current() {return value;} }';
const javaPlan=controllerPolyglotPlan('src/Counter.java',javaState);
assert.equal(javaPlan?.answer,'java_sequence');
assert.equal(javaPlan?.query,'Counter.advance');
assert.equal((javaPlan?.sequence as any).steps.length,2);
assert.deepEqual(controllerPolyglotPlan('src/Counter.java',javaState,
 {query:'Counter.current',answer:'java_sequence'})?.sequence,
 {constructor:[],steps:[{method:'current',args:[]},{method:'current',args:[]}]});
assert.equal(controllerPolyglotPlan('src/Counter.java',javaState,
 {query:'Counter.invented',answer:'java_sequence'}),null);
assert.equal(controllerPolyglotPlan('src/unrelated.ts','export function x() {}'),null);
console.log('Source-derived Java/Python/JavaScript controller plans PASSED');
