import assert from 'node:assert/strict';
import {controllerPolyglotPlan,canonicalControllerPolyglotIntent} from '../packages/security-solver/src/controller-polyglot-plan';

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
assert.deepEqual((javaPlan?.sequence as any).steps.map((s:any)=>s.method),['current','advance','current'],
  'controller observes an independent getter before and after mutation');
assert.deepEqual(controllerPolyglotPlan('src/Counter.java',javaState,
 {query:'Counter.current',answer:'java_sequence'})?.sequence,
 {constructor:[],steps:[{method:'current',args:[]},{method:'current',args:[]}]});
assert.equal(controllerPolyglotPlan('src/Counter.java',javaState,
 {query:'Counter.invented',answer:'java_sequence'}),null);
const typedJava='public class Ledger {\n'+
 ' public Ledger(int initial) { this.balance=initial; }\n'+
 ' public int update(int delta) { balance+=delta; return balance; }\n'+
 ' public int current() { return balance; }\n'+
 ' private int balance;\n'+
 '}';
const typed=controllerPolyglotPlan('src/Ledger.java',typedJava);
assert.equal(typed?.query,'Ledger.update');
assert.deepEqual((typed?.sequence as any).constructor,[1],
  'controller owns source-derived Java constructor inputs');
assert.deepEqual((typed?.sequence as any).steps,[
 {method:'current',args:[]},{method:'update',args:[1]},{method:'current',args:[]}],
 'no model is required to guess Java method values or before/after reads');
assert.deepEqual(controllerPolyglotPlan('src/Ledger.java',typedJava,{
 query:'Ledger.update',answer:'java_sequence'})?.sequence,typed?.sequence);
const unsupported='public class Dangerous {public void mutate(CustomThing arg) {} }';
assert.equal(controllerPolyglotPlan('src/Dangerous.java',unsupported),null,
 'unsupported Java types must not be guessed');
const overloaded='public class Overloaded { public int change(int n){return n;} '+
 'public int change(boolean b){return 0;} }';
assert.equal(controllerPolyglotPlan('src/Overloaded.java',overloaded),null,
 'overloaded Java methods require disambiguation, never guessed input data');
for(const [path,code,selector,kind] of [
 ['src/Counter.java',javaState,'Counter.advance','java_sequence'],
 ['src/count.py',pyState,'advance','python_sequence'],
 ['src/count.cjs',jsState,'advance','javascript_sequence'],
] as const){
  const original=controllerPolyglotPlan(path,code);
  const corrected=canonicalControllerPolyglotIntent(path,code,{
    query:selector,answer:'unsupported_model_kind'});
  assert.equal(corrected?.answer,kind,'controller fixes model-invented kind '+path);
  assert.deepEqual(corrected?.sequence,original?.sequence,
    'controller restores source-executable typed arguments regardless of Qwen');
  assert.equal(canonicalControllerPolyglotIntent(path,code,{
    query:'inventedMethod',answer:kind}),null,
    'model-invented selectors are never substituted for a different method');
}
assert.equal(canonicalControllerPolyglotIntent('src/Renderer.java',javaHtml,
 {query:'render',answer:'solidity_sequence'})?.query,'Renderer.render',
 'unambiguous unqualified Java method is source-canonicalized');
assert.equal(controllerPolyglotPlan('src/unrelated.ts','export function x() {}'),null);
console.log('Source-derived Java/Python/JavaScript controller plans PASSED');
