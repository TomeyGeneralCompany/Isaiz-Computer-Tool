/** Four-language controller progression regression: exact source edges,
 * observed intermediate behaviors, independently replayed entry, no invented
 * intermediate case and no auto-approval.
 */
import assert from 'node:assert/strict';
import {controllerEnclosingSelector,promoteControllerCallChain} from '../packages/security-solver/src/controller-investigation-chain';

const examples=[
 {ext:'.cjs',method:'render',inner:'exports.render=function render(value){return value;};',caller:'exports.wrapFragment=function wrapFragment(value){return render(value);};',entry:'exports.responseBody=function responseBody(value){return wrapFragment(value);};'},
 {ext:'.py',method:'render',inner:'def render(value):\n    return value',caller:'def wrapFragment(value):\n    return render(value)',entry:'def responseBody(value):\n    return wrapFragment(value)'},
 {ext:'.java',method:'Renderer.render',inner:'public class Renderer {\n public static String render(String value){return value;}\n}',caller:'public class Pipeline {\n public static String wrapFragment(String value){return Renderer.render(value);}\n}',entry:'public class HttpHandler {\n public static String responseBody(String value){return Pipeline.wrapFragment(value);}\n}'}
];
for(const ex of examples){
 const entryName='http-handler'+ex.ext,callerName='pipeline'+ex.ext;
 const src=new Map([[callerName,ex.caller],[entryName,ex.entry]]);
 const callerLine=ex.caller.split('\n').findIndex(x=>x.includes('render(value)'))+1;
 const entryLine=ex.entry.split('\n').findIndex(x=>x.includes('wrapFragment(value)'))+1;
 const chain=[
  {path:callerName,line:callerLine,selector:ex.method,code:ex.caller.split('\n')[callerLine-1]},
  {path:entryName,line:entryLine,selector:ex.ext==='.java'?'Pipeline.wrapFragment':'wrapFragment',code:ex.entry.split('\n')[entryLine-1]}
 ];
 const events:string[]=[];
 const result=await promoteControllerCallChain({
  start:{path:'renderer'+ex.ext,selector:ex.method,kind:'html_reflection',caseId:'initial'},
  chain,read:async path=>src.get(path)!,
  references:(source,line,selector)=>source.split('\n')[line-1].includes(selector.split('.').at(-1)!+'('),
  supported:async()=>true,
  probe:async(path,selector,kind)=>{events.push(path+':'+kind);return {status:'behavior_observed',caseId:path+'-case'};}
 });
 assert.equal(result.stopped,'verified_entry_replayed');
 assert.equal(result.promoted.path,callerName);
 assert.equal(result.entry?.path,entryName);
 assert.equal(result.caller?.line,entryLine);
 assert.equal(result.history.length,3);
 assert.deepEqual(events,[callerName+':html_reflection',entryName+':entry_html_reflection']);
 const rejected=await promoteControllerCallChain({
  start:{path:'renderer'+ex.ext,selector:ex.method,kind:'html_reflection',caseId:'initial'},
  chain,read:async path=>src.get(path)!,
  references:(source,line,selector)=>source.split('\n')[line-1].includes(selector.split('.').at(-1)!+'('),
  supported:async()=>true,
  probe:async(path)=>({status:path===callerName?'behavior_not_observed':'behavior_observed',caseId:'fake'})
 });
 assert.equal(rejected.stopped,'reproduction_not_observed');
 assert.equal(rejected.entry,undefined,'must never claim entry on unobserved intermediate');
}
assert.equal(controllerEnclosingSelector('src/web/route.cjs',
 'exports.responseBody=function responseBody(url){\n return render(url);\n};',2),'responseBody');
assert.equal(controllerEnclosingSelector('x.java',
 'public class Handler {\n public String responseBody(String value){\n return Renderer.render(value);\n }\n}',3),'x.responseBody');
console.log('Polyglot controller call-chain progression PASSED');
