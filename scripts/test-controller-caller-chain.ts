import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import {tmpdir} from 'node:os';
import {generate} from './lotus-gauntlet-fixtures';
import {controllerCallerChain,sourceImportsTarget} from '../packages/security-solver/src/source-flow-facts';
import {callerLineReferences} from '../packages/security-solver/src/source-function-reference';

const cases=[
 {lang:'javascript' as const,target:'src/pipeline.cjs',selector:'wrapFragment',
  callers:['src/renderer.cjs','src/http-handler.cjs']},
 {lang:'python' as const,target:'src/pipeline.py',selector:'wrap_fragment',
  callers:['src/renderer.py','src/http_handler.py']},
 {lang:'java' as const,target:'src/main/java/org/lotus/Pipeline.java',
  selector:'Pipeline.wrapFragment',callers:[
   'src/main/java/org/lotus/Renderer.java','src/main/java/org/lotus/HttpHandler.java']}
];
const pythonImport='from src.pipeline import wrap_fragment\ndef render(value):\n    return wrap_fragment(value)';
assert.equal(callerLineReferences(pythonImport,1,'wrap_fragment'),false,
 'Import statements are declarations, not multiline calls');
assert.equal(callerLineReferences(pythonImport,3,'wrap_fragment'),true);
assert.equal(sourceImportsTarget('source-1/src/modules/decoy.cjs',
  'source-1/src/renderer.cjs','exports.inspect=function inspect(x){return render(x)}'),false);
for(const test of cases){
 const root=await mkdtemp(join(tmpdir(),'lotus-upstream-chain-'));
 try{
  const files=generate(test.lang,144).files;
  const paths=Object.keys(files).map(p=>'source-1/'+p);
  for(const [path,source] of Object.entries(files)){
   const full=join(root,'source-1',path);
   await mkdir(dirname(full),{recursive:true});
   await writeFile(full,source);
  }
  // A caller placed beyond the first 256 eligible files must remain discoverable.
  // No private vulnerability answers or filename shortcuts participate.
  const extension=test.lang==='python'?'.py':test.lang==='java'?'.java':'.cjs';
  const decoys=Array.from({length:300},(_,i)=>
    'source-1/src/extra/Unrelated'+String(i).padStart(4,'0')+extension);
  for(const path of decoys){
    const full=join(root,path);await mkdir(dirname(full),{recursive:true});
    await writeFile(full,test.lang==='python'?'def unrelated(value): return value\\n':
      test.lang==='java'?'class Unrelated {}\\n':'exports.unrelated=(value)=>value;\\n');
  }
  const chain=await controllerCallerChain(root,'source-1/','source-1/'+test.target,
    test.selector,[...decoys,...paths],4);
  assert.deepEqual(chain.map(x=>x.path),test.callers.map(p=>'source-1/'+p),
   test.lang+' caller search must ignore 140 same-named decoys and follow imports');
  assert.ok(chain.every(x=>x.line>0&&x.code.includes('(')));
 }finally{await rm(root,{recursive:true,force:true});}
}
console.log('Import-resolved JavaScript, Python and Java multi-hop caller evidence PASSED');
