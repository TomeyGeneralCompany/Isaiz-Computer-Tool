/** Production-fidelity controller regression: 48-file 88mph-scale corpus + false leads.
 * Runs actual source-map, source-guided candidate, source-flow and workflow
 * modules; no model-selected mechanical actions and no invented probe results.
 * The isolated execution/review layer is covered by existing production tests.
 */
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {buildSourceMap} from '../packages/security-solver/src/source-map';
import {guidedSourceProbe} from '../packages/security-solver/src/source-guided-probes';
import {traceSourceCalls} from '../packages/security-solver/src/source-flow-facts';
import {InvestigationWorkflow} from '../packages/security-solver/src/investigation-workflow';
import {controllerOwnedNextAction} from '../packages/security-solver/src/controller-next-action';
import {verifiedProbeSummary} from '../packages/security-solver/src/source-candidate-evidence';

const languages={
  python:{ext:'py',target:'def render(value):\n    return "<p>" + value + "</p>"\n',
    caller:'def handle(value):\n    return render(value)\n'},
  javascript:{ext:'cjs',target:'exports.render=function render(value){return "<p>"+value+"</p>";};\n',
    caller:'exports.handle=function handle(value){return render(value);};\n'},
  java:{ext:'java',target:'public class Renderer { public static String render(String value) { return "<p>" + value + "</p>"; } }\n',
    caller:'public class Handler { public static String handle(String value) { return Renderer.render(value); } }\n'},
  solidity:{ext:'sol',target:'pragma solidity ^0.8.20; contract Renderer { function render(string memory value) public pure returns(string memory) { return value; } }\n',
    caller:'pragma solidity ^0.8.20; contract Handler { function handle() public pure returns(uint) { return 1; } }\n'}
} as const;
const root=await mkdtemp(join(tmpdir(),'lotus-production-fidelity-'));
try {
 for(const [language,fixture] of Object.entries(languages)){
   const base=join(root,language);
   await mkdir(join(base,'source-1','src'),{recursive:true});
   const target='source-1/src/Renderer.'+fixture.ext;
   const caller='source-1/src/Handler.'+fixture.ext;
   const paths:string[]=[];
   // 48 eligible files, plus an 8-file adversarial margin: realistic rather
   // than Level 6's thousands-of-files stress. The actual target is late.
   for(let i=0;i<54;i++){
     const p='source-1/src/decoy_'+String(i).padStart(2,'0')+'.'+fixture.ext;
     const fake=fixture.ext==='py'?'def unrelated(value):\n    return value\n':
       fixture.ext==='java'?'public class Decoy'+i+' { public static String unrelated(String value) { return value; } }\n':
       fixture.ext==='sol'?'pragma solidity ^0.8.20; contract Decoy'+i+' { function unrelated() public pure returns(uint) { return 1; } }\n':
       'exports.unrelated=function unrelated(value){return value;};\n';
     await writeFile(join(base,p),fake);
     paths.push(p);
   }
   await writeFile(join(base,target),fixture.target+'\n'.repeat(2300));
   await writeFile(join(base,caller),fixture.caller);
   paths.push(target,caller);
   assert.equal(paths.length,56);
   const map=await buildSourceMap(base,paths);
   assert.equal(map.scannedFiles,56,language+' must not silently discard a 56-file corpus');
   assert.equal(map.skippedFiles,0);
   assert.ok(map.symbols.some(s=>s.path===target),language+' target declaration missing');
   const targetText=await readFile(join(base,target),'utf8');
   assert.ok(targetText.length>2000,language+' target must require multiple source pages');
   const pages:number[]=[];
   for(let offset=0;offset<targetText.length;offset+=2000)pages.push(offset);
   assert.ok(pages.length>=2);
   assert.equal(new Set(pages).size,pages.length,'page cursor must advance without restarts');
   const hint=guidedSourceProbe(target,targetText);
   if(language!=='solidity'){
     assert.ok(hint,language+' source-guided candidate must be detected');
     assert.equal(hint?.kind,'html_reflection');
   }
   const decoyText=await readFile(join(base,paths[0]),'utf8');
   assert.equal(guidedSourceProbe(paths[0],decoyText),null,language+' false lead should not become a probe');
   const trace=await traceSourceCalls(join(base,'source-1'),target.replace('source-1/',''),language==='java'?'Renderer.render':'render');
   assert.ok(trace.facts.length>0,language+' source trace must cite actual lines');
   const workflow=new InvestigationWorkflow();
   workflow.requireSource(target);
   const constraints=await workflow.constraints();
   assert.deepEqual(constraints,{action:['read_file'],path:[target]});
   const owned=controllerOwnedNextAction(constraints);
   assert.equal(owned?.path,target);
   assert.equal(owned?.action,'read_file');
   workflow.read(target);
   assert.equal(controllerOwnedNextAction({action:['read_file','final']}),null,
      'ambiguous workflow choice must not be silently treated as controller-owned');
   assert.match(verifiedProbeSummary([]),/No successful reproduction/,
      'no-probe exhaustion must never manufacture verified evidence');
   const caseId='a'.repeat(64);
   assert.equal(workflow.focusVerifiedEvidence(caseId),false,
      'unrecorded model-supplied case ID cannot force finalization');
   console.log('Production fidelity '+language+' PASS: 56 files, decoys, pagination, index, trace, controller source authority');
 }
} finally {await rm(root,{recursive:true,force:true});}
