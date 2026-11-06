import assert from 'node:assert/strict';
import {CRUCIBLE_REQUIREMENTS,validateCrucibleChallenge,type CrucibleChallenge,createCrucibleInvestigatorPackage} from './lotus-crucible-contract';

const file=(i:number)=>'export function step'+i+'(input:string){\n' +
  '  const n = input.length;\n  if (n < 1) return "";\n  const text = input.trim();\n' +
  '  const answer = text + n;\n  if (answer.length > 100) return text;\n' +
  '  return answer;\n}\n';
const sourcePaths=Array.from({length:2000},(_,i)=>'src/component'+i+'.js');
const files=Object.fromEntries(sourcePaths.map((p,i)=>[p,file(i)]));
const control=(id:string,i:number)=>({id,language:'javascript' as const,
  affectedPaths:[sourcePaths[i]],safetyReason:'Escaped at executable sink',
  replayExpectation:'Payload does not appear unescaped'});
const key:CrucibleChallenge['privateAnswerKey']={
  challengeId:'sealed-level6-contract-test',seed:'test-seed',language:'javascript',kind:'vulnerable',
  defects:Array.from({length:5},(_,i)=>({id:'defect-'+i,language:'javascript' as const,
    entryPath:sourcePaths[i],affectedPaths:[sourcePaths[i],sourcePaths[i+1]],
    weakness:'missing boundary check',reproduction:{kind:'synthetic',selector:'step'+i,expectedEffect:'unauthorized change'},
    requiredChains:[[sourcePaths[i],sourcePaths[i+1]]]})),
  falseLeads:Array.from({length:200},(_,i)=>control('false-'+i,i+10)),
  negativeControls:Array.from({length:50},(_,i)=>control('safe-'+i,i+250)),
};
const challenge:CrucibleChallenge={files,privateAnswerKey:key};
const verdict=validateCrucibleChallenge(challenge);
assert.equal(verdict.sourceFiles,CRUCIBLE_REQUIREMENTS.minimumSourceFiles);
assert.equal(verdict.defects,5);
assert.equal(verdict.falseLeads,200);
assert.equal(verdict.negativeControls,50);
assert.match(verdict.sourceSha256,/^[a-f0-9]{64}$/);
assert.equal(validateCrucibleChallenge(challenge).sourceSha256,verdict.sourceSha256);
const reject=(mutate:(k:CrucibleChallenge['privateAnswerKey'])=>void)=>{
  const k=structuredClone(key);mutate(k);
  assert.throws(()=>validateCrucibleChallenge({files,privateAnswerKey:k}),/Crucible/);
};
reject(k=>k.defects.pop());
reject(k=>k.falseLeads.pop());
reject(k=>k.negativeControls.pop());
reject(k=>k.defects[0].requiredChains=[[sourcePaths[0],'src/missing.js']]);
reject(k=>{k.kind='clean';});
reject(k=>{k.falseLeads[0].id=k.defects[0].id;});
const clean=structuredClone(key);
clean.kind='clean';clean.defects=[];
assert.equal(validateCrucibleChallenge({files,privateAnswerKey:clean}).defects,0);
assert.throws(()=>validateCrucibleChallenge({files:Object.fromEntries(Object.entries(files).slice(0,1999)),
 privateAnswerKey:key}),/Crucible/);
console.log('Level 6 sealed challenge contract validation PASSED (structural only; no benchmark was run)');

const visible=createCrucibleInvestigatorPackage(challenge);
assert.equal(visible.sourceSha256,verdict.sourceSha256);
assert.equal(visible.challengeId,key.challengeId);
assert.equal(visible.files[sourcePaths[0]],files[sourcePaths[0]]);
assert.notEqual(visible.files,files);
assert.equal('privateAnswerKey' in visible,false);
assert.equal('seed' in visible,false);
assert.equal('defects' in visible,false);
assert.equal(JSON.stringify(visible).includes('test-seed'),false);
assert.equal(JSON.stringify(visible).includes('defect-0'),false);
const unsafe={...files,'../outside.js':file(9000)};
assert.throws(()=>createCrucibleInvestigatorPackage({files:unsafe,privateAnswerKey:key}),/Crucible unsafe source path/);
assert.throws(()=>validateCrucibleChallenge({files:unsafe,privateAnswerKey:key}),/Crucible unsafe source path/);
