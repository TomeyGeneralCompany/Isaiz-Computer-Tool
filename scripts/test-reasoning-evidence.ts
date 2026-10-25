import assert from 'node:assert/strict';
import {validateReasoningEvidence as validate, type ReasoningProbe} from './reasoning-evidence';
const paths=['a.py','b.py'];
const answer=(raw=false)=>JSON.stringify({files:paths.map(path=>({path,rawMarkup:raw,reason:'Based on observed output.'}))});
const probe=(path:string):ReasoningProbe=>({path,fn:'selected',kind:'html_reflection',status:'behavior_not_observed',observed:false});
assert.match(validate(answer(),paths,[])!,/no completed markup observation/);
for(const status of ['unsupported','error','timeout'])assert.match(validate(answer(),paths,[{...probe('a.py'),status}])!,/no completed/);
assert.match(validate(answer(),paths,[{...probe('a.py'),kind:'path_construction'}])!,/no completed/);
assert.match(validate(answer(),paths,[{...probe('a.py'),observed:true}])!,/no completed/);
assert.match(validate(answer(),paths,[probe('a.py')])!,/b.py/);
assert.match(validate(answer(true),paths,paths.map(probe))!,/contradicts/);
assert.equal(validate(answer(),paths,paths.map(probe)),null);
assert.match(validate('{',paths,[])!,/JSON/);
assert.match(validate('null',paths,[])!,/files array/);
assert.match(validate(JSON.stringify({files:[{path:'a.py'},{path:'a.py'}]}),paths,[])!,/exactly one/);
// Observed behavior, not a hard-coded safe/unsafe answer, controls acceptance.
assert.equal(validate(answer(true),paths,paths.map(path=>({...probe(path),status:'behavior_observed',observed:true}))),null);
assert.match(validate(answer(),paths,[...paths.map(probe),{...probe('a.py'),status:'behavior_observed',observed:true}])!,/contradicts/);
console.log('Reasoning evidence validation passed');
