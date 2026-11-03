/** Offline fixture-contract checks: never starts Ollama or accesses a bounty target. */
import assert from 'node:assert/strict';
import {LANGUAGES,generate} from './lotus-gauntlet-fixtures';
for(const language of LANGUAGES){
 for(const count of [12,28,48,84,144]){
  const {files,answer}=generate(language,count);
  const sources=Object.keys(files).filter(file=>/\.(sol|py|cjs|java)$/.test(file));
  assert.equal(sources.length,count,'Incorrect file count for '+language+' level '+count);
  assert.ok(Object.hasOwn(files,answer.file),'Missing hidden target source');
  assert.ok(Object.hasOwn(files,answer.caller),'Missing target caller');
  assert.ok(files[answer.file].includes(answer.selector.split('.').at(-1)!),'Target method not declared');
  assert.ok(files[answer.caller].includes(answer.selector.split('.').at(-1)!) ||
    (language==='python' && files[answer.caller].includes('render(')),'Caller does not use target behavior');
  assert.ok(!files[answer.file].includes('TOMEY_PROBE'),'Fixture exposes harness marker');
  assert.deepEqual(generate(language,count),{files,answer},'Fixture generator must be deterministic');
 }
}
console.log('Four Gauntlet languages and five source sizes: fixture contract checks passed');
