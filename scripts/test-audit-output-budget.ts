import assert from 'node:assert/strict';
import {allocateAuditContext,fitAuditToolOutput,compactAuditContext} from '../packages/security-solver/src/audit-context';
const pinned=[{role:'system',content:'Instructions'},{role:'user',content:'Inspect source'}];
const request={role:'assistant',content:'Read source'};
for(const structured of [true,false]) {
 const text='"\\\n\t\u0000'.repeat(3000);
 let offset=0,delivered='';
 while(offset<text.length) {
  const page={start:offset,end:text.length,totalCharacters:text.length,nextOffset:null,text:text.slice(offset)};
  const result=fitAuditToolOutput(pinned,request,'read_file',JSON.stringify(page),1000,structured);
  const actual=JSON.parse(result.output);
  assert.ok(actual.end>offset);
  assert.equal(actual.text,text.slice(offset,actual.end));
  assert.equal(actual.nextOffset,actual.end<text.length?actual.end:null);
  assert.ok(JSON.stringify([...pinned,request,result.message]).length<=1000);
  assert.doesNotThrow(()=>compactAuditContext([...pinned,request,result.message],1000));
  delivered+=actual.text;offset=actual.end;
 }
 assert.equal(delivered,text,'No gaps or dropped source across shortened pages');
 const probe=fitAuditToolOutput(pinned,request,'verify_source',JSON.stringify({caseId:'a'.repeat(64),status:'behavior_observed',behavior_observed:true,observations:text}),1000,structured);
 assert.equal(JSON.parse(probe.output).caseId,'a'.repeat(64));
 assert.equal(JSON.parse(probe.output).truncated,true);
 assert.ok(JSON.stringify([...pinned,request,probe.message]).length<=1000);
 const indexed=fitAuditToolOutput(pinned,request,'read_solidity',JSON.stringify({excerpts:[{text}]}),1000,structured);
 assert.match(indexed.output,/Tool error:.*read_file/);
}
console.log('Serialized JSON/native messages fit; escaped source pagination is lossless; oversized probes retain evidence IDs PASSED');

const {summarizeAuditLog}=await import('./audit-log-summary');
const summary=summarizeAuditLog('[READ_OK] file.py offset=0 end=10\n[READ_OK] file.py offset=0 end=10\n[CONTEXT_REREAD] {}\n[TIMING] {"promptMs":123,"generationMs":456}\nSECRET_SOURCE_CONTENT');
assert.equal(summary.repeatedReadMarkers,1);assert.equal(summary.contextRereads,1);
assert.equal(summary.durations.promptMs,123);assert.ok(!JSON.stringify(summary).includes('SECRET_SOURCE'));

// Production previously subtracted controller space only after accepting input.
const largePinned=[{role:'system',content:'s'.repeat(4000)},{role:'user',content:'p'.repeat(6000)}];
const allocation=allocateAuditContext(largePinned,{schema:'s'.repeat(3500)},8192,4096,3000);
assert.ok(allocation.generationBudget<4096);
assert.ok(allocation.generationBudget>=256);
const usable=allocation.messageBudget-3000;
assert.ok(usable-JSON.stringify(largePinned).length>=3000);
const page=fitAuditToolOutput(largePinned,request,'read_file',JSON.stringify({start:0,end:10000,totalCharacters:10000,nextOffset:null,text:'x'.repeat(10000)}),usable,true);
assert.doesNotThrow(()=>compactAuditContext([...largePinned,request,page.message],usable));
const corrections=Array.from({length:80},()=>({role:'user',content:'Rejected action: follow the current schema. '.repeat(5)}));
const compacted=compactAuditContext([...largePinned,...corrections],usable);
assert.ok(JSON.stringify(compacted).length<=usable);
assert.equal(compacted.at(-1),corrections.at(-1));
// Reproduce an oversized latest controller/tool exchange without increasing
// model context or silently fabricating source coverage.
const overPinned=[{role:'system',content:'s'.repeat(5250)},{role:'user',content:'task'}];
const overRequest={role:'assistant',content:'read_file source-1/contract.sol'};
const overTool={role:'user',content:'TOOL_RESULT '+JSON.stringify({
  name:'read_file',output:JSON.stringify({start:0,end:7000,totalCharacters:7000,
    nextOffset:null,text:'a'.repeat(7000)})
})+'\\nTool result /no_think'};
const over=compactAuditContext([...overPinned,overRequest,overTool],11663);
assert.ok(JSON.stringify(over).length<=11663);
assert.equal(over[2],overRequest,'The exact tool action must not be discarded');
assert.match(over[3].content,/contextEvicted/);
assert.doesNotMatch(over[3].content,/a{100}/,'Evicted source must not appear as fabricated evidence');
assert.match(over[3].content,/Re-read the indexed source/);

// The four-language gauntlet can produce a latest exchange larger than the
// available 11663-byte budget even when it contains no TOOL_RESULT message.
// The controller must retain durable evidence externally and recover its
// active model context instead of aborting before hypothesis planning.
const latestOversized=[
  {role:'assistant',content:'{"action":"read_file","path":"source-1/Vault.sol"}'},
  {role:'user',content:'Required stage feedback: '+'x'.repeat(6800)}
];
const rec=compactAuditContext([...overPinned,...latestOversized],11663);
assert.ok(JSON.stringify(rec).length<=11663);
assert.match(rec.at(-1)!.content,/CONTEXT_EXCHANGE_EVICTED/);
assert.doesNotMatch(JSON.stringify(rec),/x{100}/);
assert.match(rec.at(-1)!.content,/re-read indexed source or recorded evidence/);


console.log('Production input/schema/controller/output allocation and repeated correction compaction PASSED');
