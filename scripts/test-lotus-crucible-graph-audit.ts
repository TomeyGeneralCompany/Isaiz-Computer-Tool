import {strict as assert} from 'node:assert';
import {planCrucibleTopology} from './lotus-crucible-topology';
import {auditCrucibleGraph} from './lotus-crucible-graph-audit';
for(const language of ['solidity','python','javascript','java'] as const){
  const t=planCrucibleTopology({seed:'sealed-audit-regression',language,fileCount:2000,defectCount:5});
  const a=auditCrucibleGraph(t);
  assert.equal(a.largestStrongComponent,2000);
  assert.equal(a.chainCount,5);
  const broken={...t,edges:t.edges.filter(([a,b])=>a!==t.defectChains[0][0]||b!==t.defectChains[0][1])};
  assert.throws(()=>auditCrucibleGraph(broken),/broken causal chain/);
  const overlap={...t,ordinaryNodes:[...t.ordinaryNodes,t.negativeControlNodes[0]]};
  assert.throws(()=>auditCrucibleGraph(overlap),/node roles/);
  const disconnected={...t,edges:t.edges.filter(([a,b])=>a!==0&&b!==0)};
  assert.throws(()=>auditCrucibleGraph(disconnected),/disconnected/);
}
console.log('Crucible graph integrity audit PASSED');
