import assert from 'node:assert/strict';
import {planCrucibleTopology} from './lotus-crucible-topology';

const languages=['solidity','python','javascript','java'] as const;
for(const language of languages){
  const args={seed:'sealed-test-1',language,fileCount:2000,defectCount:6};
  const a=planCrucibleTopology(args);
  const b=planCrucibleTopology(args);
  const c=planCrucibleTopology({...args,seed:'sealed-test-2'});
  assert.deepEqual(a,b,'same seed must reproduce exact topology');
  assert.notDeepEqual(a,c,'different seeds must change topology');
  assert.equal(a.defectChains.length,6);
  assert.equal(a.falseLeadNodes.length,200);
  assert.equal(a.negativeControlNodes.length,50);
  const roles=[...a.defectChains.flat(),...a.falseLeadNodes,
    ...a.negativeControlNodes,...a.ordinaryNodes];
  assert.equal(roles.length,2000);
  assert.equal(new Set(roles).size,2000,'oracle roles must be disjoint');
  assert(a.defectChains.every(x=>x.length>=3&&x.length<=7));
  const edges=new Set(a.edges.map(([x,y])=>x+':'+y));
  assert(a.defectChains.every(chain=>chain.slice(1).every((v,i)=>
    edges.has(chain[i]+':'+v))),'each planned chain must have explicit edges');
  const out=new Set(a.edges.map(([x])=>x));
  assert.equal(out.size,2000,'no isolated source nodes');
  assert(a.edges.length<=2000*4,'bounded sparse topology');
  const clean=planCrucibleTopology({...args,defectCount:0});
  assert.equal(clean.defectChains.length,0);
  assert.equal(clean.falseLeadNodes.length,200);
  assert.equal(clean.negativeControlNodes.length,50);
}
const base={seed:'seed',language:'python' as const,fileCount:2000,defectCount:5};
for(const changes of [
  {seed:''},{fileCount:1999},{fileCount:5001},{defectCount:4},
  {defectCount:9},{falseLeadCount:199},{negativeControlCount:49},
  {fileCount:2000,falseLeadCount:1950},
]){
  assert.throws(()=>planCrucibleTopology({...base,...changes}),/Crucible/);
}
console.log('Level 6 seeded polyglot topology invariants PASSED (planning only; no exploit or oracle qualification)');
