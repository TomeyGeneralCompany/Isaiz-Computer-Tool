/** Grader-only seeded topology planner for Level 6.
 * Planning is NOT source generation or a vulnerability oracle. Keep this
 * module outside the investigator package and production controller.
 */
import {createHash} from 'node:crypto';
import type {Language} from './lotus-gauntlet-fixtures';
import {CRUCIBLE_REQUIREMENTS} from './lotus-crucible-contract';

export type CrucibleTopology={
  language:Language;
  fileCount:number;
  edges:ReadonlyArray<readonly [number,number]>;
  defectChains:ReadonlyArray<ReadonlyArray<number>>;
  falseLeadNodes:ReadonlyArray<number>;
  negativeControlNodes:ReadonlyArray<number>;
  ordinaryNodes:ReadonlyArray<number>;
};

function rng(seed:string):()=>number {
  if(!seed.trim())throw new Error('Crucible topology requires a nonempty sealed seed');
  let counter=0;
  return ()=>{
    const bytes=createHash('sha256').update(seed).update(':').update(String(counter++)).digest();
    return bytes.readUInt32BE(0)/0x100000000;
  };
}
function shuffle<T>(items:T[],next:()=>number):T[]{
  for(let i=items.length-1;i>0;i--){
    const j=Math.floor(next()*(i+1));
    [items[i],items[j]]=[items[j],items[i]];
  }
  return items;
}
/** Reproducible topology with disjoint seeded role assignments.
 * Edges are directed source dependencies. Every file has an outgoing
 * dependency, and every defect chain has an explicit traversable route.
 * The grader must separately prove executable reachability and effects.
 */
export function planCrucibleTopology(input:{
  seed:string;language:Language;fileCount:number;defectCount:number;
  falseLeadCount?:number;negativeControlCount?:number;
}):CrucibleTopology {
  const {seed,language,fileCount,defectCount}=input;
  const r=CRUCIBLE_REQUIREMENTS;
  const falseLeadCount=input.falseLeadCount??r.minimumFalseLeads;
  const negativeControlCount=input.negativeControlCount??r.minimumNegativeControls;
  if(!(['solidity','python','javascript','java'] as string[]).includes(language))
    throw new Error('Crucible unsupported language');
  if(!Number.isInteger(fileCount)||fileCount<r.minimumSourceFiles||fileCount>r.maximumSourceFiles)
    throw new Error('Crucible invalid topology source count');
  if(!Number.isInteger(defectCount)||defectCount<0||defectCount>r.maximumDefects||
     (defectCount>0&&defectCount<r.minimumDefects))
    throw new Error('Crucible invalid topology defect count');
  if(!Number.isInteger(falseLeadCount)||falseLeadCount<r.minimumFalseLeads||
     !Number.isInteger(negativeControlCount)||negativeControlCount<r.minimumNegativeControls)
    throw new Error('Crucible insufficient topology controls');
  const next=rng(seed+':'+language);
  const nodes=shuffle(Array.from({length:fileCount},(_,i)=>i),next);
  const chainLengths=Array.from({length:defectCount},()=>r.minimumChainStages+
    Math.floor(next()*(r.maximumChainStages-r.minimumChainStages+1)));
  const reserved=chainLengths.reduce((a,b)=>a+b,0)+falseLeadCount+negativeControlCount;
  if(reserved>fileCount)throw new Error('Crucible topology roles exceed file count');
  let cursor=0;
  const defectChains=chainLengths.map(n=>nodes.slice(cursor,cursor+=n));
  const falseLeadNodes=nodes.slice(cursor,cursor+=falseLeadCount);
  const negativeControlNodes=nodes.slice(cursor,cursor+=negativeControlCount);
  const ordinaryNodes=nodes.slice(cursor);
  const edgeSet=new Set<string>();
  const add=(a:number,b:number)=>{if(a!==b)edgeSet.add(a+':'+b);};
  // Randomized strongly connected backbone: every node participates in a
  // reachable component, not a disconnected filler island.
  for(let i=0;i<nodes.length;i++)add(nodes[i],nodes[(i+1)%nodes.length]);
  // Additional sparse inter-service dependencies, bounded for 4c/8t hosts.
  for(let i=0;i<nodes.length;i++)for(let j=0;j<2;j++)
    add(nodes[i],nodes[Math.floor(next()*nodes.length)]);
  for(const chain of defectChains)for(let i=1;i<chain.length;i++)
    add(chain[i-1],chain[i]);
  const edges=Array.from(edgeSet,x=>x.split(':').map(Number) as [number,number]);
  return {language,fileCount,edges,defectChains,falseLeadNodes,
    negativeControlNodes,ordinaryNodes};
}
