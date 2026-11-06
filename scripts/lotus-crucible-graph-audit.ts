/** Grader-side graph audit: topology alone never proves executable behavior. */
import type {CrucibleTopology} from './lotus-crucible-topology';

export type CrucibleGraphAudit={
  nodes:number;edges:number;largestStrongComponent:number;
  chainCount:number;controlCount:number;
};

/** Iterative SCC traversal avoids recursion overflow at 5,000 nodes.
 * Rejects unreachable islands, forged role membership and broken causal edges.
 */
export function auditCrucibleGraph(t:CrucibleTopology):CrucibleGraphAudit {
  const n=t.fileCount;
  if(!Number.isInteger(n)||n<2000||n>5000)throw new Error('Crucible invalid node count');
  const forward:number[][]=Array.from({length:n},()=>[]);
  const reverse:number[][]=Array.from({length:n},()=>[]);
  const edgeSet=new Set<string>();
  for(const [a,b] of t.edges){
    if(!Number.isInteger(a)||!Number.isInteger(b)||a<0||b<0||a>=n||b>=n||a===b)
      throw new Error('Crucible invalid dependency edge');
    const id=a+':'+b;
    if(edgeSet.has(id))throw new Error('Crucible duplicate dependency edge');
    edgeSet.add(id);forward[a].push(b);reverse[b].push(a);
  }
  const roles=[...t.defectChains.flat(),...t.falseLeadNodes,...t.negativeControlNodes,...t.ordinaryNodes];
  if(roles.length!==n||new Set(roles).size!==n||roles.some(x=>!Number.isInteger(x)||x<0||x>=n))
    throw new Error('Crucible missing or overlapping node roles');
  for(const chain of t.defectChains){
    if(chain.length<3||chain.length>7||new Set(chain).size!==chain.length)
      throw new Error('Crucible invalid causal chain');
    for(let i=1;i<chain.length;i++)
      if(!edgeSet.has(chain[i-1]+':'+chain[i]))
        throw new Error('Crucible broken causal chain dependency');
  }
  if(t.falseLeadNodes.length<200||t.negativeControlNodes.length<50)
    throw new Error('Crucible insufficient decoy/control coverage');
  const seen=new Uint8Array(n),order:number[]=[];
  for(let root=0;root<n;root++){
    if(seen[root])continue;
    seen[root]=1;
    const stack:Array<[number,number]>=[[root,0]];
    while(stack.length){
      const top=stack[stack.length-1],neighbors=forward[top[0]];
      if(top[1]<neighbors.length){
        const v=neighbors[top[1]++];
        if(!seen[v]){seen[v]=1;stack.push([v,0]);}
      }else{order.push(top[0]);stack.pop();}
    }
  }
  seen.fill(0);
  let largest=0;
  for(let i=order.length-1;i>=0;i--){
    const root=order[i];if(seen[root])continue;
    let count=0,stack=[root];seen[root]=1;
    while(stack.length){
      const v=stack.pop()!;count++;
      for(const w of reverse[v])if(!seen[w]){seen[w]=1;stack.push(w);}
    }
    largest=Math.max(largest,count);
  }
  if(largest!==n)throw new Error('Crucible disconnected dependency graph');
  return {nodes:n,edges:edgeSet.size,largestStrongComponent:largest,
    chainCount:t.defectChains.length,controlCount:t.negativeControlNodes.length};
}
