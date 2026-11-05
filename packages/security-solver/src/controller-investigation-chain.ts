/** Controller-owned, language-neutral call-chain promotion.
 * Each edge must be source-grounded; each promoted helper must be actually
 * reproduced. An entry point is executed separately, never inferred from
 * a matching filename. Nothing here approves security impact.
 */
export type ControllerCallEdge={path:string;line:number;selector:string;code:string};
export type ControllerProbeResult={status:string;caseId?:string};
export type ControllerChainStep={path:string;selector:string;caseId:string;kind:string};
export type ControllerChainResult={
  promoted:ControllerChainStep; entry?:ControllerChainStep;
  caller?:ControllerCallEdge; history:ControllerChainStep[];
  stopped:string;
};
export function controllerEnclosingSelector(path:string,source:string,line:number):string|null {
  if(!Number.isSafeInteger(line)||line<1)return null;
  const lines=source.split('\n');
  if(line>lines.length)return null;
  const preceding=lines.slice(Math.max(0,line-24),line-1);
  for(const text of preceding.reverse()){
    const py=/^\s*(?:async\s+)?def\s+([A-Za-z_][\w$]*)\s*\(/.exec(text);
    const js=/\bexports\.([A-Za-z_$][\w$]*)\s*=/.exec(text) ||
      /\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/.exec(text);
    const java=/\b(?:public|protected|private)\s+(?:static\s+)?[A-Za-z_$][\w$<>\[\]., ?]*\s+([A-Za-z_$][\w$]*)\s*\(/.exec(text);
    const name=(py||js||java)?.[1];
    if(name)return path.endsWith('.java')?
      path.split('/').at(-1)!.replace(/\.java$/,'')+'.'+name:name;
  }
  return null;
}
export async function promoteControllerCallChain(input:{
  start:ControllerChainStep;chain:ControllerCallEdge[];maxSteps?:number;
  read:(path:string)=>Promise<string>;
  references:(source:string,line:number,selector:string)=>boolean;
  probe:(path:string,selector:string,kind:string)=>Promise<ControllerProbeResult>;
  supported:(path:string,selector:string)=>Promise<boolean>;
  onStep?:(step:ControllerChainStep,edge:ControllerCallEdge)=>Promise<void>;
}):Promise<ControllerChainResult> {
  let current=input.start;
  const history=[current],visited=new Set([current.path]);
  const max=Math.min(8,Math.max(1,input.maxSteps??6));
  for(const edge of input.chain.slice(0,max)){
    if(visited.has(edge.path))return {promoted:current,history,stopped:'cycle'};
    const source=await input.read(edge.path);
    if(!input.references(source,edge.line,current.selector))
      return {promoted:current,history,stopped:'unverified_source_edge'};
    const selector=controllerEnclosingSelector(edge.path,source,edge.line);
    if(!selector)return {promoted:current,history,stopped:'unresolved_enclosing_function'};
    const entry=/(?:handler|controller|route|entry|server)/i.test(edge.path.split('/').at(-1)||'');
    if(!entry && !await input.supported(edge.path,selector))
      return {promoted:current,history,stopped:'unsupported_intermediate_reproduction'};
    const kind=entry?'entry_html_reflection':current.kind;
    // Only HTML handlers currently have a verified entry-level reproduction
    // adapter. Other probe kinds must not be reinterpreted as HTML evidence.
    if(entry && current.kind!=='html_reflection')
      return {promoted:current,history,stopped:'no_language_entry_adapter'};
    const result=await input.probe(edge.path,selector,kind);
    if(result.status!=='behavior_observed'||!result.caseId)
      return {promoted:current,history,stopped:'reproduction_not_observed'};
    const next={path:edge.path,selector,caseId:result.caseId,kind};
    history.push(next);visited.add(edge.path);
    await input.onStep?.(next,edge);
    if(entry)return {promoted:current,entry:next,caller:edge,history,stopped:'verified_entry_replayed'};
    current=next;
  }
  return {promoted:current,history,stopped:'upstream_chain_exhausted'};
}
