/**
 * Source-grounded, offline experiment constructor. Operates ONLY on supplied,
 * already-acquired source bytes. No I/O, model inference, or controller actions.
 * Existing role-mutation planner remains the authoritative legacy fallback.
 */
import {createHash} from 'node:crypto';
import {parse} from '@solidity-parser/parser';
import {posix} from 'node:path';
import type {SolidityProbeDeclaration} from './solidity-probe-inputs';
import type {SoliditySequence} from './solidity-sequence';
import {sourceGroundedSolidityProbes} from './controller-solidity-security-probes';
import {orderPreparation, type PreparationPrerequisite, type SourceWitness} from './controller-solidity-prerequisites';

export interface SourceSnapshot {path:string;sha256:string;content:string}
export interface ConstructionInput {
  repositoryCommit:string;targetPath:string;targetSelector:string;
  sources:readonly SourceSnapshot[];
  declarations:readonly SolidityProbeDeclaration[];
}
export interface PreparedSecurityExperiment {
  version:1;id:string;language:'solidity';status:'constructed';
  path:string;selector:string;hypothesis:string;securityProperty:string;
  witnesses:SourceWitness[];prerequisites:PreparationPrerequisite[];
  sequence:SoliditySequence;
}
export type ConstructionResult =
  | {ok:true;experiments:PreparedSecurityExperiment[]}
  | {ok:false;code:string;detail:string};
const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
const identifier=/^[A-Za-z_]\w*$/;
const clean=(s:string)=>s.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g,'');
const body=(text:string,node:any)=>node?.body?.range ?
  clean(text.slice(node.body.range[0],node.body.range[1]+1)):'';
function witness(snapshot:SourceSnapshot,node:any,symbol:string):SourceWitness {
  const range=node?.range||[0,snapshot.content.length-1];
  return {path:snapshot.path,sourceSha256:snapshot.sha256,
    start:range[0],end:range[1]+1,symbol};
}
function valueOfType(type:string):string|boolean|null {
  if(/^u?int(?:[0-9]{1,3})?$/.test(type))return '1';
  if(type==='bool')return false;
  if(type==='address')return '$account0';
  if(type==='string')return '';
  return null;
}
/** Proof of ownership comes from THIS contract's actual source, not a name. */
function directOwnerExperiment(snapshot:SourceSnapshot,contract:any,menu:readonly SolidityProbeDeclaration[],
  target:string):{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}|null {
  const source=snapshot.content,members:any[]=contract.subNodes||[];
  const functions=members.filter(n=>n.type==='FunctionDefinition');
  const constructor=functions.find(n=>n.isConstructor);
  const owner=members.filter(n=>n.type==='StateVariableDeclaration').flatMap(n=>n.variables||[])
    .find((v:any)=>v.name==='owner'&&v.typeName?.name==='address'&&v.visibility==='public');
  if(!owner || !constructor || constructor.parameters?.length ||
    !/\bowner\s*=\s*msg\s*\.\s*sender\s*;/.test(body(source,constructor)))return null;
  const setter=functions.find(n=>n.name===target&&['public','external'].includes(n.visibility) &&
    n.parameters?.length===1 && n.body?.range);
  if(!setter)return null;
  const parameter=setter.parameters[0];
  if(!identifier.test(parameter?.name||''))return null;
  const type=parameter.typeName?.name;
  if(!type || !/^uint(?:[0-9]{1,3})?$/.test(type))return null;
  const state=members.filter(n=>n.type==='StateVariableDeclaration').flatMap(n=>n.variables||[])
    .find((v:any)=>v.visibility==='public'&&v.typeName?.name===type && v.name!==parameter.name);
  if(!state || !identifier.test(state.name))return null;
  const fnBody=body(source,setter);
  if(!/\brequire\s*\(\s*msg\s*\.\s*sender\s*==\s*owner\b/.test(fnBody))return null;
  const assignment=new RegExp('\\b'+state.name+'\\s*=\\s*'+parameter.name+'\\s*;');
  if(!assignment.test(fnBody))return null;
  const remainder=fnBody.replace(/\brequire\s*\([^;]*\)\s*;/g,'')
    .replace(assignment,'').replace(/[{}\s]/g,'');
  if(remainder)return null; // No unproven side effects.
  const selector=contract.name+'.'+setter.name;
  const entry=menu.find(m=>m.selector===selector&&m.operation==='send'&&
    m.inputs.length===1&&m.inputs[0]===type);
  const getter=menu.find(m=>m.selector===contract.name+'.'+state.name&&
    m.operation==='call'&&m.inputs.length===0);
  const ownerGetter=menu.find(m=>m.selector===contract.name+'.owner'&&
    m.operation==='call'&&m.inputs.length===0);
  if(!entry||!getter||!ownerGetter)return null;
  const initial=state.expression?null:'0';
  if(initial===null)return null;
  const sequence:SoliditySequence={constructorArgs:[],steps:[
    {operation:'call',function:'owner()',args:[],expect:'$account0'},
    {operation:'call',function:state.name+'()',args:[],expect:initial},
    {operation:'send',function:setter.name+'('+type+')',args:['2'],sender:1,expectRevert:true},
    {operation:'call',function:state.name+'()',args:[],expect:initial},
    {operation:'send',function:setter.name+'('+type+')',args:['2'],sender:0},
    {operation:'call',function:state.name+'()',args:[],expect:'2'}
  ]};
  return {hypothesis:'Unauthorized caller cannot update '+state.name+
    ' through '+selector+'; authorized owner can.',property:'owner-gated state transition',
    sequence,witnesses:[witness(snapshot,constructor,contract.name+'.constructor'),
      witness(snapshot,setter,selector),witness(snapshot,owner,contract.name+'.owner'),
      witness(snapshot,state,contract.name+'.'+state.name)]};
}
export function constructSolidityExperiments(input:ConstructionInput):ConstructionResult {
  if(!/^[a-f0-9]{40}$/.test(input.repositoryCommit))
    return {ok:false,code:'INVALID_COMMIT',detail:'Expected a source commit SHA'};
  const indexed=new Map<string,SourceSnapshot>();
  for(const s of input.sources) {
    if(!s.path||s.path.startsWith('/')||s.path.split('/').includes('..')||
      !/^[a-f0-9]{64}$/.test(s.sha256)||hash(s.content)!==s.sha256||
      indexed.has(s.path))
      return {ok:false,code:'SOURCE_IDENTITY_INVALID',detail:s.path};
    indexed.set(s.path,s);
  }
  const target=indexed.get(input.targetPath);
  if(!target)return {ok:false,code:'SOURCE_NOT_ACQUIRED',detail:input.targetPath};
  const separator=input.targetSelector.lastIndexOf('.');
  if(separator<1)return {ok:false,code:'TARGET_INVALID',detail:input.targetSelector};
  const contractName=input.targetSelector.slice(0,separator);
  const method=input.targetSelector.slice(separator+1);
  let ast:any;
  try{ast=parse(target.content,{range:true});}
  catch{return {ok:false,code:'UNPARSEABLE_SOURCE',detail:input.targetPath};}
  const contract=(ast.children||[]).find((n:any)=>n.type==='ContractDefinition'&&n.name===contractName);
  if(!contract)return {ok:false,code:'TARGET_NOT_DECLARED',detail:input.targetSelector};
  // Preserve existing strict role-transition proof as first source of plans.
  const peers=[...indexed.values()].map(s=>({path:s.path,source:s.content}));
  const legacy=sourceGroundedSolidityProbes(target.content,[...input.declarations],
    {path:target.path,peers}).filter(p=>p.selector===input.targetSelector);
  const choices:{hypothesis:string;property:string;sequence:SoliditySequence;witnesses:SourceWitness[]}[]=[];
  for(const item of legacy)choices.push({hypothesis:item.probe.hypothesis,
    property:'source-proven role mutation',sequence:item.probe.sequence,
    witnesses:[witness(target,contract,input.targetSelector)]});
  const direct=directOwnerExperiment(target,contract,input.declarations,method);
  if(direct)choices.push(direct);
  if(!choices.length)return {ok:false,code:'UNKNOWN_ASSERTION',
    detail:'No source-grounded security setup and falsifiable assertion for '+input.targetSelector};
  const seen=new Set<string>(),out:PreparedSecurityExperiment[]=[];
  for(const c of choices) {
    const prereqs:PreparationPrerequisite[]=[];
    const graph=orderPreparation(prereqs);
    if(!graph.ok)return {ok:false,code:graph.code,detail:graph.detail};
    const payload={sourceCommit:input.repositoryCommit,path:input.targetPath,
      selector:input.targetSelector,property:c.property,sequence:c.sequence};
    const id=hash(JSON.stringify(payload));
    if(seen.has(id))continue;seen.add(id);
    out.push({version:1,id,language:'solidity',status:'constructed',
      path:input.targetPath,selector:input.targetSelector,
      hypothesis:c.hypothesis,securityProperty:c.property,witnesses:c.witnesses,
      prerequisites:graph.ordered,sequence:c.sequence});
  }
  return {ok:true,experiments:out};
}
