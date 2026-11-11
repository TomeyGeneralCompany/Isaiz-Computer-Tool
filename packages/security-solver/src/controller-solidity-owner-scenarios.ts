import {parse} from '@solidity-parser/parser';
import {posix} from 'node:path';
import type {SolidityProbeDeclaration} from './solidity-probe-inputs';
import {sourceGroundedSolidityProbes,type GroundedSolidityProbe} from './controller-solidity-security-probes';

/**
 * Source-backed owner-gated scalar transition experiments.
 *
 * This is deliberately NOT a vulnerability detector: a rejected non-owner
 * transaction is a negative control, and a successful owner transaction is
 * a positive control. The isolated EVM and independent reviewer decide what
 * was actually observed. Neither an ABI setter nor a modifier name alone
 * authorizes an experiment.
 */
export function sourceGroundedOwnerGuardProbes(
  source:string, menu:SolidityProbeDeclaration[],
  context?:{path:string;peers:Array<{path:string;source:string}>}
):Array<{selector:string;probe:GroundedSolidityProbe}> {
  if(!context?.path.endsWith('.sol') || source.length>256000)return [];
  let ast:any;
  try{ast=parse(source,{range:true});}catch{return [];}
  const strip=(text:string)=>text.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g,'');
  const body=(node:any)=>node?.body?.range
    ? strip(source.slice(node.body.range[0],node.body.range[1]+1)) : '';
  const escape=(s:string)=>s.replace(/[.*+?^$\{\}()|[\]\\]/g,'\\$&');
  // A verified local inheritance/import edge, not a presumed standard library
  // or an untrusted method name, establishes owner initialization and guard.
  const ownerPath=posix.normalize(posix.join(posix.dirname(context.path),'./libs/BoringOwnable.sol'));
  const owner=context.peers.find(p=>p.path===ownerPath && p.source.length<=256000);
  if(!owner || !(ast.children||[]).some((n:any)=>n.type==='ImportDirective' &&
      typeof n.path==='string' &&
      posix.normalize(posix.join(posix.dirname(context.path),n.path))===ownerPath))return [];
  let ownerAst:any;
  try{ownerAst=parse(owner.source,{range:true});}catch{return [];}
  const base=(ownerAst.children||[]).find((n:any)=>
    n.type==='ContractDefinition' && n.name==='BoringOwnable');
  if(!base)return [];
  const ownerBody=(node:any)=>node?.body?.range
    ? strip(owner.source.slice(node.body.range[0],node.body.range[1]+1)) : '';
  const baseMembers:any[]=base.subNodes||[];
  const init=baseMembers.find(n=>n.type==='FunctionDefinition' && n.name==='__Ownable_init');
  const guard=baseMembers.find(n=>n.type==='ModifierDefinition' && n.name==='onlyOwner');
  const getter=baseMembers.find(n=>n.type==='FunctionDefinition' && n.name==='owner');
  if(!init || !guard || !getter ||
     !/\b_owner\s*=\s*msg\s*\.\s*sender\s*;/.test(ownerBody(init)) ||
     !/\brequire\s*\(\s*msg\s*\.\s*sender\s*==\s*_owner\s*,/.test(ownerBody(guard)) ||
     !/\breturn\s+_owner\s*;/.test(ownerBody(getter)))return [];
  const results:Array<{selector:string;probe:GroundedSolidityProbe}>=[];
  for(const contract of (ast.children||[])) {
    if(contract.type!=='ContractDefinition' || !contract.name ||
       !(contract.baseContracts||[]).some((b:any)=>b.baseName?.namePath==='BoringOwnable'))continue;
    const members:any[]=contract.subNodes||[];
    const functions=members.filter(n=>n.type==='FunctionDefinition');
    if(functions.some(n=>n.isConstructor && n.parameters?.length))continue;
    const externalInit=functions.find(n=>n.name==='initialize' &&
      ['external','public'].includes(n.visibility) &&
      (n.modifiers||[]).some((m:any)=>m.name==='initializer'));
    if(!externalInit || !externalInit.body)return [];
    const initText=body(externalInit);
    const helpers=functions.filter(n=>n.name && n.name!=='initialize' &&
      new RegExp('\\b'+escape(n.name)+'\\s*\\(').test(initText));
    const initChain=[initText,...helpers.map(body)].join('\n');
    if(!/\b__Ownable_init\s*\(\s*\)\s*;/.test(initChain))continue;
    const initSelector=contract.name+'.initialize';
    const initAbi=menu.find(m=>m.selector===initSelector && m.operation==='send');
    if(!initAbi || initAbi.inputs.length>12)continue;
    const initArgs:(string|boolean)[]=[];
    for(const type of initAbi.inputs) {
      if(/^u?int(?:[0-9]{1,3})?$/.test(type))initArgs.push('1');
      else if(/^address(?: payable)?$/.test(type))initArgs.push('$account0');
      else if(type==='bool')initArgs.push(false);
      else if(type==='string')initArgs.push('');
      else break;
    }
    if(initArgs.length!==initAbi.inputs.length)continue;
    const variables=members.filter(n=>n.type==='StateVariableDeclaration')
      .flatMap(n=>n.variables||[]).filter((v:any)=>
        v.visibility==='public' && /^uint(?:[0-9]{1,3})?$/.test(v.typeName?.name||'') &&
        /^[A-Za-z_]\w*$/.test(v.name||'') && !v.expression);
    for(const variable of variables) {
      if(new RegExp('\\b'+escape(variable.name)+'\\s*=').test(initChain))continue;
      const getterAbi=menu.find(m=>m.selector===contract.name+'.'+variable.name &&
        m.operation==='call' && m.inputs.length===0);
      if(!getterAbi)continue;
      for(const fn of functions) {
        if(!fn.name || fn.isConstructor || !['external','public'].includes(fn.visibility) ||
           fn.parameters?.length!==1 ||
           !(fn.modifiers||[]).some((m:any)=>m.name==='onlyOwner'))continue;
        const parameter=fn.parameters[0];
        if(!/^[A-Za-z_]\w*$/.test(parameter?.name||'') ||
           !/^uint(?:[0-9]{1,3})?$/.test(parameter?.typeName?.name||''))continue;
        const selector=contract.name+'.'+fn.name;
        if(!menu.some(m=>m.selector===selector && m.operation==='send' &&
          m.inputs.length===1 && /^uint(?:[0-9]{1,3})?$/.test(m.inputs[0])))continue;
        const setterText=body(fn);
        const assignment=new RegExp('\\b'+escape(variable.name)+'\\s*=\\s*'+escape(parameter.name)+'\\s*;');
        if(!assignment.test(setterText))continue;
        // Reject any other state mutation, helper call or branch. Emitting an
        // event is harmless; unknown setup/side effects must be proven separately.
        const remaining=setterText.replace(assignment,'')
          .replace(/\bemit\s+[A-Za-z_]\w*\s*\([^;]*\)\s*;/g,'')
          .replace(/[{}\s]/g,'');
        if(remaining)continue;
        const sequence:GroundedSolidityProbe['sequence']={
          constructorArgs:[],steps:[
            {operation:'send',function:'initialize('+initAbi.inputs.join(',')+')',args:initArgs,sender:0},
            {operation:'call',function:'owner()',args:[],expect:'$account0'},
            {operation:'call',function:variable.name+'()',args:[],expect:'0'},
            {operation:'send',function:fn.name+'('+menu.find(m=>m.selector===selector&&m.operation==='send')!.inputs.join(',')+')',
              args:['2'],sender:1,expectRevert:true},
            {operation:'call',function:variable.name+'()',args:[],expect:'0'},
            {operation:'send',function:fn.name+'('+menu.find(m=>m.selector===selector&&m.operation==='send')!.inputs.join(',')+')',
              args:['2'],sender:0},
            {operation:'call',function:variable.name+'()',args:[],expect:'2'}
          ]
        };
        results.push({selector,probe:{
          hypothesis:'Source-proven BoringOwnable guard on '+selector+
            ' must reject a nonowner scalar update, preserve '+variable.name+
            ', and permit the initialized owner to update it. A successful unauthorized'+
            ' send or failed authorized state transition falsifies the control.',
          sequence,guardedConsumer:selector
        }});
        if(results.length>=16)return results;
      }
    }
  }
  return results;
}

/** Shared admission for controller-owned and model-proposed Solidity plans. */
export function controllerSourceGroundedSolidityProbes(source:string,menu:SolidityProbeDeclaration[],
  context?:{path:string;peers:Array<{path:string;source:string}>}) {
  return [...sourceGroundedSolidityProbes(source,menu,context),
    ...sourceGroundedOwnerGuardProbes(source,menu,context)];
}
