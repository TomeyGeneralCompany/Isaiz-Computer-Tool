import {parse} from '@solidity-parser/parser';
import type {SolidityProbeDeclaration} from './solidity-probe-inputs';
import type {SoliditySequence} from './solidity-sequence';

/** A probe is eligible only when source establishes a security rule, a
 * reproducible caller/role setup, and an assertion which can falsify the
 * suspected violation. ABI mutability alone is never a security hypothesis.
 *
 * This intentionally supports one narrow scenario: a nonadmin changing a
 * role that protects another entry point. Other Solidity methods require a
 * separately proven scenario and are skipped, not given fixture transactions.
 */
type RoleMutation = {selector:string;role:string;method:string};
export type GroundedSolidityProbe = {
  hypothesis:string;
  sequence:SoliditySequence;
  guardedConsumer:string;
};

export function sourceGroundedSolidityProbe(
  source:string,
  menu:SolidityProbeDeclaration[],
  candidate:RoleMutation|null|undefined,
  requestedSelector:string
):GroundedSolidityProbe|null {
  if(!candidate || candidate.selector!==requestedSelector || source.length>256000)return null;
  const separator=requestedSelector.lastIndexOf('.');
  if(separator<1)return null;
  const contractName=requestedSelector.slice(0,separator);
  const mutation=requestedSelector.slice(separator+1);
  if(candidate.method!==mutation || !/^[A-Za-z_]\w*$/.test(candidate.role))return null;
  let ast:any;
  try {ast=parse(source,{range:true});}catch{return null;}
  const contracts=(ast.children||[]).filter((node:any)=>
    node.type==='ContractDefinition' && node.name===contractName);
  if(contracts.length!==1)return null;
  const members:any[]=contracts[0].subNodes||[];
  const functions=members.filter(node=>node.type==='FunctionDefinition');
  const constructor=functions.filter(node=>node.isConstructor);
  if(constructor.length!==1 || constructor[0].parameters?.length!==0)return null;
  const extract=(node:any):string=>{
    if(!node?.body?.range)return '';
    return source.slice(node.body.range[0],node.body.range[1]+1);
  };
  const literal=(value:string)=>value.replace(/[.*+?^$\{\}()|[\]\\]/g,'\\$&');
  const role=literal(candidate.role);
  // The starting value is not assumed: deployment by account0 must initialize
  // the protected role to msg.sender, or the expected baseline is unsupported.
  const init=new RegExp('\\b'+role+'\\s*=\\s*msg\\s*\\.\\s*sender\\s*;');
  if(!init.test(extract(constructor[0])))return null;
  const roleStorage=members.some(member=>member.type==='StateVariableDeclaration' &&
    (member.variables||[]).some((variable:any)=>
      variable.name===candidate.role && variable.visibility==='public' &&
      variable.typeName?.type==='ElementaryTypeName' && variable.typeName.name==='address'));
  if(!roleStorage)return null;

  const setter=functions.filter(fn=>fn.name===mutation && !fn.isConstructor);
  if(setter.length!==1 || !['public','external'].includes(setter[0].visibility) ||
     (setter[0].modifiers||[]).length!==0 || setter[0].parameters?.length!==1)return null;
  const param=setter[0].parameters[0];
  if(param?.typeName?.type!=='ElementaryTypeName' ||
     param.typeName.name!=='address' || !/^[A-Za-z_]\w*$/.test(param.name||''))return null;
  const parameter=literal(param.name);
  const setterBody=extract(setter[0]);
  if(!setterBody)return null;
  // Permit a single nonzero-address validation, but no implicit modifiers,
  // unknown helper calls, conditional branches or caller authorization.
  // Those cases need a source-specific setup and must not be guessed.
  const nonzero=new RegExp('require\\s*\\(\\s*'+parameter+
    '\\s*!=\\s*address\\s*\\(\\s*0\\s*\\)\\s*(?:,\\s*(?:"[^"\\n]*"|\x27[^\x27\\n]*\x27))?\\s*\\)\\s*;','g');
  const remaining=setterBody.replace(nonzero,'')
    .replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g,'')
    .replace(/^\s*\{|\}\s*$/g,'').trim();
  if(!new RegExp('^'+role+'\\s*=\\s*'+parameter+'\\s*;$').test(remaining))return null;
  // A different contract declaring its own identically named role is not a
  // protected consumer of this storage slot. Require a guard in THIS contract.
  const guard=new RegExp('\\brequire\\s*\\(\\s*(?:msg\\s*\\.\\s*sender\\s*==\\s*'+role+
    '|'+role+'\\s*==\\s*msg\\s*\\.\\s*sender)\\b');
  const consumers=functions.filter(fn=>fn!==setter[0] && !fn.isConstructor &&
    ['public','external'].includes(fn.visibility) &&
    !['view','pure'].includes(fn.stateMutability||'') &&
    guard.test(extract(fn)) && !!extract(fn));
  if(!consumers.length)return null;
  const getter=menu.find(item=>item.selector===contractName+'.'+candidate.role &&
    item.operation==='call' && item.inputs.length===0);
  const entry=menu.find(item=>item.selector===requestedSelector &&
    item.operation==='send' && item.inputs.length===1 &&
    /^address(?: payable)?$/.test(item.inputs[0]));
  if(!getter || !entry)return null;
  const observedGetter=candidate.role+'()';
  const setterSignature=mutation+'('+entry.inputs.join(',')+')';
  const sequence:SoliditySequence={constructorArgs:[],steps:[
    {operation:'call',function:observedGetter,args:[],expect:'$account0'},
    {operation:'send',function:setterSignature,args:['$account2'],sender:1},
    {operation:'call',function:observedGetter,args:[],expect:'$account2'}
  ]};
  return {
    hypothesis:'Source declares '+candidate.role+' as an account0-initialized role that gates '+
      consumers[0].name+'; caller account1 must not be able to set it to account2 via '+
      requestedSelector+'. The test is falsified by a rejected unauthorized send or by '+
      'failure of the asserted account0-to-account2 role transition.',
    sequence,guardedConsumer:contractName+'.'+consumers[0].name
  };
}

/** Source-backed *navigation hints*, not vulnerability findings. Trace actual
 * calls from project contracts before considering an inherited ERC1155 entry.
 * AST traversal ignores comments and bare method declarations. Callers still
 * require independent reachability, setup and a security assertion to qualify.
 */
export function traceProjectErc1155Callers(path:string,source:string):
  Array<{path:string;selector:string;calledMethod:string;line:number}> {
  if(!path.endsWith('.sol') || source.length>256000 ||
     !/\\bsafe(?:Batch)?TransferFrom\\s*\\(/.test(source))return [];
  let ast:any;
  try {ast=parse(source,{range:true,loc:true});}catch{return [];}
  const results:Array<{path:string;selector:string;calledMethod:string;line:number}>=[];
  for(const contract of (ast.children||[])) {
    if(contract.type!=='ContractDefinition' ||
       /^(?:ERC1155Upgradeable|IERC1155(?:Upgradeable)?)$/.test(contract.name))continue;
    for(const fn of contract.subNodes||[]) {
      if(fn.type!=='FunctionDefinition' || !fn.body)continue;
      const declared=fn.name||(fn.isConstructor?'constructor':'');
      if(!declared)continue;
      let seen=0;
      const walk=(node:any,depth:number):void=>{
        if(!node || typeof node!=='object' || depth>48 || seen++>4000)return;
        if(Array.isArray(node)) {for(const child of node)walk(child,depth+1);return;}
        if(node.type==='FunctionCall') {
          const called=node.expression?.type==='MemberAccess'
            ? node.expression.memberName
            : node.expression?.type==='Identifier'?node.expression.name:'';
          if(called==='safeTransferFrom' || called==='safeBatchTransferFrom') {
            results.push({path,selector:contract.name+'.'+declared,calledMethod:called,
              line:node.loc?.start?.line||1});
          }
        }
        for(const [key,child] of Object.entries(node))
          if(key!=='range' && key!=='loc')walk(child,depth+1);
      };
      walk(fn.body,0);
    }
  }
  return results.slice(0,40);
}
