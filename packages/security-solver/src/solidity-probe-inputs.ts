/** Deterministic local-EVM test values, never external account data.
 * Return null when the declaration needs semantic setup rather than guesswork. */
export function fixtureArguments(types:string[]):unknown[]|null {
  const values:unknown[]=[];
  for(const original of types) {
    const type=original.replace(/\s+/g,' ').trim();
    const fixed=type.match(/^(.*)\[(\d+)\]$/);
    if(fixed) {
      const count=Number(fixed[2]);if(count>8)return null;
      const one=fixtureArguments([fixed[1]]);if(!one)return null;
      values.push(Array.from({length:count},()=>one[0]));continue;
    }
    if(/\[\]$/.test(type)){values.push([]);continue;}
    if(/^u?int(?:[0-9]{1,3})?$/.test(type)){values.push('7');continue;}
    if(type==='bool'){values.push(true);continue;}
    if(type==='address'||type==='address payable'){values.push('$account1');continue;}
    if(type==='string'){values.push('TOMEY_LOCAL_PROBE');continue;}
    if(type==='bytes'){values.push('0x4142');continue;}
    const sized=type.match(/^bytes([1-9]|[12][0-9]|3[012])$/);
    if(sized){values.push('0x'+'41'.repeat(Number(sized[1])));continue;}
    return null; // structs, contracts, mappings and custom types need a setup plan
  }
  return values;
}

export interface SolidityProbeDeclaration {
  selector:string;operation:'constructor'|'send'|'call';inputs:string[];
}
/** Construct a local baseline/transition test from declarations, not imagined
 * state expectations. Unresolved ABI setup returns null. */
export function buildBaselineSequence(menu:SolidityProbeDeclaration[],selectedSelector:string,adversarialRoleTest=false) {
  const selected=menu.find(entry=>entry.selector===selectedSelector && entry.operation==='send');
  if(!selected)return null;
  const contract=selectedSelector.split('.')[0];
  const declarations=menu.filter(entry=>entry.selector.startsWith(contract+'.'));
  const constructors=declarations.filter(entry=>entry.operation==='constructor');
  if(constructors.length>1)return null;
  const constructorArgs=constructors.length?fixtureArguments(constructors[0].inputs):[];
  let sendArgs=fixtureArguments(selected.inputs);
  const reads=declarations.filter(entry=>entry.operation==='call' && fixtureArguments(entry.inputs)!==null);
  // For the repository's ERC1155 implementation, the controller owns a
  // deterministic positive transfer scenario. Empty batches and transfers
  // back to the same account cannot establish a useful state transition.
  const erc1155=contract==='ERC1155Upgradeable';
  const erc1155Single=erc1155 && selectedSelector.endsWith('.safeTransferFrom') &&
    JSON.stringify(selected.inputs)===JSON.stringify(['address','address','uint256','uint256','bytes']);
  const erc1155Batch=erc1155 && selectedSelector.endsWith('.safeBatchTransferFrom') &&
    JSON.stringify(selected.inputs)===JSON.stringify(['address','address','uint256[]','uint256[]','bytes']);
  if(erc1155Single)sendArgs=['$account1','$account2','7','7','0x4142'];
  if(erc1155Batch)sendArgs=['$account1','$account2',['7'],['7'],'0x4142'];
  // A zero-input getter is preferable to an unrelated parameterized read;
  // these are observations, not invented assertions about correctness.
  const selectedMethod=selectedSelector.split('.').at(-1)||'';
  const roleName=/^(?:rotate|change|set|update|transfer|assign)([A-Z][A-Za-z0-9_]*)$/.exec(selectedMethod)?.[1];
  const expectedGetter=roleName?roleName[0].toLowerCase()+roleName.slice(1):'';
  reads.sort((a,b)=>{
    const rank=(entry:SolidityProbeDeclaration)=>{
      const name=entry.selector.split('.').at(-1)||'';
      const getter=/^(?:get[A-Z]|value$|balanceOf$|totalSupply$|owner$|count$|stored$|current)/.test(name);
      return (entry.inputs.length?4:0)+(getter?0:1)-(name===expectedGetter?10:0);
    };
    return rank(a)-rank(b);
  });
  let read=reads[0];
  let readArgs=read?fixtureArguments(read.inputs):null;
  if(erc1155Single||erc1155Batch) {
    const balance=reads.find(entry=>entry.selector===contract+'.balanceOf' &&
      JSON.stringify(entry.inputs)===JSON.stringify(['address','uint256']));
    if(!balance)return null;
    read=balance;readArgs=['$account2','7'];
  } else if(erc1155 && selectedSelector.endsWith('.setApprovalForAll')) {
    const approved=reads.find(entry=>entry.selector===contract+'.isApprovedForAll' &&
      JSON.stringify(entry.inputs)===JSON.stringify(['address','address']));
    if(approved){read=approved;readArgs=['$account0','$account1'];}
  }
  if(!read || !constructorArgs || !sendArgs || !readArgs)return null;
  const signature=(entry:SolidityProbeDeclaration)=>entry.selector.split('.').at(-1)+'('+entry.inputs.join(',')+')';
  // This is only an authorization *observation* when the caller has source
  // evidence of a protected role consumer. A nonadmin sender and a distinct
  // target role make the before/after state interpretable.
  const args=adversarialRoleTest ? sendArgs.map((v,i)=>
    /^(?:address|address payable)$/.test(selected.inputs[i])?'$account2':v) : sendArgs;
  return {constructorArgs,steps:[
    {operation:'observe' as const,function:signature(read),args:readArgs},
    {operation:'send' as const,function:signature(selected),args,
      ...(adversarialRoleTest?{sender:1}: {})},
    {operation:'observe' as const,function:signature(read),args:readArgs}
  ]};
}
