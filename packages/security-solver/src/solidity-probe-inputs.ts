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
export function buildBaselineSequence(menu:SolidityProbeDeclaration[],selectedSelector:string) {
  const selected=menu.find(entry=>entry.selector===selectedSelector && entry.operation==='send');
  if(!selected)return null;
  const contract=selectedSelector.split('.')[0];
  const declarations=menu.filter(entry=>entry.selector.startsWith(contract+'.'));
  const constructors=declarations.filter(entry=>entry.operation==='constructor');
  if(constructors.length>1)return null;
  const constructorArgs=constructors.length?fixtureArguments(constructors[0].inputs):[];
  const sendArgs=fixtureArguments(selected.inputs);
  const read=declarations.find(entry=>entry.operation==='call' && fixtureArguments(entry.inputs)!==null);
  const readArgs=read?fixtureArguments(read.inputs):null;
  if(!read || !constructorArgs || !sendArgs || !readArgs)return null;
  const signature=(entry:SolidityProbeDeclaration)=>entry.selector.split('.').at(-1)+'('+entry.inputs.join(',')+')';
  return {constructorArgs,steps:[
    {operation:'observe' as const,function:signature(read),args:readArgs},
    {operation:'send' as const,function:signature(selected),args:sendArgs},
    {operation:'observe' as const,function:signature(read),args:readArgs}
  ]};
}
