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
