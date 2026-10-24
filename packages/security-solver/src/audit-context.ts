export type AuditMessage={role:string;content:string;tool_name?:string;tool_calls?:Array<{function:{name:string;arguments:Record<string,unknown>}}>};
/** Keep pinned instructions and whole recent exchanges. Estimates reserve room for output. */
export function compactAuditContext(messages:AuditMessage[],budget:number,progress:string[]=[]):AuditMessage[] {
  const pinned=messages.slice(0,2);
  if(JSON.stringify(pinned).length>budget)throw new Error("Audit instructions exceed the context budget; narrow the investigation");
  const groups:AuditMessage[][]=[];
  for(const message of messages.slice(2)) {
    if(message.role==='assistant' || !groups.length)groups.push([]);
    groups.at(-1)!.push(message);
  }
  if(JSON.stringify(messages).length<=budget)return messages;
  // Refresh notes only when old exchanges are actually removed. Never rewrite
  // the pinned task on every turn: that discards the reusable prompt prefix.
  const notes:AuditMessage[]=progress.length ? [{role:"user",content:
    "Recent tool progress (not evidence; re-read as needed): "+JSON.stringify(progress)}] : [];
  while(groups.length>1 && JSON.stringify([...pinned,...notes,...groups.flat()]).length>budget)groups.shift();
  // Progress summaries are optional; never evict actual latest evidence for them.
  if(JSON.stringify([...pinned,...notes,...groups.flat()]).length>budget)notes.length=0;
  const result=[...pinned,...notes,...groups.flat()];
  if(JSON.stringify(result).length>budget)throw new Error("Latest audit exchange exceeds the context budget; narrow the probe output");
  return result;
}
export function auditCheckpoint(events:string[]):string {
  return JSON.stringify({version:1,notes:events.slice(-12),instruction:"Re-read evidence and rerun probes before reporting. These are progress notes, not evidence."});
}

/** Size the fully serialized exchange, including JSON escaping and tool wrappers. */
export function fitAuditToolOutput(pinned:AuditMessage[], request:AuditMessage, tool:string,
  output:string, budget:number, structured:boolean):{output:string;message:AuditMessage} {
  const wrap=(value:string):AuditMessage=> {
    let guidance='Choose the next JSON action.';
    if(tool==='read_file')try {
      const page=JSON.parse(value);
      if(typeof page.text==='string') guidance=page.nextOffset===null
        ? 'End of this file. Choose a relevant caller/search, a supported probe, or the permitted incomplete-inspection outcome. Do not restart this file without a specific evidence need.'
        : 'This file has more text. Continue at offset '+page.nextOffset+' if relevant; do not restart at offset 0.';
    }catch{}
    return structured
      ? {role:'user',content:'TOOL_RESULT '+JSON.stringify({name:tool,output:value})+'\n'+guidance+' /no_think'}
      : {role:'tool',tool_name:tool,content:value};
  };
  const fits=(value:string)=>JSON.stringify([...pinned,request,wrap(value)]).length<=budget;
  if(fits(output))return {output,message:wrap(output)};
  let data:any;try {data=JSON.parse(output);}catch{}
  let candidate:(size:number)=>string;
  let length:number;
  if(tool==='read_file' && typeof data?.text==='string' && Number.isSafeInteger(data.start)) {
    length=data.text.length;
    candidate=size=>JSON.stringify({...data,text:data.text.slice(0,size),end:data.start+size,
      nextOffset:data.start+size<data.totalCharacters?data.start+size:null});
  } else if(['read_solidity','outline_solidity'].includes(tool)) {
    // Never claim indexed source was read if it was not delivered intact.
    const error='Tool error: Indexed source exceeds available context. Use read_file with a page offset.';
    if(!fits(error))throw new Error('Audit instructions leave no room for a tool result');
    return {output:error,message:wrap(error)};
  } else {
    length=output.length;
    candidate=size=>JSON.stringify({truncated:true,caseId:data?.caseId,status:data?.status,
      behavior_observed:data?.behavior_observed,excerpt:output.slice(0,size),
      instruction:'Output abbreviated. Narrow the request; this excerpt is not complete evidence.'});
  }
  let low=0,high=length;
  while(low<high) {const mid=Math.ceil((low+high)/2);if(fits(candidate(mid)))low=mid;else high=mid-1;}
  const result=candidate(low);
  if(!fits(result) || (tool==='read_file' && length>0 && low===0))
    throw new Error('Audit instructions leave no room for a source page');
  return {output:result,message:wrap(result)};
}
