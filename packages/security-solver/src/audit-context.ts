export type AuditMessage={role:string;content:string;tool_name?:string;tool_calls?:Array<{function:{name:string;arguments:Record<string,unknown>}}>};
/** Allocate instructions, schema, controller and one useful exchange together.
 * numPredict is a ceiling, not a reservation that may crowd out required input.
 */
export function allocateAuditContext(pinned:AuditMessage[],schema:unknown,numCtx:number,numPredict:number,controllerReserve=0) {
  const pinnedSize=JSON.stringify(pinned).length;
  const schemaSize=JSON.stringify(schema).length;
  const exchangeReserve=controllerReserve ? 3000 : 800;
  const maximumOutput=Math.floor(numCtx-512-(pinnedSize+schemaSize+controllerReserve+exchangeReserve)/3);
  const generationBudget=Math.min(numPredict,maximumOutput);
  if(generationBudget<Math.min(numPredict,256))throw new Error('Audit instructions leave no usable context; move large task data into paginated workspace files');
  const contextBudget=(numCtx-generationBudget-512)*3;
  return {generationBudget,contextBudget,messageBudget:contextBudget-schemaSize};
}
export function latestAuditExchangeStart(messages:AuditMessage[]):number {
  let latestStart=messages.length;
  for(let i=2;i<messages.length;i++) {
    const message=messages[i];
    if(message.role==="assistant" || latestStart===messages.length ||
      (message.role==="user" && !message.content.startsWith("TOOL_RESULT ")))latestStart=i;
  }
  return latestStart;
}
/** Keep pinned instructions and whole recent exchanges. Estimates reserve room for output. */
export function compactAuditContext(messages:AuditMessage[],budget:number,progress:string[]=[]):AuditMessage[] {
  const pinned=messages.slice(0,2);
  if(JSON.stringify(pinned).length>budget)throw new Error("Audit instructions exceed the context budget; narrow the investigation");
  const groups:AuditMessage[][]=[];
  for(const message of messages.slice(2)) {
    // A standalone correction is not part of an earlier completed exchange.
    // Otherwise repeated rejected actions accumulate in one unevictable group.
    if(message.role==='assistant' || !groups.length ||
      (message.role==='user' && !message.content.startsWith('TOOL_RESULT ')))groups.push([]);
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
  let result=[...pinned,...notes,...groups.flat()];
  // A correctly fitted result can become too large when a subsequent
  // controller correction joins the latest exchange. Preserve the assistant
  // action, source references and audit archive; evict only the oversized
  // previous TOOL_RESULT payload from active model context. Never fabricate
  // an abbreviated source page or claim those bytes remain in context.
  if(JSON.stringify(result).length>budget){
    const latest=groups.at(-1);
    if(latest){
      for(let i=latest.length-1;i>=0 && JSON.stringify(result).length>budget;i--){
        const message=latest[i];
        if(message.role!=='user'||!message.content.startsWith('TOOL_RESULT '))continue;
        const firstLine=message.content.split('\n')[0].slice('TOOL_RESULT '.length);
        let toolName='unknown',caseId:string|undefined;
        try {
          const packet=JSON.parse(firstLine);
          if(typeof packet?.name==='string')toolName=packet.name;
          const output=typeof packet?.output==='string' ? JSON.parse(packet.output) : packet?.output;
          if(typeof output?.caseId==='string'&&/^[a-f0-9]{64}$/.test(output.caseId))caseId=output.caseId;
        }catch{}
        latest[i]={role:'user',content:'TOOL_RESULT '+JSON.stringify({
          name:toolName,contextEvicted:true,...(caseId?{caseId}:{}),
          message:'Previous tool payload archived outside the active context; do not infer its contents. Re-read the indexed source or recorded evidence if needed.'
        })+' /no_think'};
        result=[...pinned,...notes,...groups.flat()];
      }
    }
  }
  if(JSON.stringify(result).length>budget){
    // A standalone model action or controller correction can itself be larger
    // than the remaining window, even after old exchanges and TOOL_RESULT
    // payloads have been evicted. The caller records *all* replaced messages
    // in its append-only exchange archive before inference proceeds. Do not
    // silently truncate source or imply that omitted evidence was examined.
    const latest=groups.at(-1);
    if(latest){
      latest.splice(0,latest.length,{role:'user',content:
        'CONTEXT_EXCHANGE_EVICTED: The most recent oversized exchange is unavailable in active model context. '+
        'Its original is preserved by the controller audit archive. Do not assume its evidence or instructions are still in context. '+
        'Follow the current controller constraints and re-read indexed source or recorded evidence before relying on it. /no_think'});
      result=[...pinned,...notes,...groups.flat()];
      if(JSON.stringify(result).length>budget) {
        // The note is optional; pinned instructions still govern any retry.
        groups.pop();
        result=[...pinned,...notes,{role:'user',content:
          'CONTEXT_EXCHANGE_EVICTED: Previous oversized exchange archived. Re-read required evidence and follow current stage constraints. /no_think'}];
      }
    }
  }
  if(JSON.stringify(result).length>budget)throw new Error("Audit pinned instructions and controller reserve exceed context budget (budget="+budget+")");
  return result;
}
/** Keep a current controller instruction out of the evictable historical tier.
 * Required tail messages are appended AFTER compaction; they never enter
 * the archival history and cannot be replaced by CONTEXT_EXCHANGE_EVICTED.
 * Count the output schema adjustment and pre-existing controller reservation.
 */
export function compactAuditContextWithRequiredTail(
  history:AuditMessage[],messageBudget:number,requiredTail:AuditMessage[],
  schemaExtra:number,controllerReserve:number,notes:string[]=[]
):{history:AuditMessage[];requestMessages:AuditMessage[];historyBudget:number} {
  const tailChars=requiredTail.length?JSON.stringify(requiredTail).length+1:0;
  const historyBudget=messageBudget-Math.max(tailChars+schemaExtra,controllerReserve);
  if(historyBudget<=JSON.stringify(history.slice(0,2)).length)
    throw new Error('CONTROLLER_REQUIRED_INSTRUCTION_EXCEEDS_CONTEXT_BUDGET');
  const kept=compactAuditContext(history,historyBudget,notes);
  const requestMessages=[...kept,...requiredTail];
  if(JSON.stringify(requestMessages).length+schemaExtra>messageBudget)
    throw new Error('CONTROLLER_REQUEST_EXCEEDS_CONTEXT_BUDGET');
  return {history:kept,requestMessages,historyBudget};
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
    candidate=size=>JSON.stringify({truncated:true,caseId:data?.caseId,evidenceFile:data?.evidenceFile,status:data?.status,
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
