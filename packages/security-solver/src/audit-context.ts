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
  const result=[...pinned,...notes,...groups.flat()];
  if(JSON.stringify(result).length>budget)throw new Error("Latest audit exchange exceeds the context budget; narrow the probe output");
  return result;
}
export function auditCheckpoint(events:string[]):string {
  return JSON.stringify({version:1,notes:events.slice(-12),instruction:"Re-read evidence and rerun probes before reporting. These are progress notes, not evidence."});
}
