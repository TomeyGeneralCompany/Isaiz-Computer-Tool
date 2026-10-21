export type AuditMessage={role:string;content:string;tool_name?:string;tool_calls?:Array<{function:{name:string;arguments:Record<string,unknown>}}>};
/** Keep pinned instructions and whole recent exchanges. Estimates reserve room for output. */
export function compactAuditContext(messages:AuditMessage[],budget:number):AuditMessage[] {
  const pinned=messages.slice(0,2);
  if(JSON.stringify(pinned).length>budget)throw new Error("Audit instructions exceed the context budget; narrow the investigation");
  const groups:AuditMessage[][]=[];
  for(const message of messages.slice(2)) {
    if(message.role==='assistant' || !groups.length)groups.push([]);
    groups.at(-1)!.push(message);
  }
  while(groups.length>1 && JSON.stringify([...pinned,...groups.flat()]).length>budget)groups.shift();
  const result=[...pinned,...groups.flat()];
  if(JSON.stringify(result).length>budget)throw new Error("Latest audit exchange exceeds the context budget; narrow the probe output");
  return result;
}
export function auditCheckpoint(events:string[]):string {
  return JSON.stringify({version:1,notes:events.slice(-12),instruction:"Re-read evidence and rerun probes before reporting. These are progress notes, not evidence."});
}
