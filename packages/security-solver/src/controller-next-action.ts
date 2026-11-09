/** Select actions the controller already knows exactly.
 * These requests are replayed through normal workflow/tool validation; no result
 * is fabricated and no source content is inferred from a model prediction.
 */
export type ControllerAction = {
  action:string;path:string;query:string;answer:string;
  offset?:number;hypothesis?:string;sequence?:unknown;result?:Record<string,unknown>
};
export type ActionConstraints=Partial<Record<'action'|'path'|'query'|'answer',string[]>>;

export function controllerOwnedNextAction(
  constraints:ActionConstraints|undefined,
  pending?:{path:string;query:string;answer:string;sequence?:unknown}|null
):ControllerAction|null {
  if(!constraints?.action || constraints.action.length!==1)return null;
  if(constraints.action[0]==='verify_source' && pending &&
    constraints.path?.length===1 && constraints.query?.length===1 && constraints.answer?.length===1 &&
    constraints.path[0]===pending.path && constraints.query[0]===pending.query &&
    constraints.answer[0]===pending.answer) {
    return {action:'verify_source',path:pending.path,query:pending.query,answer:pending.answer,
      ...(pending.sequence===undefined?{}:{sequence:pending.sequence})};
  }
  if(constraints.action[0]==='read_file' && constraints.path?.length===1) {
    return {action:'read_file',path:constraints.path[0],query:'',answer:'',offset:0};
  }
  if(constraints.action[0]==='read_solidity' &&
     constraints.path?.length===1 && constraints.query?.length===1) {
    return canonicalSourceNavigationAction({action:'read_solidity',path:constraints.path[0],
      query:constraints.query[0],answer:'',offset:0});
  }
  if(constraints.action[0]==='search_files' &&
     constraints.path?.length===1 && constraints.query?.length===1) {
    return {action:'search_files',path:constraints.path[0],query:constraints.query[0],answer:'',offset:0};
  }
  if(constraints.action[0]==='list_files' && constraints.path?.length===1) {
    return {action:'list_files',path:constraints.path[0],query:'',answer:'',offset:0};
  }
  if(constraints.action[0]==='outline_solidity' && constraints.path?.length===1) {
    return {action:'outline_solidity',path:constraints.path[0],query:'',answer:'',offset:0};
  }
  return null;
}

/** Correct a navigation action when a language-specific source operation was
 * requested for an incompatible extension. Actual pages still come from disk.
 */
export function canonicalSourceNavigationAction(action:ControllerAction):ControllerAction {
  if(['read_solidity','outline_solidity'].includes(action.action) && action.path &&
    !action.path.endsWith('.sol'))
    return {...action,action:'read_file',query:'',offset:0};
  return action;
}
