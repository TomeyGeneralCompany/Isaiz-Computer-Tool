/** A forced Solidity outline starts at item zero, not at the previous read_file
 * character cursor. Optional model-selected outline pagination retains its offset.
 */
export function normalizeForcedOutlineCursor(
  action:string, offset:number, allowedActions?:readonly string[]
):number {
  return action==='outline_solidity' &&
    allowedActions?.length===1 && allowedActions[0]==='outline_solidity' ? 0 : offset;
}
