/** Distinguish a finished CLI process from completed real-world coverage.
 * Zero findings is permitted; unexecuted/partial investigations are not green. */
export function oneBountyOutcomeExitCode(
  workflowStatus:string,coverageStatus:string
):number {
  if(workflowStatus!=='completed')return 1;
  return coverageStatus==='completed'?0:3;
}
