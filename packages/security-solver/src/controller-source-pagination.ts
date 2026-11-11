/** Completion is a property of the evidence actually delivered to the
 * controller, never of the larger raw page before context-budget fitting. */
export function deliveredSourcePageComplete(page:{
  end:number;totalCharacters:number;nextOffset?:number|null
}):boolean {
  return Number.isSafeInteger(page.end) && Number.isSafeInteger(page.totalCharacters) &&
    page.end===page.totalCharacters && page.nextOffset===null;
}
