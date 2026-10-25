/** Validate observations, never the hidden fixture answer key. */
export interface ReasoningProbe {
  path: string;
  fn: string;
  kind: string;
  status: string;
  observed: boolean;
}
export function validateReasoningEvidence(text: string, paths: string[], probes: ReasoningProbe[]): string | null {
  let value: any;
  try { value = JSON.parse(text); } catch { return 'Return JSON with a files array inside the final answer string.'; }
  if (!value || !Array.isArray(value.files)) return 'Return the requested files array.';
  if (value.files.length !== paths.length || paths.some(path => value.files.filter((f: any) => f?.path === path).length !== 1))
    return 'Return exactly one classification for each Python module in the workspace, without duplicates or extra files.';
  for (const path of paths) {
    const answer = value.files.find((f: any) => f.path === path);
    if (typeof answer.rawMarkup !== 'boolean' || typeof answer.reason !== 'string' || !answer.reason.trim())
      return 'Each classification needs a rawMarkup boolean and an evidence-based reason.';
    const completed = probes.filter(p => p.path === path && p.kind === 'html_reflection' &&
      ((p.status === 'behavior_observed' && p.observed === true) ||
       (p.status === 'behavior_not_observed' && p.observed === false)));
    if (!completed.length)
      return `Final answer deferred: no completed markup observation exists for ${path}. Choose the relevant formatting function from source and use verify_source to test the stated requirement. Failed, blocked, or unrelated tests do not establish the result. Do not guess a classification.`;
    const latest = completed.at(-1)!;
    if (answer.rawMarkup !== latest.observed)
      return `Final answer deferred: the classification for ${path} contradicts the recorded observation for ${latest.fn}. Reconcile your conclusion with the returned test result and source. If you tested the wrong function, select and test the relevant one. Do not treat the fixed HTML wrapper as evidence that untrusted input survives unescaped.`;
  }
  return null;
}
