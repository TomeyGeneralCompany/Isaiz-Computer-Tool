/** A bounded pass is partial even when its selected probes succeed. */
export function selectSourceBatch(urls: string[], pass: number, size = 2): string[] {
  if (!urls.length) return [];
  const start = ((Number.isSafeInteger(pass) && pass >= 0 ? pass : 0) * size) % urls.length;
  return Array.from({length: Math.min(size, urls.length)}, (_, i) => urls[(start + i) % urls.length]);
}
export function incompleteProbeCoverage(session: {failedProbes:number; unsupportedProbes:number}): "failed" | "unsupported" {
  return session.failedProbes > 0 || session.unsupportedProbes === 0 ? "failed" : "unsupported";
}
