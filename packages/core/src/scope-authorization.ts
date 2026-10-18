/**
 * Fail-closed allowlist for bounty assets. This is a preflight guard, not a
 * network sandbox. Active probing additionally needs request-level controls.
 */
export interface BountyScope {
  assetIdentifier: string;
  assetType?: string;
  eligibleForBounty?: boolean;
  eligibleForSubmission?: boolean;
}
function scopesFromJson(summary: string | null): BountyScope[] {
  try {
    const parsed: unknown = JSON.parse(summary || "");
    const raw = Array.isArray(parsed) ? parsed :
      parsed && typeof parsed === "object" && "scopes" in parsed ?
        (parsed as { scopes: unknown }).scopes : [];
    if (!Array.isArray(raw)) return [];
    return raw.filter((s): s is BountyScope => !!s && typeof s === "object"
      && typeof s.assetIdentifier === "string"
      && (s.eligibleForBounty === true || s.eligibleForSubmission === true));
  } catch { return []; }
}
function canonical(raw: string): URL | null {
  try {
    if (raw.startsWith("//") || /[\\\u0000-\u001f]/.test(raw)) return null;
    const url = new URL(raw);
    if (!["https:", "http:"].includes(url.protocol)
      || url.username || url.password || url.search || url.hash) return null;
    if (url.port && url.port !== "80" && url.port !== "443") return null;
    // Raw encoded separators can bypass path equality checks in downstream tools.
    if (/%2f|%5c|%2e/i.test(url.pathname)) return null;
    return url;
  } catch { return null; }
}

/** No wildcard widening or suffix tricks: exact host and approved path only. */
export function targetInExplicitScope(summary: string | null, target: string): boolean {
  const candidate = canonical(target);
  if (!candidate) return false;
  return scopesFromJson(summary).some(scope => {
    const identifier = canonical(scope.assetIdentifier);
    if (!identifier || identifier.protocol !== candidate.protocol
      || identifier.host !== candidate.host) return false;
    const a = identifier.pathname.replace(/\/+$/, "") || "/";
    const b = candidate.pathname.replace(/\/+$/, "") || "/";
    if (b === a) return true;
    // Only explicit source-code repository scopes allow individual file paths
    // under that repository, not arbitrary paths on the same host.
    return scope.assetType === "SOURCE_CODE" &&
      (identifier.hostname === "github.com" || identifier.hostname === "gitlab.com")
      && a !== "/" && b.startsWith(a + "/");
  });
}

export function assertAuthorizedProgram(summary: string | null): void {
  if (!scopesFromJson(summary).some(s => canonical(s.assetIdentifier)))
    throw new Error("Program has no explicitly eligible, URL-addressable scope");
}
export function assertAuthorizedTarget(summary: string | null, target: string): void {
  if (!targetInExplicitScope(summary, target))
    throw new Error("Target is not within an explicitly authorized program asset");
}
