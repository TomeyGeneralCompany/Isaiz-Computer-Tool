/** Repository roots supplied by program scope, never URLs from model prose. */
export function authorizedSourceUrls(scopes: unknown): string[] {
  if (!Array.isArray(scopes)) return [];
  return [...new Set(scopes.filter(scope => scope && scope.assetType === "SOURCE_CODE"
    && scope.eligibleForBounty === true && typeof scope.assetIdentifier === "string")
    .map(scope => scope.assetIdentifier as string)
    .filter(url => /^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/[A-Za-z0-9_][A-Za-z0-9_.-]*\/[A-Za-z0-9_][A-Za-z0-9_.-]*(?:\/)?$/.test(url))
    .map(url => url.replace(/\/$/, "")))];
}
