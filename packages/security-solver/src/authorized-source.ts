import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";

const execute = promisify(execFile);

/** Repository roots only; never extract a command or URL from model prose. */
export function authorizedSourceUrls(scopes: unknown): string[] {
  if (!Array.isArray(scopes)) return [];
  return [...new Set(scopes.filter(scope => scope && scope.assetType === "SOURCE_CODE"
    && scope.eligibleForBounty === true && typeof scope.assetIdentifier === "string")
    .map(scope => scope.assetIdentifier as string)
    .filter(url => /^https:\/\/(github\.com|gitlab\.com|bitbucket\.org)\/[A-Za-z0-9_][A-Za-z0-9_.-]*\/[A-Za-z0-9_][A-Za-z0-9_.-]*(?:\/)?$/.test(url))
    .map(url => url.replace(/\/$/, "")))];
}

export async function cloneAuthorizedSource(url: string, destination: string): Promise<void> {
  if (!authorizedSourceUrls([{assetType:"SOURCE_CODE", eligibleForBounty:true,
    assetIdentifier:url}]).includes(url)) throw new Error("Invalid authorized source repository URL");
  // Do not inherit credential helpers, URL rewrite rules, hooks, or a global
  // Git configuration from the operator's shell. Never execute repository code.
  const env = {...process.env};
  for (const key of Object.keys(env)) if (key.startsWith("GIT_")) delete env[key];
  await execute("git", ["-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
    "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "-c", "http.followRedirects=false",
    "clone", "--depth", "1", "--single-branch", "--", url, destination], {
    cwd: join(destination, ".."), timeout: 90_000, maxBuffer: 256 * 1024,
    env: {...env, GIT_CONFIG_NOSYSTEM:"1", GIT_CONFIG_GLOBAL:"/dev/null",
      GIT_TERMINAL_PROMPT:"0", GIT_LFS_SKIP_SMUDGE:"1"},
  });
}
