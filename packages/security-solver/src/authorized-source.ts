import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join } from "node:path";

const execute = promisify(execFile);

import { authorizedSourceUrls } from "@bounty/core";
export { authorizedSourceUrls };

export async function cloneAuthorizedSource(url: string, destination: string, options: { signal?: AbortSignal; commit?: string } = {}): Promise<void> {
  if (!authorizedSourceUrls([{assetType:"SOURCE_CODE", eligibleForBounty:true,
    assetIdentifier:url}]).includes(url)) throw new Error("Invalid authorized source repository URL");
  if (options.commit && !/^[a-f0-9]{40}$/.test(options.commit)) throw new Error("Invalid recorded source commit");
  options.signal?.throwIfAborted();
  // Do not inherit credential helpers, URL rewrite rules, hooks, or a global
  // Git configuration from the operator's shell. Never execute repository code.
  const env = {...process.env};
  for (const key of Object.keys(env)) if (key.startsWith("GIT_")) delete env[key];
  const gitConfig = ["-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
    "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "-c", "http.followRedirects=false"];
  const execution = {
    cwd: join(destination, ".."), timeout: 90_000, maxBuffer: 256 * 1024, signal: options.signal,
    env: {...env, GIT_CONFIG_NOSYSTEM:"1", GIT_CONFIG_GLOBAL:"/dev/null",
      GIT_TERMINAL_PROMPT:"0", GIT_LFS_SKIP_SMUDGE:"1"},
  };
  await execute("git", [...gitConfig, "clone", "--depth", "1", "--single-branch", "--", url, destination], execution);
  if (options.commit) {
    options.signal?.throwIfAborted();
    await execute("git", [...gitConfig, "fetch", "--depth", "1", "--no-tags", "--", "origin", options.commit],
      {...execution, cwd: destination});
    await execute("git", [...gitConfig, "checkout", "--detach", options.commit], {...execution, cwd: destination});
  }
}
