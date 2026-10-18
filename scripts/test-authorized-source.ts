import { mkdtemp, writeFile, readFile, chmod, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import { authorizedSourceUrls, cloneAuthorizedSource } from "../packages/security-solver/src/authorized-source";
const scope = (url: string, eligible = true) => ({assetType:"SOURCE_CODE", eligibleForBounty:eligible, assetIdentifier:url});
assert.deepEqual(authorizedSourceUrls([scope("https://github.com/owner/repo/"),
  scope("https://github.com/owner/repo"), scope("https://gitlab.com/owner/repo.git")]),
  ["https://github.com/owner/repo", "https://gitlab.com/owner/repo.git"]);
for (const url of ["file:///tmp/repo", "https://github.com/owner/repo;touch /tmp/pwned",
  "https://github.com/owner/repo$(id)", "https://github.com/owner/repo/tree/main",
  "https://github.com.evil.test/owner/repo", "https://user:pass@github.com/owner/repo",
  "https://github.com/../repo", "https://github.com/owner/repo?redirect=evil"]) {
  assert.deepEqual(authorizedSourceUrls([scope(url)]), []);
  await assert.rejects(cloneAuthorizedSource(url, "/tmp/unused"), /Invalid authorized/);
}
assert.deepEqual(authorizedSourceUrls([scope("https://github.com/owner/repo", false),
  {assetType:"URL", eligibleForBounty:true, assetIdentifier:"https://github.com/owner/repo"}]), []);
console.log("Authorized repository selection rejects unscoped URLs and shell input");

// Exercise the production execFile call through an owned fake Git executable.
// This proves argument boundaries and credential isolation without any network.
const dir = await mkdtemp(join(tmpdir(), "autohack-git-test-"));
const savedPath = process.env.PATH;
const savedGit = process.env.GIT_CONFIG_COUNT;
try {
  const bin = join(dir, "bin");
  await mkdir(bin);
  const git = join(bin, "git");
  await writeFile(git, `#!/usr/bin/env python3
import json, os, sys
with open(${JSON.stringify(join(dir, "git-call.json"))}, "w") as output:
    json.dump({"args":sys.argv[1:], "env":{k:v for k,v in os.environ.items() if k.startswith("GIT_")}}, output)
`);
  await chmod(git, 0o700);
  process.env.PATH = bin + ":" + savedPath;
  process.env.GIT_CONFIG_COUNT = "99";
  await cloneAuthorizedSource("https://github.com/owner/repo", join(dir, "checkout"));
  const call = JSON.parse(await readFile(join(dir, "git-call.json"), "utf8"));
  assert.deepEqual(call.args.slice(-3), ["--", "https://github.com/owner/repo", join(dir, "checkout")]);
  assert.ok(call.args.includes("http.followRedirects=false"));
  assert.equal(call.env.GIT_CONFIG_GLOBAL, "/dev/null");
  assert.equal(call.env.GIT_TERMINAL_PROMPT, "0");
  assert.equal(call.env.GIT_CONFIG_COUNT, undefined);
  console.log("Actual Git execution uses bounded argv and isolated credentials/configuration");
} finally {
  process.env.PATH = savedPath;
  if (savedGit === undefined) delete process.env.GIT_CONFIG_COUNT;
  else process.env.GIT_CONFIG_COUNT = savedGit;
  await rm(dir, {recursive:true, force:true});
}
