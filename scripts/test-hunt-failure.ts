/** Own temporary SQLite, fake Git and intercepted model; no target traffic. */
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
const root = mkdtempSync(join(tmpdir(), "autohack-failed-hunt-"));
const originalFetch = globalThis.fetch;
const originalPath = process.env.PATH;
process.env.PROJECT_ROOT = root;
process.env.DB_PATH = join(root, "data", "fixture.sqlite");
process.env.GITHUB_TOKEN = "owned-offline-fixture";
process.env.LOCAL_OLLAMA_MODEL = "owned-mock";
process.env.SECURITY_AUTO_SUBMIT = "false";
try {
  execFileSync(process.execPath, ["--import", "tsx", "scripts/initialize-db.ts"], {stdio:"pipe"});
  mkdirSync(join(root, "bin"));
  const git = join(root, "bin", "git");
  writeFileSync(git, "#!/bin/sh\nexit 42\n");
  chmodSync(git, 0o700);
  process.env.PATH = join(root, "bin") + ":" + originalPath;
  let modelCalls = 0;
  globalThis.fetch = (async () => { modelCalls++; throw new Error("Owned model fixture unavailable"); }) as typeof fetch;
  const { getDb, schema } = await import("../packages/core/src/db/index");
  const { huntProgram } = await import("../packages/security-solver/src/index");
  const db = getDb();
  const now = new Date();
  db.insert(schema.securityPrograms).values({id:"owned-failure",provider:"fixture",
    name:"Owned source acquisition failure",status:"active",discoveredAt:now,updatedAt:now,
    scopeSummary:JSON.stringify({scopes:[{assetType:"SOURCE_CODE",eligibleForBounty:true,
      assetIdentifier:"https://github.com/fixture/owned"}]})}).run();
  const program = db.select().from(schema.securityPrograms).get()!;
  const outcome = await huntProgram(program).then(() => null, error => error);
  const after = db.select().from(schema.securityPrograms).get()!;
  assert.equal(after.lastHuntedAt, null, "Failed acquisition must not mark a program previously hunted");
  assert.equal(after.huntCount, 0);
  assert.equal(after.huntMissStreak, 0);
  assert.match(String(outcome), /No authorized source repository (?:was )?acquired/);
  assert.equal(modelCalls, 0, "A model cannot audit source that was never acquired");
  // Successful acquisition with incomplete model output is also a failed hunt.
  writeFileSync(git, `#!/usr/bin/env python3
import pathlib, sys
root = pathlib.Path(sys.argv[-1])
root.mkdir(parents=True)
(root / "sample.ts").write_text("export const ownedFixture = true;\\n")
`);
  let answer = "Incomplete owned fixture output";
  globalThis.fetch = (async (_input, init) => {
    const request = JSON.parse(String(init?.body));
    const hasRead = request.messages.some((message: {content:string}) =>
      message.content.includes("TOOL_RESULT") && message.content.includes("ownedFixture"));
    return Response.json({message:{role:"assistant",content:JSON.stringify(hasRead
      ? {action:"final",path:"",query:"",answer}
      : {action:"read_file",path:"source-1/sample.ts",query:"",answer:""})}});
  }) as typeof fetch;
  await assert.rejects(huntProgram(program), /inspection limit/);
  assert.equal(db.select().from(schema.securityPrograms).get()!.lastHuntedAt, null);
  answer = JSON.stringify({findings:[]});
  // A read-only model answer without a completed probe is incomplete coverage.
  await assert.rejects(huntProgram(program), /No supported function reproduction completed/);
  const incomplete = db.select().from(schema.securityPrograms).get()!;
  assert.equal(incomplete.lastHuntedAt, null);
  assert.equal(incomplete.huntCount, 0);
  assert.equal(JSON.parse(incomplete.scopeSummary!).huntCoverage.status, "unsupported");
  // Preserve an existing completed-hunt history when a later acquisition fails.
  const { eq } = await import("drizzle-orm");
  db.update(schema.securityPrograms).set({lastHuntedAt:now,huntCount:1,huntMissStreak:1})
    .where(eq(schema.securityPrograms.id,program.id)).run();
  const completed = db.select().from(schema.securityPrograms).get()!;
  assert.ok(completed.lastHuntedAt);
  assert.equal(completed.huntCount, 1);
  assert.equal(completed.huntMissStreak, 1);
  // A later failed attempt preserves the existing completed-hunt timestamp.
  writeFileSync(git, "#!/bin/sh\nexit 42\n");
  await assert.rejects(huntProgram(completed), /No authorized source repository (?:was )?acquired/);
  const preserved = db.select().from(schema.securityPrograms).get()!;
  assert.deepEqual(preserved.lastHuntedAt, completed.lastHuntedAt);
  assert.equal(preserved.huntCount, 1);
  assert.equal(preserved.huntMissStreak, 1);
  console.log("Acquisition failure, incomplete coverage and preserved history: PASSED");
} finally {
  globalThis.fetch = originalFetch;
  process.env.PATH = originalPath;
  rmSync(root, {recursive:true,force:true});
}
