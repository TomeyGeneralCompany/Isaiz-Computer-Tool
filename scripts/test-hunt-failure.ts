/** Own temporary SQLite, fake Git and intercepted model; no target traffic. */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, chmodSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
const root = mkdtempSync(join(tmpdir(), "autohack-failed-hunt-"));
const originalFetch = globalThis.fetch;
const originalPath = process.env.PATH;
const originalUrl = process.env.AUTOHACK_OLLAMA_URL;
let modelCalls = 0;
let answer = "Incomplete owned fixture output";
const model = createServer(async (req,res) => {
  let raw="";for await(const part of req) raw+=part.toString();
  const request=JSON.parse(raw);modelCalls++;
  const hasRead=request.messages.some((message:{content:string}) => message.content.includes("TOOL_RESULT") && message.content.includes("ownedFixture"));
  res.end(JSON.stringify({message:{role:"assistant",content:JSON.stringify(hasRead
    ? {action:"final",path:"",query:"",answer}
    : {action:"read_file",path:"source-1/sample.cjs",query:"",answer:""})}}));
});
process.env.PROJECT_ROOT = root;
process.env.DB_PATH = join(root, "data", "fixture.sqlite");
process.env.GITHUB_TOKEN = "owned-offline-fixture";
process.env.LOCAL_OLLAMA_MODEL = "owned-mock";
process.env.SECURITY_AUTO_SUBMIT = "false";
process.env.LOCAL_HUNT_MAX_TURNS = "4";
try {
  await new Promise<void>(resolve=>model.listen(0,"127.0.0.1",resolve));
  const address=model.address();assert.ok(address && typeof address !== "string");
  process.env.AUTOHACK_OLLAMA_URL=`http://127.0.0.1:${address.port}/api/chat`;
  execFileSync(process.execPath, ["--import", "tsx", "scripts/initialize-db.ts"], {stdio:"pipe"});
  mkdirSync(join(root, "bin"));
  const git = join(root, "bin", "git");
  writeFileSync(git, "#!/bin/sh\nexit 42\n");
  chmodSync(git, 0o700);
  process.env.PATH = join(root, "bin") + ":" + originalPath;
  globalThis.fetch = (async () => { throw new Error("Unexpected outbound fetch in owned fixture"); }) as typeof fetch;
  const { getDb, schema } = await import("../packages/core/src/db/index");
  const { huntProgram } = await import("../packages/security-solver/src/index");
  const db = getDb();
  const now = new Date();
  db.insert(schema.securityPrograms).values({id:"owned-failure",provider:"fixture",
    name:"Owned source acquisition failure",status:"active",discoveredAt:now,updatedAt:now,
    scopeSummary:JSON.stringify({scopes:[{assetType:"SOURCE_CODE",eligibleForBounty:true,
      assetIdentifier:"https://github.com/fixture/owned"}]})}).run();
  const program = db.select().from(schema.securityPrograms).get()!;
  // A live cross-process lock must reject auto dispatch before consuming quota.
  const {readDailyQuota,claimDailyHuntSlot,setRuntimeOverride} = await import("../packages/core/src/index");
  writeFileSync(join(root,"data","security-hunt.lock"),JSON.stringify({pid:process.pid,token:"other-owner"}));
  await assert.rejects(huntProgram(program,"auto"),/already busy/);
  assert.equal(readDailyQuota(),null);
  const {unlinkSync}=await import("node:fs");unlinkSync(join(root,"data","security-hunt.lock"));
  setRuntimeOverride("SECURITY_MAX_DAILY_HUNTS",1);
  claimDailyHuntSlot(1);
  await assert.rejects(huntProgram(program,"auto"),/Daily dispatch limit/);
  assert.equal(db.select().from(schema.securityPrograms).get()!.scopeSummary,program.scopeSummary,"Quota refusal must not change hunt history");
  setRuntimeOverride("SECURITY_MAX_DAILY_HUNTS",8);
  const outcome = await huntProgram(program,"auto").then(() => null, error => error);
  const after = db.select().from(schema.securityPrograms).get()!;
  assert.equal(after.lastHuntedAt, null, "Failed acquisition must not mark a program previously hunted");
  assert.equal(after.huntCount, 0);
  assert.equal(JSON.parse(after.scopeSummary!).inspectionPass,1,"Even a failed pass advances repository selection");
  assert.equal(after.huntMissStreak, 0);
  assert.match(String(outcome), /No authorized source repository (?:was )?acquired/);
  assert.equal(readDailyQuota()!.dispatched,1,"Acquisition failures must not consume inspection quota");
  assert.equal(modelCalls, 0, "A model cannot audit source that was never acquired");
  // Successful acquisition with incomplete model output is also a failed hunt.
  writeFileSync(git, `#!/usr/bin/env python3
import pathlib, sys
if "ls-files" in sys.argv:
    sys.stdout.write("sample.cjs" + chr(0))
elif "rev-parse" in sys.argv:
    print("a" * 40)
else:
    root = pathlib.Path(sys.argv[-1])
    root.mkdir(parents=True)
    (root / "sample.cjs").write_text("exports.ownedFixture = true;" )
`);
  await assert.rejects(huntProgram(program), /inspection limit/);
  assert.equal(db.select().from(schema.securityPrograms).get()!.lastHuntedAt, null);
  answer = JSON.stringify({findings:[]});
  // A read-only model answer without a completed probe is incomplete coverage.
  await assert.rejects(huntProgram(program), /inspection limit/);
  const incomplete = db.select().from(schema.securityPrograms).get()!;
  assert.equal(incomplete.lastHuntedAt, null);
  assert.equal(incomplete.huntCount, 0);
  assert.equal(JSON.parse(incomplete.scopeSummary!).huntCoverage.status, "failed");
  answer=JSON.stringify({findings:[],outcome:"no_testable_candidate",reason:"Inspected sample source; it exposes a boolean and no supported function candidate."});
  assert.deepEqual(await huntProgram(program,"auto"),{findingsCreated:0});
  assert.equal(readDailyQuota()!.dispatched,2,"A model inspection consumes exactly one slot");
  assert.equal(JSON.parse(db.select().from(schema.securityPrograms).get()!.scopeSummary!).huntCoverage.status,"partial");
  // A complete unsupported inventory is stored without consuming model turns.
  const previousCalls=modelCalls;
  writeFileSync(git,readFileSync(git,"utf8").replaceAll("sample.cjs","sample.ts"));
  await assert.rejects(huntProgram(program,"auto"), /Source capability preflight/);
  assert.equal(readDailyQuota()!.dispatched,2,"Unsupported inventory must not consume inspection quota");
  assert.equal(modelCalls,previousCalls);
  const unsupported=JSON.parse(db.select().from(schema.securityPrograms).get()!.scopeSummary!);
  assert.equal(unsupported.huntCoverage.status,"unsupported");
  assert.ok(unsupported.capabilityBlock);
  assert.equal(unsupported.sourceCapabilities.checks["https://github.com/fixture/owned"].blocked,true);
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
  model.closeAllConnections();model.close();
  if(originalUrl === undefined) delete process.env.AUTOHACK_OLLAMA_URL;
  else process.env.AUTOHACK_OLLAMA_URL=originalUrl;
  globalThis.fetch = originalFetch;
  process.env.PATH = originalPath;
  rmSync(root, {recursive:true,force:true});
}
