/** Own temporary SQLite only; verifies the diagnostic cannot modify persisted state. */
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import Database from "better-sqlite3";
const root = mkdtempSync(join(tmpdir(), "tomey-diagnostic-"));
const env = { ...process.env, PROJECT_ROOT: root, DB_PATH: join(root, "data/fixture.sqlite"), GITHUB_TOKEN: "fictional-only", IMMUNEFI_ENABLED: "true", SECURITY_AUTO_HUNT_ENABLED: "true", HACKERONE_ENABLED: "true", SKIP_SIGNAL_REQUIRED: "true", SKIP_PREVIOUSLY_HUNTED: "true" };
try {
  execFileSync(process.execPath, ["--import", "tsx", "scripts/initialize-db.ts"], { env, stdio: "pipe" });
  const db = new Database(env.DB_PATH);
  db.prepare("INSERT INTO security_programs (id, provider, name, scope_summary, reward_max_cents, status, discovered_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .run("fictional", "immunefi", "Flooperfloop", JSON.stringify({ scopes: [{ assetIdentifier: "https://github.com/fictional/flooperfloop", assetType: "SOURCE_CODE", eligibleForBounty: true }] }), 100000, "active", Math.floor(Date.now()/1000), Math.floor(Date.now()/1000));
  const inspectedScope = JSON.stringify({scopes: [{assetIdentifier:"https://github.com/fictional/flooperfloop", assetType:"SOURCE_CODE", eligibleForBounty:true}], assessment:{opportunityScore:0.8}});
  db.prepare("INSERT INTO security_programs (id,provider,name,scope_summary,reward_max_cents,status,discovered_at,updated_at,last_hunted_at,hunt_count,requires_signal) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
    .run("legacy", "immunefi", "Legacy fixture", inspectedScope, 100000, "active", Math.floor(Date.now()/1000), Math.floor(Date.now()/1000), Math.floor(Date.now()/1000)-48*3600, 7, 0);
  db.prepare("INSERT INTO security_programs (id,provider,name,scope_summary,reward_max_cents,status,discovered_at,updated_at,requires_signal) VALUES (?,?,?,?,?,?,?,?,?)")
    .run("signal", "hackerone", "Signal fixture", inspectedScope, 100000, "active", Math.floor(Date.now()/1000), Math.floor(Date.now()/1000), 1);
  db.close();
  const beforeFiles = readdirSync(join(root, "data")).sort();
  const beforeDb = readFileSync(env.DB_PATH);
  const report = JSON.parse(execFileSync(process.execPath, ["--import", "tsx", "scripts/diagnose-progress.ts"], { env, encoding: "utf8" }));
  assert.equal(report.selection.total, 3);
  assert.equal(report.selection.eligible, 2, "Legacy history and Signal submission settings must not empty local inspection queue");
  assert.equal(report.selection.firstBlockingReasonCounts.assessment_missing, 1);
  assert.equal(report.dailyQuota, "not_present");
  assert.ok(!JSON.stringify(report).includes("fictional-only"), "Do not print credentials");
  assert.deepEqual(readFileSync(env.DB_PATH), beforeDb, "Diagnostic must not alter the database");
  const addedFiles = readdirSync(join(root, "data")).filter(file => !beforeFiles.includes(file));
  assert.ok(addedFiles.every(file => /-shm$|-wal$/.test(file)), "No quota, status, report or configuration files may be written");
  console.log("Read-only diagnostic: isolated SQLite snapshot, credential omission and unchanged database: PASSED");
} finally { rmSync(root, { recursive: true, force: true }); }
