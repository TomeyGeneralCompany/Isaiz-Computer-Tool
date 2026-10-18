/** Actual fresh-directory schema creation and Drizzle's false-success defense. */
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import Database from "better-sqlite3";
const directory = mkdtempSync(join(tmpdir(), "autohack-db-init-"));
try {
  const path = join(directory, "previously-missing", "nested", "fixture.sqlite");
  const env = {...process.env, PROJECT_ROOT:directory, DB_PATH:path};
  const first = spawnSync(process.execPath, ["--import","tsx","scripts/initialize-db.ts"], {env,encoding:"utf8",timeout:180000});
  assert.equal(first.status,0,first.stdout+first.stderr);
  const db = new Database(path, {readonly:true, fileMustExist:true});
  assert.ok(db.prepare("SELECT name FROM sqlite_master WHERE name='security_findings'").get());
  db.close();
  const bin = join(directory,"bin");
  mkdirSync(bin);
  writeFileSync(join(bin,"npm"),"#!/usr/bin/env bash\n# Simulate Drizzle printing an error but returning success.\necho 'Fixture connection error' >&2\nexit 0\n");
  chmodSync(join(bin,"npm"),0o700);
  const empty = join(directory,"empty.sqlite");
  new Database(empty).close();
  const failed = spawnSync(process.execPath,["--import","tsx","scripts/initialize-db.ts"],{
    env:{...env, DB_PATH:empty, PATH:bin+":"+process.env.PATH},encoding:"utf8",timeout:10000,
  });
  assert.equal(failed.status,1,failed.stdout+failed.stderr);
  assert.match(failed.stderr,/setup stopped before acceptance/);
  console.log("Fresh nested database directory created; false-success schema command rejected");
} finally {rmSync(directory,{recursive:true,force:true});}
