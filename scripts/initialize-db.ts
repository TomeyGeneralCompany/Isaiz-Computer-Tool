import "dotenv/config";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import Database from "better-sqlite3";

const result = spawnSync("npm", ["run", "db:push"], {stdio:"inherit", timeout:180_000});
if (result.error || result.status !== 0) {
  console.error("Database schema initialization command failed; setup stopped.");
  process.exit(1);
}
// Drizzle can print a connection error yet exit zero. Check its actual result.
const path = resolve(process.env.PROJECT_ROOT || process.cwd(), process.env.DB_PATH || "data/bounty.db");
try {
  const db = new Database(path, {readonly:true, fileMustExist:true});
  try {
    const tables = new Set((db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all() as {name:string}[]).map(row=>row.name));
    if (!["security_programs", "security_findings"].every(name=>tables.has(name)))
      throw new Error("Required application tables are missing");
  } finally {db.close();}
  console.log("Application database schema verified");
} catch {
  console.error("Application database was not initialized correctly; setup stopped before acceptance or service startup.");
  process.exitCode = 1;
}
