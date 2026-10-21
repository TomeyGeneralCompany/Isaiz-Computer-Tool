import Database from "better-sqlite3";
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

/** OS-released mutex; keep the JSON store and its existing recovery semantics. */
export function withStateMutex<T>(path:string, action:()=>T):T {
  mkdirSync(dirname(path), {recursive:true});
  // Old versions used an ownerless lock. Never guess whether an old writer is alive.
  if (existsSync(path + ".lock")) throw new Error(
    `Legacy state lock at ${path}.lock: stop all old service/dashboard processes and remove this stale lock before restarting`);
  const mutex = new Database(path + ".mutex.sqlite", {timeout:5000});
  try { return mutex.transaction(action).immediate(); }
  finally { mutex.close(); }
}
