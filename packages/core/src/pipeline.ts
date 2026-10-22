import { AsyncLocalStorage } from "node:async_hooks";
import { acquireFileGate } from "./ollama-gate";
import { mkdirSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";

export function sequentialPipelineEnabled() { return process.env.AUTOHACK_SEQUENTIAL_PIPELINE !== "false"; }
const owned = new AsyncLocalStorage<boolean>();
/** One whole workflow across dashboard/orchestrator processes; nested stages reuse ownership. */
export async function withPipeline<T>(work:()=>Promise<T>):Promise<T> {
  if (!sequentialPipelineEnabled() || owned.getStore()) return work();
  const release=await acquireFileGate(new AbortController().signal,"sequential-pipeline.lock");
  try { return await owned.run(true,work); } finally { await release(); }
}
export interface PipelineStatus {
  phase:"analyzing"|"hunting"|"reviewing"|"waiting";
  total?:number; completed?:number; currentName?:string; detail?:string;
}
const statusPath=()=>join(process.env.PROJECT_ROOT || process.cwd(),"data","sequential-pipeline.json");
export function writePipelineStatus(status:PipelineStatus) {
  const path=statusPath();mkdirSync(join(path,".."),{recursive:true});
  const temp=path+"."+process.pid+".tmp";
  writeFileSync(temp,JSON.stringify({...status,pid:process.pid,updatedAt:Date.now()}),{mode:0o600});renameSync(temp,path);
}
export function readPipelineStatus():PipelineStatus|null {
  try {const value=JSON.parse(readFileSync(statusPath(),"utf8"));process.kill(value.pid,0);return value;} catch {return null;}
}
/** A fixed ranked pass: failure/review blockers do not strand later programs. */
export async function runSequentialPass<T>(steps:{
  analyze:()=>Promise<void>; recover:()=>Promise<void>; programs:()=>T[];
  enabled:()=>boolean; eligible:(program:T)=>boolean; available:()=>boolean;
  hunt:(program:T)=>Promise<void>; review:(program:T)=>Promise<void>;
  failed:(error:unknown,program:T)=>void;
}) {
  await steps.analyze();
  if (!steps.enabled()) return;
  await steps.recover();
  const programs=steps.programs();
  for (const program of programs) {
    if (!steps.enabled() || !steps.available()) break;
    if (!steps.eligible(program)) continue;
    try {await steps.hunt(program);} catch(error) {steps.failed(error,program);}
    // Drain reports even when the hunt failed after writing partial results.
    try {await steps.review(program);} catch(error) {steps.failed(error,program);}
  }
}
