import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import { withPipeline, runSequentialPass, readPipelineStatus, writePipelineStatus } from "../packages/core/src/pipeline";
import { compareProgramDifficulty, estimateProgramDifficulty } from "../packages/security-solver/src/program-selection";
import type { SecurityProgram } from "../packages/core/src/db/schema";
const root=mkdtempSync(join(tmpdir(),"autohack-sequential-"));
process.env.PROJECT_ROOT=root;process.env.AUTOHACK_SEQUENTIAL_PIPELINE="true";
const events:string[]=[];
let started!:()=>void;const firstStarted=new Promise<void>(r=>{started=r;});
const tick=()=>new Promise(r=>setTimeout(r,40));
try {
  await Promise.all([withPipeline(async()=>{
    started();
    await runSequentialPass({analyze:async()=>{events.push("analysis");await tick();},
      recover:async()=>{events.push("recover");},programs:()=>["a","b","c"],enabled:()=>true,eligible:()=>true,available:()=>true,
      hunt:async p=>{events.push("hunt:"+p);await withPipeline(tick);if(p==="a")throw Error("fixture failure");},
      review:async p=>{events.push("review:"+p);await tick();},failed:()=>{events.push("failed");}});
    events.push("pass-done");
  }), (async()=>{await firstStarted;await withPipeline(async()=>{events.push("manual");});})()]);
  assert.deepEqual(events,["analysis","recover","hunt:a","failed","review:a","hunt:b","review:b","hunt:c","review:c","pass-done","manual"]);
  let enabled=true;events.length=0;
  await runSequentialPass({analyze:async()=>{},recover:async()=>{},programs:()=>[1,2],enabled:()=>enabled,eligible:()=>true,available:()=>true,
    hunt:async()=>{events.push("hunt");enabled=false;},review:async()=>{events.push("review");},failed:()=>{}});
  assert.deepEqual(events,["hunt","review"],"Pause drains the active program and prevents the next dispatch");
  events.length=0;
  await runSequentialPass({analyze:async()=>{events.push("analysis");},recover:async()=>{events.push("recover");},programs:()=>[1],enabled:()=>true,eligible:()=>true,available:()=>false,
    hunt:async()=>{events.push("unexpected");},review:async()=>{},failed:()=>{}});
  assert.deepEqual(events,["analysis","recover"],"Quota must not block analysis or pending report recovery");
  const fixture=(id:string,reward:number,fit:number,breadth:number)=>({id,rewardMaxCents:reward,scopeSummary:JSON.stringify({
    scopes:[{assetType:"SOURCE_CODE"}],assessment:{rubric:{techStackMatch:fit,sourceCodeQuality:3,scopeBreadth:breadth}}})} as SecurityProgram);
  const easy=fixture("easy",150000,3,0),hard=fixture("hard",1000000000,1,3),expensive=fixture("same-difficulty",1000000000,3,0);
  assert.ok(estimateProgramDifficulty(easy)<estimateProgramDifficulty(hard));
  assert.deepEqual([hard,expensive,easy].sort(compareProgramDifficulty).map(p=>p.id),["easy","same-difficulty","hard"]);
  assert.equal(estimateProgramDifficulty(easy),estimateProgramDifficulty(expensive),"Payout is only a tie-breaker");
  writePipelineStatus({phase:"analyzing",total:5,completed:2});assert.equal(readPipelineStatus()?.completed,2);
  // A real second Node process must wait for this process's full workflow lock.
  let child:ReturnType<typeof spawn>|undefined;let output="";
  await withPipeline(async()=>{
    const source=`import {withPipeline} from ${JSON.stringify(resolve("packages/core/src/pipeline.ts"))};await withPipeline(async()=>console.log('ACQUIRED'));`;
    child=spawn(process.execPath,["--import","tsx","--input-type=module","-e",source],{env:process.env,stdio:["ignore","pipe","inherit"]});
    child.stdout!.on("data",d=>{output+=d;});
    await new Promise(r=>setTimeout(r,500));assert.equal(output,"");
  });
  await new Promise<void>((resolve,reject)=>{child!.on("error",reject);child!.on("close",code=>code===0?resolve():reject(Error("child failed")));});
  assert.match(output,/ACQUIRED/);
  console.log("Sequential pipeline: ordered stages, failure continuation, pause, quota recovery, difficulty ranking and cross-process exclusion PASSED");
} finally {rmSync(root,{recursive:true,force:true});}
