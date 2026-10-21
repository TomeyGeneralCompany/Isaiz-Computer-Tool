import assert from "node:assert/strict";
import {mkdtempSync,rmSync,writeFileSync,unlinkSync} from "node:fs";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {spawn} from "node:child_process";
import {once} from "node:events";
import {claimDailyHuntSlot,readDailyQuota} from "../packages/core/src/daily-hunt-limit";
import {claimSubmission,readSubmissionOutbox} from "../packages/core/src/submission-outbox";
const root=mkdtempSync(join(tmpdir(),"state-mutex-"));
try {
  const quota=join(root,"quota.json"),outbox=join(root,"outbox.json");
  assert.ok(claimDailyHuntSlot(10,quota));
  claimSubmission("first","fixture",{},outbox);
  for(const path of [quota,outbox]) {
    const source=`import {withStateMutex} from ${JSON.stringify(resolve("packages/core/src/state-mutex.ts"))};
      withStateMutex(${JSON.stringify(path)},()=>{process.stdout.write("LOCKED\\n");Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0);});`;
    const child=spawn(process.execPath,["--import","tsx","--input-type=module","-e",source],{stdio:["ignore","pipe","inherit"]});
    await once(child.stdout,"data");
    const exited=once(child,"exit");child.kill("SIGKILL");await exited;
    if(path===quota) {assert.ok(claimDailyHuntSlot(10,path));assert.equal(readDailyQuota(path)!.dispatched,2);}
    else {claimSubmission("second","fixture",{},path);assert.equal(readSubmissionOutbox(path).first.state,"started");}
  }
  const racePath=join(root,"race.json");
  const results=await Promise.all(Array.from({length:4},()=>new Promise<string>((resolveResult,reject)=>{
    const source=`import {claimDailyHuntSlot} from ${JSON.stringify(resolve("packages/core/src/daily-hunt-limit.ts"))};console.log(claimDailyHuntSlot(1,${JSON.stringify(racePath)}));`;
    const child=spawn(process.execPath,["--import","tsx","--input-type=module","-e",source],{stdio:["ignore","pipe","inherit"]});
    let out="";child.stdout.on("data",chunk=>out+=chunk);child.on("error",reject);
    child.on("exit",code=>code===0?resolveResult(out.trim()):reject(new Error("Child failed: "+code)));
  })));
  assert.equal(results.filter(x=>x==="true").length,1);assert.equal(readDailyQuota(racePath)!.dispatched,1);
  writeFileSync(quota+".lock","");assert.throws(()=>claimDailyHuntSlot(10,quota),/Legacy state lock/);unlinkSync(quota+".lock");
  console.log("Killed quota/outbox lock owners recover; concurrent claims serialize; submission history survives: PASSED");
} finally {rmSync(root,{recursive:true,force:true});}
