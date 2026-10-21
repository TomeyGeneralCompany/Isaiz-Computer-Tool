import {open,readdir,stat} from "node:fs/promises";
import {join} from "node:path";

let cachedLog:{startedAt:string;name:string}|null=null;

export function describeHuntFailure(detail:unknown) {
  const reason=typeof detail==="string" ? detail.slice(0,2000)
    .replace(/(Bearer\s+)[^\s]+/gi,"$1[redacted]")
    .replace(/(https?:\/\/)[^/\s@]+:[^/\s@]+@/gi,"$1[redacted]@") : "";
  const stage=/reproduction|probe|solc|sandbox/i.test(reason)?"Source reproduction":
    /ollama|model|inference|JSON action|inspection limit/i.test(reason)?"Model inspection":
    /acquir|clone|git |repository was acquired/i.test(reason)?"Source download":"Hunt attempt";
  return {stage,reason:reason || "The original failure reason was not retained for this attempt."};
}


export function parseWorkEvents(text:string) {
  const events:Array<{at:string|null;tool:string;phase:string;title:string;detail:string;status?:string;durationMs?:number}>=[];
  const labels:Record<string,string>={read_file:"Read source file",search_files:"Searched source",
    list_files:"Listed source files",verify_source:"Reproduction test",verify_python:"Reproduction test"};
  const statuses:Record<string,string>={behavior_observed:"Behavior reproduced — requires review",
    behavior_not_observed:"Behavior not reproduced",probe_failed:"Test could not run successfully",
    timeout:"Test timed out",invalid_probe:"Unsupported probe",
    unsupported_dependencies:"Dependencies unsupported",blocked_no_runtime:"Runtime unavailable",
    blocked_no_sandbox:"Sandbox unavailable"};
  const hasStructured=text.includes("[ACTIVITY] ");
  for(const line of text.split("\n")){
    if(line.startsWith("[ACTIVITY] ")){
      try {
        const value=JSON.parse(line.slice(11));
        if(!Object.prototype.hasOwnProperty.call(labels,value.tool)||!["started","completed","failed"].includes(value.phase))continue;
        const path=typeof value.path==="string"?value.path.slice(0,500):"";
        const query=typeof value.query==="string"?value.query.slice(0,120):"";
        let detail=path;
        if(value.tool==="search_files")detail=JSON.stringify(query)+(value.phase==="completed"&&Number.isSafeInteger(value.count)?" · "+value.count+" matches":"");
        else if(value.tool.startsWith("verify_"))detail=[path,query,typeof value.kind==="string"?value.kind.slice(0,80):""].filter(Boolean).join(" · ");
        if(value.phase==="failed")detail+=" · "+describeHuntFailure(value.error).reason;
        events.push({at:typeof value.at==="string"&&Number.isFinite(Date.parse(value.at))?value.at:null,
          tool:value.tool,phase:value.phase,
          title:(value.phase==="started"?"Started: ":value.phase==="failed"?"Failed: ":"")+labels[value.tool],
          detail,status:typeof value.status==="string"?(statuses[value.status] || "Test returned: "+value.status.slice(0,100)):undefined,
          durationMs:typeof value.durationMs==="number"&&Number.isFinite(value.durationMs)?Math.max(0,value.durationMs):undefined});
      }catch{}
    } else if(!hasStructured && line.startsWith("[TOOL] ")){
      const tool=line.slice(7).trim();
      if(tool==="search_files"||tool==="verify_source"||tool==="verify_python")events.push({at:null,tool,phase:"started",title:tool==="search_files"?"Search requested":"Reproduction requested",detail:"This running worker did not record the query or result."});
    } else if(line.startsWith("[READ_OK] ")){
      events.push({at:null,tool:"read_file",phase:"completed",title:"Read source file",detail:line.slice(10,510)});
    }
  }
  const deduped=events.filter((event,i)=>!(event.at===null&&event.tool==="read_file"&&
    events.slice(i+1,i+3).some(next=>next.tool==="read_file"&&next.phase==="completed"&&next.detail===event.detail&&next.at)));
  const completed=deduped.filter(e=>e.phase==="completed");
  return {events:deduped.slice(-16).reverse(),counts:{
    filesRead:completed.filter(e=>e.tool==="read_file").length,
    searches:completed.filter(e=>e.tool==="search_files").length,
    tests:completed.filter(e=>e.tool.startsWith("verify_")).length}};
}

/** Read only bounded progress markers; never return target source/model prose. */
export async function readLocalActivity(dataDir:string,status:{active:boolean;startedAt?:string;currentActivity?:string;currentActivityDetail?:string;stage?:string}) {
  const fallback={task:status.currentActivity || (status.active?"Preparing source inspection":"No active source hunt"),
    detail:status.currentActivityDetail || "",lastProgressAt:null as string|null,language:null as string|null,...parseWorkEvents("")};
  if(!status.active || !status.startedAt)return fallback;
  const started=Date.parse(status.startedAt);
  if(!Number.isFinite(started))return fallback;
  try {
    const directory=join(dataDir,"logs");
    const files=(cachedLog?.startedAt===status.startedAt ? [cachedLog.name] : await readdir(directory)).filter(n=>/^local-hunt-[a-f0-9]+\.log$/.test(n));
    // File names do not contain timestamps. Use metadata and reject older runs.
    const candidates=await Promise.all(files.map(async name=>{
      try {const info=await stat(join(directory,name));return {name,info};}catch{return null;}
    }));
    const latest=candidates.filter((x):x is NonNullable<typeof x>=>!!x && x.info.mtimeMs>=started)
      .sort((a,b)=>b.info.mtimeMs-a.info.mtimeMs)[0];
    if(!latest)return fallback;
    cachedLog={startedAt:status.startedAt,name:latest.name};
    const file=await open(join(directory,latest.name),"r");
    let text="";
    try {
      const size=Math.min(latest.info.size,32768);
      const bytes=Buffer.alloc(size);
      const read=await file.read(bytes,0,size,Math.max(0,latest.info.size-size));
      text=bytes.subarray(0,read.bytesRead).toString("utf8");
    }finally{await file.close();}
    let workText=text;
    // Dedicated telemetry is written by the tool runner, separate from model prose.
    try {
      const telemetry=await open(join(directory,latest.name+".activity.jsonl"),"r");
      try {
        const info=await telemetry.stat();
        const size=Math.min(info.size,32768);
        const bytes=Buffer.alloc(size);
        const read=await telemetry.read(bytes,0,size,Math.max(0,info.size-size));
        workText=bytes.subarray(0,read.bytesRead).toString("utf8");
      }finally{await telemetry.close();}
    }catch{}
    let task=fallback.task,detail=fallback.detail,language:string|null=null;
    for(const line of text.split("\n")){
      if(line.startsWith("[READ_OK] ")){
        detail=line.slice(10,510);task="Inspecting source";
        const extension=/\.(py|js|mjs|cjs|sol)$/.exec(detail)?.[1];
        language=extension==="py"?"Python":extension==="sol"?"Solidity":extension?"JavaScript":null;
      }else if(line.startsWith("[TOOL] ")){
        const tool=line.slice(7).trim();detail="";language=null;
        task=tool==="verify_source"||tool==="verify_python"?"Running isolated reproduction":
          tool==="read_file"?"Reading source":tool==="search_files"?"Searching source":
          tool==="list_files"?"Listing source files":"Inspecting source";
      }else if(/^\[OLLAMA\].*request started/.test(line)){task="Waiting for local model";detail=line.match(/turn \d+\/\d+/)?.[0] || "";language=null;}
      else if(/^\[OLLAMA\].*response received/.test(line)){task="Processing model response";detail=line.slice(0,300);}
      else if(line.startsWith("[FINAL_REJECTED]")){task="Checking report evidence";detail="The model is revising an answer that did not meet the evidence checks.";}
    }
    return {task,detail,lastProgressAt:latest.info.mtime.toISOString(),language,...parseWorkEvents(workText)};
  }catch{return fallback;}
}
