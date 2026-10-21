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

/** Read only bounded progress markers; never return target source/model prose. */
export async function readLocalActivity(dataDir:string,status:{active:boolean;startedAt?:string;currentActivity?:string;currentActivityDetail?:string;stage?:string}) {
  const fallback={task:status.currentActivity || (status.active?"Preparing source inspection":"No active source hunt"),
    detail:status.currentActivityDetail || "",lastProgressAt:null as string|null,language:null as string|null};
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
    return {task,detail,lastProgressAt:latest.info.mtime.toISOString(),language};
  }catch{return fallback;}
}
