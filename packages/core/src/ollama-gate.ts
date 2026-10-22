import { spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { resolve, dirname } from "node:path";

// The Python research worker uses the same flock. A dead client closes stdin,
// releasing the OS lock even if it was still waiting. No stale lock deletion.
const HOLDER = `import fcntl,os,select,sys,time
f=open(sys.argv[1], 'a')
while True:
    if select.select([sys.stdin],[],[],0)[0]:
        sys.exit(0)
    try:
        fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        break
    except BlockingIOError:
        time.sleep(0.05)
print('LOCKED',flush=True)
sys.stdin.read()
`;
export async function acquireOllamaGate(signal:AbortSignal):Promise<()=>Promise<void>> {
  signal.throwIfAborted();
  const path=resolve(process.env.PROJECT_ROOT || process.env.AUTOHACK_ROOT || process.cwd(),"data","ollama-inference.lock");
  await mkdir(dirname(path),{recursive:true});
  signal.throwIfAborted();
  return new Promise((resolveGate,reject)=>{
    const child=spawn("python3",["-c",HOLDER,path],{stdio:["pipe","pipe","pipe"]});
    let acquired=false,settled=false;
    const closed=new Promise<void>(r=>child.once("close",()=>r()));
    const cleanup=()=>signal.removeEventListener("abort",abort);
    const abort=()=>{
      child.stdin.end();
      if(!settled){settled=true;reject(new DOMException("Ollama request cancelled while queued","AbortError"));}
    };
    signal.addEventListener("abort",abort,{once:true});
    child.stdin.on("error",()=>{});
    child.stderr.resume();
    child.once("error",error=>{cleanup();if(!settled){settled=true;reject(error);}});
    child.once("close",()=>{
      cleanup();
      if(!settled){settled=true;reject(new Error("Ollama inference lock helper exited before acquisition"));}
    });
    let output="";
    child.stdout.on("data",chunk=>{
      output+=chunk;
      if(!acquired && output.includes("LOCKED\n") && !settled){
        acquired=true;settled=true;
        // Once acquired, HTTP cancellation owns the signal. Release only after
        // the request exits, so another client cannot overlap body processing.
        cleanup();
        resolveGate(async()=>{child.stdin.end();await closed;});
      }
    });
    if(signal.aborted)abort();
  });
}
