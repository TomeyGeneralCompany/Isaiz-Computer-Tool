import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { acquireOllamaGate } from '../../core/src/ollama-gate';
const root=fileURLToPath(new URL('../../../',import.meta.url));
/** Qwen supplies formatting/parsing only. The existing runner owns every tool. */
export async function postQwenAgentJson(url:URL|string,payload:unknown,signal:AbortSignal):Promise<any> {
  const queued=Date.now();const release=await acquireOllamaGate(signal);
  try {
    signal.throwIfAborted();
    const queueMs=Date.now()-queued;
    return await new Promise((resolveResult,reject)=>{
      const child=spawn(process.env.QWEN_AGENT_PYTHON || resolve(root,'.venv-qwen/bin/python'),
        [resolve(root,'scripts/qwen-agent-bridge.py')],{stdio:['pipe','pipe','pipe']});
      let stdout='',stderr='',overflow=false;
      const abort=()=>child.kill('SIGKILL');
      signal.addEventListener('abort',abort,{once:true});
      child.stdin.on('error',()=>{});
      child.on('error',error=>{signal.removeEventListener('abort',abort);reject(error);});
      child.stdout.on('data',chunk=>{stdout+=chunk;if(stdout.length>1048576){overflow=true;abort();}});
      child.stderr.on('data',chunk=>{stderr=(stderr+chunk).slice(-2000);});
      child.on('close',code=>{
        signal.removeEventListener('abort',abort);
        if(signal.aborted){reject(new DOMException('Model request cancelled','AbortError'));return;}
        if(overflow || code!==0){reject(new Error(overflow?'Qwen response exceeds limit':stderr || 'Qwen bridge exited unsuccessfully'));return;}
        try{resolveResult({...JSON.parse(stdout),client_queue_ms:queueMs});}catch{reject(new Error('Malformed Qwen bridge response'));}
      });
      if(signal.aborted)abort();else child.stdin.end(JSON.stringify({url:String(url),payload}));
    });
  } finally {await release();}
}
