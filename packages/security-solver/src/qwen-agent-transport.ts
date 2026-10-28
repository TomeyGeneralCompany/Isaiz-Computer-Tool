import {modelInactivityGuard,validateModelIdleTimeout,type ChatProgressOptions} from '../../core/src/ollama-chat';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { acquireOllamaGate } from '../../core/src/ollama-gate';
// Resolve at runtime: a directory URL is treated as an asset import by webpack.
const root=resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
/** Qwen supplies formatting/parsing only. The existing runner owns every tool. */
export async function postQwenAgentJson(url:URL|string,payload:unknown,signal:AbortSignal,options:ChatProgressOptions={}):Promise<any> {
  validateModelIdleTimeout(options.idleTimeoutMs);
  const queued=Date.now();const release=await acquireOllamaGate(signal);
  const guard=modelInactivityGuard(signal,options.idleTimeoutMs);
  const active=guard.signal;
  try {
    active.throwIfAborted();
    const queueMs=Date.now()-queued;
    return await new Promise((resolveResult,reject)=>{
      const child=spawn(process.env.QWEN_AGENT_PYTHON || resolve(root,'.venv-qwen/bin/python'),
        [resolve(root,'scripts/qwen-agent-bridge.py')],{stdio:['pipe','pipe','pipe']});
      let stdout='',stderr='',progressBuffer='',overflow=false;
      const abort=()=>child.kill('SIGKILL');
      active.addEventListener('abort',abort,{once:true});
      child.stdin.on('error',()=>{});
      child.on('error',error=>{active.removeEventListener('abort',abort);reject(error);});
      child.stdout.on('data',chunk=>{stdout+=chunk;if(stdout.length>1048576){overflow=true;abort();}});
      child.stderr.on('data',chunk=>{
        stderr=(stderr+chunk).slice(-2000);progressBuffer=(progressBuffer+chunk).slice(-8192);
        let end;while((end=progressBuffer.indexOf('\n'))>=0){
          const line=progressBuffer.slice(0,end);progressBuffer=progressBuffer.slice(end+1);
          if(line.startsWith('[MODEL_PROGRESS] '))try {
            const progress=JSON.parse(line.slice(17));
            if(progress.contentCharacters>0||progress.thinkingCharacters>0){guard.progress();options.onProgress?.(progress);}
          }catch{}
        }
      });
      child.on('close',code=>{
        active.removeEventListener('abort',abort);
        if(active.aborted){reject(new DOMException('Model request cancelled','AbortError'));return;}
        if(overflow || code!==0){reject(new Error(overflow?'Qwen response exceeds limit':stderr || 'Qwen bridge exited unsuccessfully'));return;}
        try{resolveResult({...JSON.parse(stdout),client_queue_ms:queueMs});}catch{reject(new Error('Malformed Qwen bridge response'));}
      });
      if(active.aborted)abort();else child.stdin.end(JSON.stringify({url:String(url),payload}));
    });
  } catch(error){throw guard.error(error);} finally {guard.close();await release();}
}
