import {request as httpRequest} from 'node:http';
import {request as httpsRequest} from 'node:https';
import {StringDecoder} from 'node:string_decoder';
import {acquireOllamaGate} from './ollama-gate';
export type ModelProgress={contentCharacters:number;thinkingCharacters:number;toolCalls:number};
export type ChatProgressOptions={idleTimeoutMs?:number;onProgress?:(progress:ModelProgress)=>void};
/** Queue wait belongs to the audit deadline. Only lack of output after dispatch
 * consumes the inactivity deadline; output never extends the overall audit. */
export function validateModelIdleTimeout(milliseconds=900000) {
  if(!Number.isFinite(milliseconds)||milliseconds<=0)throw new Error('Invalid model inactivity timeout');
}
export function modelInactivityGuard(parent:AbortSignal,milliseconds=900000) {
  validateModelIdleTimeout(milliseconds);
  const controller=new AbortController();let timer:ReturnType<typeof setTimeout>;
  const reset=()=>{clearTimeout(timer);timer=setTimeout(()=>controller.abort(new Error('Local model produced no new output within the inactivity deadline after dispatch')),milliseconds);};
  reset();
  return {signal:AbortSignal.any([parent,controller.signal]),progress:reset,close:()=>clearTimeout(timer),
    error:(error:unknown)=>parent.aborted?error:controller.signal.aborted?controller.signal.reason:error};
}

/** Ollama's documented NDJSON chat protocol, assembled before any action executes. */
export async function postOllamaChat(url:URL|string,payload:Record<string,unknown>,signal:AbortSignal,options:ChatProgressOptions={}) {
  validateModelIdleTimeout(options.idleTimeoutMs);
  const queued=Date.now(),release=await acquireOllamaGate(signal);
  const queueMs=Date.now()-queued,guard=modelInactivityGuard(signal,options.idleTimeoutMs);
  try {
    guard.signal.throwIfAborted();
    const endpoint=new URL(url);
    if(!['http:','https:'].includes(endpoint.protocol)||endpoint.username||endpoint.password)throw new Error('Invalid Ollama HTTP endpoint');
    const body=JSON.stringify({...payload,stream:true});
    return await new Promise<any>((resolve,reject)=>{
      let settled=false,size=0,pending='',content='',thinking='';
      const calls:any[]=[],decoder=new StringDecoder('utf8');let completed:any;
      const req=(endpoint.protocol==='https:'?httpsRequest:httpRequest)(endpoint,{method:'POST',signal:guard.signal,agent:false,maxHeaderSize:16384,
        headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body)}},res=>{
        const fail=(error:Error)=>{if(!settled){settled=true;reject(error);}res.destroy();req.destroy();};
        res.on('error',error=>{if(!settled){settled=true;reject(error);}});
        if((res.statusCode||0)<200||(res.statusCode||0)>=300){fail(new Error(`Ollama HTTP ${res.statusCode}`));return;}
        const streaming=String(res.headers['content-type']||'').includes('ndjson');
        const frame=(line:string)=>{
          if(!line.trim())return;
          if(completed)throw new Error('Ollama returned data after completion');
          const value=JSON.parse(line);
          if(!value||typeof value!=='object'||Array.isArray(value)||value.error)throw new Error('Ollama returned an invalid stream frame');
          const message=value.message||{};
          if(message.content!==undefined&&typeof message.content!=='string')throw new Error('Invalid model content');
          if(message.thinking!==undefined&&typeof message.thinking!=='string')throw new Error('Invalid model thinking');
          if(message.tool_calls!==undefined&&!Array.isArray(message.tool_calls))throw new Error('Invalid model tool calls');
          content+=message.content||'';thinking+=message.thinking||'';calls.push(...(message.tool_calls||[]));
          if(message.content?.length||message.thinking?.length||message.tool_calls?.length){
            guard.progress();options.onProgress?.({contentCharacters:content.length,thinkingCharacters:thinking.length,toolCalls:calls.length});
          }
          if(value.done===true)completed=value;
        };
        res.on('data',(chunk:Buffer)=>{
          size+=chunk.length;if(size>1048576){fail(new Error('Ollama response exceeds 1 MiB'));return;}
          pending+=decoder.write(chunk);
          if(streaming)try {let end;while((end=pending.indexOf('\n'))>=0){const line=pending.slice(0,end);pending=pending.slice(end+1);frame(line);}}catch{fail(new Error('Ollama returned malformed stream'));}
        });
        res.on('end',()=>{
          if(settled)return;
          try {
            pending+=decoder.end();
            if(!streaming){
              // Compatibility with existing JSON-only local adapters and test servers.
              const value=JSON.parse(pending);if(value.error)throw new Error('Model error');
              settled=true;resolve({...value,client_queue_ms:queueMs});return;
            }
            if(pending.trim())frame(pending);
            if(!completed)throw new Error('Ollama stream ended before completion');
            settled=true;resolve({...completed,message:{role:'assistant',content,...(thinking?{thinking}:{}),...(calls.length?{tool_calls:calls}:{})},client_queue_ms:queueMs});
          }catch{fail(new Error('Ollama returned malformed or incomplete response'));}
        });
      });
      req.on('error',error=>{if(!settled){settled=true;reject(error);}});req.end(body);
    });
  }catch(error){throw guard.error(error);}finally{guard.close();await release();}
}
