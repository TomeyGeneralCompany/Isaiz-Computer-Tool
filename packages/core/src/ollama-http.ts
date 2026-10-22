import { acquireOllamaGate } from "./ollama-gate";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

/** Ollama's non-streaming replies can legitimately wait minutes for headers.
 * Use the caller's AbortSignal for the entire request, including body reading,
 * rather than fetch/Undici's separate fixed headers deadline. Never redirect.
 * Internal transport: callers must hold acquireOllamaGate, or use postOllamaJson.
 */
export async function sendOllamaJson<T = unknown>(url:URL | string, payload:unknown, signal:AbortSignal, label="Ollama"):Promise<T> {
  const endpoint=new URL(url);
  if (!["http:","https:"].includes(endpoint.protocol) || endpoint.username || endpoint.password)
    return Promise.reject(new Error("Invalid Ollama HTTP endpoint"));
  const body=JSON.stringify(payload);
  return new Promise<T>((resolve,reject)=>{
    const request=endpoint.protocol === "https:" ? httpsRequest : httpRequest;
    const req=request(endpoint,{method:"POST",signal,agent:false,maxHeaderSize:16384,
      headers:{"Content-Type":"application/json","Content-Length":Buffer.byteLength(body)}},res=>{
      res.on("error",reject);
      const status=res.statusCode || 0;
      if(status<200 || status>=300) {
        reject(new Error(`${label} HTTP ${status}`));
        res.destroy();req.destroy();return;
      }
      let size=0;const chunks:Buffer[]=[];
      res.on("data",(chunk:Buffer)=>{
        size+=chunk.length;
        if(size>1048576) {
          const error=new Error(`${label} response exceeds 1 MiB`);
          reject(error);res.destroy();req.destroy();return;
        }
        chunks.push(chunk);
      });
      res.on("end",()=>{
        try {resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")) as T);}
        catch {reject(new Error(`${label} returned malformed response`));}
      });
    });
    req.on("error",reject);
    req.end(body);
  });
}

/** Serialize inference across application processes and the Python research worker.
 * Queue waiting shares the caller deadline; cancellation never sends a queued request.
 */
export async function postOllamaJson<T = unknown>(url:URL|string,payload:unknown,signal:AbortSignal,label="Ollama"):Promise<T> {
  const queued=Date.now();
  const release=await acquireOllamaGate(signal);
  const queueMs=Date.now()-queued;
  try {
    signal.throwIfAborted();
    const result=await sendOllamaJson<T>(url,payload,signal,label);
    if(result && typeof result === "object" && ("message" in result || "response" in result))Object.assign(result,{client_queue_ms:queueMs});
    return result;
  } finally {await release();}
}
