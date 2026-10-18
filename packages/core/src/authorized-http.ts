/**
 * Bounded non-invasive HTTP observation of explicitly allowed program assets.
 * GET/HEAD only, no credentials, no redirects, public IPv4 DNS pinned before
 * connect (avoids DNS rebinding and local metadata/service access).
 */
import { lookup } from "node:dns/promises";
import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIPv4 } from "node:net";
import { targetInExplicitScope } from "./scope-authorization";

export interface HttpObservation {
  url: string;
  status: number;
  method: "GET" | "HEAD";
  bodySha256: string;
  bodyExcerpt: string;
  observedAt: string;
  bytes: number;
}
export interface InspectionOptions {
  maxRequests?: number;
  minIntervalMs?: number;
  timeoutMs?: number;
  maxBodyBytes?: number;
}
export type InspectionTransport =
  (url: URL, method: "GET" | "HEAD", timeoutMs: number, maxBodyBytes: number) =>
    Promise<{ status: number; body: Buffer }>;

export function isPublicIpv4(address: string): boolean {
  if (!isIPv4(address)) return false;
  const [a,b,c] = address.split(".").map(Number);
  if (a===0 || a===10 || a===127 || a>=224 || a===169 && b===254
    || a===172 && b>=16 && b<=31 || a===192 && b===168
    || a===100 && b>=64 && b<=127 || a===192 && b===0 && c===0
    || a===198 && b>=18 && b<=19 || a===192 && b===0 && c===2
    || a===198 && b===51 && c===100 || a===203 && b===0 && c===113)
    return false;
  return true;
}

async function publicPinnedTransport(url: URL, method: "GET" | "HEAD",
  timeoutMs: number, maxBodyBytes: number): Promise<{status:number;body:Buffer}> {
  // IPv6-only destinations are deliberately refused until a pinned IPv6
  // address policy is implemented; never fall back to unpinned DNS.
  const resolved = await lookup(url.hostname, { family: 4, all: true });
  const addresses = resolved.filter(x => isPublicIpv4(x.address));
  if (!addresses.length) throw new Error("Destination has no public IPv4 address");
  const pinned = addresses[0].address;
  return await new Promise((resolve, reject) => {
    const request = (url.protocol==="https:" ? httpsRequest : httpRequest)(
      url, {
        method,
        timeout: timeoutMs,
        headers: { "User-Agent":"AutoHack-Scoped-Observer/1.0",
          "Accept":"text/plain,text/html,application/json" },
        lookup: (_hostname, _options, callback) => callback(null, pinned, 4),
      }, response => {
        const status = response.statusCode || 0;
        // Never follow redirects, and never dispatch a request to Location.
        if (status>=300 && status<400) {
          response.resume();
          reject(new Error("Redirect blocked; new URL requires explicit scope approval"));
          return;
        }
        let size=0;
        const chunks:Buffer[]=[];
        response.on("data",(chunk:Buffer)=>{
          size += chunk.length;
          if(size>maxBodyBytes) {
            request.destroy(new Error("Response exceeds configured evidence size limit"));
          } else chunks.push(chunk);
        });
        response.on("end",()=>resolve({status,body:Buffer.concat(chunks)}));
        response.on("error",reject);
      },
    );
    request.on("timeout",()=>request.destroy(new Error("HTTP observation timed out")));
    request.on("error",reject);
    request.end();
  });
}

export class ScopedHttpInspector {
  private requests = 0;
  private lastRequest = 0;
  private maxRequests: number;
  private minIntervalMs: number;
  private timeoutMs: number;
  private maxBodyBytes: number;
  constructor(private readonly programScope: string,
    opts: InspectionOptions = {},
    private readonly transport: InspectionTransport = publicPinnedTransport) {
    this.maxRequests = opts.maxRequests ?? 10;
    this.minIntervalMs = opts.minIntervalMs ?? 3000;
    this.timeoutMs = opts.timeoutMs ?? 7000;
    this.maxBodyBytes = opts.maxBodyBytes ?? 64 * 1024;
    if (!Number.isSafeInteger(this.maxRequests) || this.maxRequests<1 || this.maxRequests>100
      || !Number.isSafeInteger(this.minIntervalMs) || this.minIntervalMs<0 || this.minIntervalMs>60000
      || !Number.isSafeInteger(this.timeoutMs) || this.timeoutMs<100 || this.timeoutMs>30000
      || !Number.isSafeInteger(this.maxBodyBytes) || this.maxBodyBytes<64 || this.maxBodyBytes>1024*1024)
      throw new Error("Invalid bounded HTTP inspection configuration");
  }

  async observe(target: string, method: "GET" | "HEAD" = "GET"): Promise<HttpObservation> {
    if (!targetInExplicitScope(this.programScope,target))
      throw new Error("Denied: target not explicitly authorized by bounty program");
    if (method!=="GET" && method!=="HEAD") throw new Error("Only GET/HEAD observations permitted");
    if (this.requests>=this.maxRequests) throw new Error("Inspection request budget exhausted");
    this.requests++; // failures also consume the bounded budget
    const delay = Math.max(0,this.lastRequest+this.minIntervalMs-Date.now());
    if(delay) await new Promise(resolve=>setTimeout(resolve,delay));
    this.lastRequest = Date.now();
    const url=new URL(target);
    const result = await this.transport(url,method,this.timeoutMs,this.maxBodyBytes);
    if (result.body.length>this.maxBodyBytes)
      throw new Error("Transport violated evidence size limit");
    return {
      url:target,method,status:result.status,bytes:result.body.length,
      observedAt:new Date().toISOString(),
      bodySha256:createHash("sha256").update(result.body).digest("hex"),
      bodyExcerpt:method==="HEAD" ? "" : result.body.toString("utf8").slice(0,4096),
    };
  }
}
