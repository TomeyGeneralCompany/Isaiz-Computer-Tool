import assert from "node:assert/strict";
import { ScopedHttpInspector, isPublicIpv4 } from "../packages/core/src/authorized-http";
const summary=JSON.stringify({scopes:[
  {assetType:"URL",assetIdentifier:"https://in-scope.test/health",eligibleForBounty:true},
]});
const seen:string[]=[];
const inspector=new ScopedHttpInspector(summary,{maxRequests:2,minIntervalMs:0},async(url,method)=>{
  seen.push(method+" "+url.toString());
  return {status:200,body:Buffer.from('{"ok":true}')};
});
assert.equal((await inspector.observe("https://in-scope.test/health")).status,200);
assert.equal((await inspector.observe("https://in-scope.test/health","HEAD")).bodyExcerpt,"");
assert.equal(seen.length,2);
await assert.rejects(()=>inspector.observe("https://in-scope.test/private"),/not explicitly authorized/);
assert.equal(seen.length,2);
await assert.rejects(()=>inspector.observe("https://in-scope.test/health"),/budget exhausted/);
for(const ip of ["127.0.0.1","169.254.169.254","10.0.0.1","192.168.1.2","172.31.0.1","100.64.0.1","0.0.0.0","8.8.8.8x","203.0.113.2"])
  assert.equal(isPublicIpv4(ip),false,ip);
assert.equal(isPublicIpv4("8.8.8.8"),true);
assert.equal(isPublicIpv4("1.1.1.1"),true);
console.log("Scoped, budgeted HTTP observation and private-IP denial tests passed");
