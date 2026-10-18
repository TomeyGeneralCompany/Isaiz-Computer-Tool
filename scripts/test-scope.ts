import assert from "node:assert/strict";
import { targetInExplicitScope, assertAuthorizedProgram, assertAuthorizedTarget } from "../packages/core/src/scope-authorization";

const scopes = JSON.stringify({scopes: [
  {assetType:"SOURCE_CODE", assetIdentifier:"https://github.com/acme/allowed", eligibleForBounty:true},
  {assetType:"URL",assetIdentifier:"https://app.example.test/account",eligibleForSubmission:true},
  {assetType:"URL",assetIdentifier:"https://private.example.test",eligibleForBounty:false},
]});
assertAuthorizedProgram(scopes);
assertAuthorizedTarget(scopes,"https://github.com/acme/allowed/src/a.ts");
assert.ok(targetInExplicitScope(scopes, "https://app.example.test/account"));
for(const target of [
  "https://github.com/acme/allowed-sibling", "https://github.com/acme/other",
  "https://github.com.evil.test/acme/allowed", "https://github.com/acme/allowed/../other",
  "https://github.com/acme/allowed/%2e%2e/other",
  "https://app.example.test/admin", "https://private.example.test",
  "https://attacker@app.example.test/account", "file:///etc/passwd",
  "https://github.com/acme/allowed?other=1", "http://github.com/acme/allowed",
  "https://github.com/acme/allowed%2Fother",
]) {
  assert.equal(targetInExplicitScope(scopes,target),false, "Unexpected authorization: "+target);
  assert.throws(()=>assertAuthorizedTarget(scopes,target), /not within/);
}
for(const invalid of [null, "", "{bad", "{}", JSON.stringify({scopes:[{assetIdentifier:"https://example.test",eligibleForBounty:false}]})])
  assert.throws(()=>assertAuthorizedProgram(invalid), /no explicitly eligible/);
console.log("Scope-authorization deterministic tests passed");
