import assert from "node:assert/strict";
import { fetchAggregatorPrograms } from "../packages/security-discovery/src/aggregator-client";
import { fetchHuntrPrograms } from "../packages/security-discovery/src/huntr-client";
const originalFetch = globalThis.fetch;
const calls: string[] = [];
try {
  globalThis.fetch = (async (input, init) => {
    const url = String(input);
    calls.push(url);
    assert.ok(init?.signal, "Feed requests must have a deadline");
    if (url.endsWith("bugcrowd_data.json")) return Response.json([{name:"Owned fixture",
      url:"https://fixture.invalid/program", max_payout:10,
      targets:{in_scope:[{type:"source_code",target:"https://github.com/fixture/owned"}]}}]);
    if (url.endsWith("intigriti_data.json")) return new Response(null, {status:503});
    if (url.endsWith("yeswehack_data.json")) return Response.json([]);
    throw new Error("Unexpected or retired feed requested: " + url);
  }) as typeof fetch;
  const programs = await fetchAggregatorPrograms();
  assert.equal(programs.length, 1, "One unavailable provider must not discard other feeds");
  assert.deepEqual(calls.map(url => url.split('/').pop()),
    ["bugcrowd_data.json", "intigriti_data.json", "yeswehack_data.json"]);
  calls.length = 0;
  assert.deepEqual(await fetchHuntrPrograms(), []);
  assert.deepEqual(calls, [], "Retired repository feed must not fetch or invent programs");
  console.log("Supported feeds, bounded requests, provider isolation and retired Huntr feed: PASSED");
} finally { globalThis.fetch = originalFetch; }
