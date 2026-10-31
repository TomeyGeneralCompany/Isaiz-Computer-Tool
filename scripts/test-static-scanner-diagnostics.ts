/** Regression: scanner failures must preserve their bounded subprocess diagnostics.
 * This uses an owned fake scanner wrapper and never contacts a target.
 */
import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { collectStaticLeads } from "../packages/security-solver/src/local-static-leads";

const root=await mkdtemp(join(tmpdir(),"autohack-static-diagnostic-"));
const previous=process.env.PROJECT_ROOT;
try {
  const scripts=join(root,"scripts");
  const vendor=join(scripts,"vendor","semgrep-rules");
  const repository=join(root,"owned-fixture");
  await mkdir(vendor,{recursive:true});
  await mkdir(repository,{recursive:true});
  await writeFile(join(scripts,"static-leads.yaml"),"rules: []\n");
  await writeFile(join(vendor,"manifest.json"),"{}\n");
  await writeFile(join(scripts,"source-static.py"),[
    "import json",
    "print(json.dumps({'status':'failed','reason':'Scanner returned no valid JSON',",
    "  'exitCode':1,'diagnostic':'bwrap: namespace unavailable\\ntry another sandbox', 'leads':[]}))",
    "",
  ].join("\n"));
  process.env.PROJECT_ROOT=root;
  const cache=join(root,"static-leads-cache.json");
  const result=await collectStaticLeads(root,
    [{directory:repository,url:"https://github.com/owned-fixture/source"}],
    [],cache,new AbortController().signal);
  assert.equal(result.runs.length,1);
  const run=result.runs[0];
  assert.equal(run.status,"failed");
  assert.equal(run.reason,"Scanner returned no valid JSON");
  assert.equal(run.exitCode,1);
  assert.equal(run.diagnostic,"bwrap: namespace unavailable try another sandbox");
  assert.equal(result.leads.length,0);
  const saved=JSON.parse(await readFile(cache,"utf8"));
  assert.equal(saved.runs[0].exitCode,1);
  assert.equal(saved.runs[0].diagnostic,run.diagnostic);
  console.log("Scanner subprocess failure diagnostics preserved PASSED");
} finally {
  if(previous===undefined)delete process.env.PROJECT_ROOT;
  else process.env.PROJECT_ROOT=previous;
  await rm(root,{recursive:true,force:true});
}
