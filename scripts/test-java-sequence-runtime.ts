/** Exercises constructor state and multiple method invocations in the real isolated Java verifier. */
import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtemp,writeFile,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
const root=await mkdtemp(join(tmpdir(),"autohack-java-sequence-"));
try {
  await writeFile(join(root,"ContractState.java"),`
public class ContractState {
  private long weight;
  public ContractState(int initial) { weight=initial; }
  public long addWeight(int delta) { weight+=delta; return weight; }
  public long getTotalTronPowerWeight() { return weight; }
}`);
  const spec=join(root,"spec.json");
  await writeFile(spec,JSON.stringify({
    file:"ContractState.java",function:"ContractState.getTotalTronPowerWeight",
    kind:"java_sequence",nonce:"0123456789abcdef0123456789abcdef",
    sequence:{constructor:[3],steps:[
      {method:"addWeight",args:[2],expected:5},
      {method:"getTotalTronPowerWeight",args:[],expected:5}
    ]}
  }));
  let output="";
  try {
    output=execFileSync("python3",["scripts/source-reproduction.py","--repository",root,"--spec",spec],
      {encoding:"utf8",timeout:120000});
  } catch(error:any) {
    output=String(error.stdout||"");
    if(!output)throw error;
  }
  const result=JSON.parse(output);
  assert.equal(result.kind,"java_sequence",JSON.stringify(result));
  assert.equal(result.status,"observation_only",JSON.stringify(result));
  assert.equal(result.behavior_observed,false);
  assert.deepEqual(result.observations.constructor,[3]);
  assert.ok(result.observations.steps.every((x:any)=>x.operation==="call"&&typeof x.function==="string"));
  assert.deepEqual(result.observations.steps.map((x:any)=>x.actual),["5","5"]);
  assert.ok(result.observations.steps.every((x:any)=>x.passed));
  console.log("Stateful Java constructor + mutation + getter in real isolated verifier: PASSED");
} finally {await rm(root,{recursive:true,force:true});}
