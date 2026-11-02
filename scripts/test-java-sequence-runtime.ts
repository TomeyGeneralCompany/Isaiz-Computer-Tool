/** Exercises constructor state and multiple method invocations in the real isolated Java verifier. */
import assert from "node:assert/strict";
import {execFileSync} from "node:child_process";
import {mkdtemp,mkdir,writeFile,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
// The driver intentionally exits 1 when no security behavior was observed.
// An observation_only result is still a successful execution of the test harness.
function runObservation(root:string,spec:string):string {
  try {
    return execFileSync("python3",["scripts/source-reproduction.py","--repository",root,"--spec",spec],\n      {encoding:"utf8",timeout:120000});
  } catch(error:any) {
    if(error.status===1 && typeof error.stdout==="string" && error.stdout.trim()) {
      const result=JSON.parse(error.stdout);
      if(result.status==="observation_only" || result.status==="behavior_not_observed")return error.stdout;
    }
    throw error;
  }
}
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
    output=runObservation(root,spec);
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

  // Reproduces the actual ContractState dependency pattern: a nonpublic
  // constructor receives ProgramInvoke and obtains a Repository collaborator.
  await writeFile(join(root,"ProxyState.java"),`
interface Repository { long getTotalTronPowerWeight(); }
interface ProgramInvoke { Repository getDeposit(); Object getContractAddress(); }
public class ProxyState {
  private final Repository repository;
  ProxyState(ProgramInvoke invoke) { repository=invoke.getDeposit(); }
  public long getTotalTronPowerWeight() { return repository.getTotalTronPowerWeight(); }
}`);
  await writeFile(spec,JSON.stringify({
    file:"ProxyState.java",function:"ProxyState.getTotalTronPowerWeight",
    kind:"java_sequence",nonce:"0123456789abcdef0123456789abcdef",
    sequence:{constructor:[{proxy:"ProgramInvoke",returns:{
      getDeposit:{proxy:"Repository",returns:{getTotalTronPowerWeight:42}},
      getContractAddress:null
    }}],steps:[{method:"getTotalTronPowerWeight",args:[],expected:42}]}
  }));
  let proxyOutput="";
  try {
    proxyOutput=runObservation(root,spec);
  } catch(error:any) {
    proxyOutput=String(error.stdout||"");
    if(!proxyOutput)throw error;
  }
  const proxied=JSON.parse(proxyOutput);
  assert.equal(proxied.kind,"java_sequence",JSON.stringify(proxied));
  assert.equal(proxied.status,"observation_only",JSON.stringify(proxied));
  assert.equal(proxied.observations.steps[0].actual,"42");
  assert.equal(proxied.observations.steps[0].passed,true);
  // The schema also permits interface mocks without explicit class names.
  // Resolve each nested mock against its Java formal parameter type.
  await writeFile(spec,JSON.stringify({
    file:"ProxyState.java",function:"ProxyState.getTotalTronPowerWeight",
    kind:"java_sequence",nonce:"0123456789abcdef0123456789abcdef",
    sequence:{constructor:[{mock:{
      getDeposit:{mock:{getTotalTronPowerWeight:43}},
      getContractAddress:null
    }}],steps:[{method:"getTotalTronPowerWeight",args:[],expected:43}]}
  }));
  const mockOutput=runObservation(root,spec);
  const mocked=JSON.parse(mockOutput);
  assert.equal(mocked.kind,"java_sequence",JSON.stringify(mocked));
  assert.equal(mocked.status,"observation_only",JSON.stringify(mocked));
  assert.equal(mocked.observations.steps[0].actual,"43");
  assert.equal(mocked.observations.steps[0].passed,true);
  console.log("Nested inferred Java interface mocks: PASSED");
  // Real repositories use package-qualified classes under src/main/java.
  const packageDir=join(root,"src","main","java","org","tron","core","vm","program");
  await mkdir(packageDir,{recursive:true});
  await writeFile(join(packageDir,"PackageState.java"),`
package org.tron.core.vm.program;
public class PackageState {
  private int value;
  public PackageState(int initial) { value=initial; }
  public int increment(int by) { value+=by; return value; }
  public int getValue() { return value; }
}`);
  await writeFile(spec,JSON.stringify({
    file:"src/main/java/org/tron/core/vm/program/PackageState.java",
    function:"PackageState.getValue",kind:"java_sequence",
    nonce:"0123456789abcdef0123456789abcdef",
    sequence:{constructor:[7],steps:[
      {method:"increment",args:[3],expected:10},
      {method:"getValue",args:[],expected:10}
    ]}
  }));
  const packagedOutput=runObservation(root,spec);
  const packaged=JSON.parse(packagedOutput);
  assert.equal(packaged.kind,"java_sequence",JSON.stringify(packaged));
  assert.equal(packaged.status,"observation_only",JSON.stringify(packaged));
  assert.deepEqual(packaged.observations.steps.map((x:any)=>x.actual),["10","10"]);
  assert.ok(packaged.observations.steps.every((x:any)=>x.passed));
  console.log("Package-qualified Java constructor and state sequence: PASSED");
  // A package-qualified interface may be named by its simple source name
  // in a declarative proxy; the harness resolves it from the formal type.
  await writeFile(join(packageDir,"PackageProxyState.java"),`
package org.tron.core.vm.program;
interface PackageRepo { long getPower(); }
interface PackageInvoke { PackageRepo getRepo(); }
public class PackageProxyState {
  private final PackageRepo repo;
  PackageProxyState(PackageInvoke invoke) { repo=invoke.getRepo(); }
  public long getPower() { return repo.getPower(); }
}`);
  await writeFile(spec,JSON.stringify({
    file:"src/main/java/org/tron/core/vm/program/PackageProxyState.java",
    function:"PackageProxyState.getPower",kind:"java_sequence",
    nonce:"0123456789abcdef0123456789abcdef",
    sequence:{constructor:[{proxy:"PackageInvoke",returns:{
      getRepo:{proxy:"PackageRepo",returns:{getPower:51}}
    }}],steps:[{method:"getPower",args:[],expected:51}]}
  }));
  const qualifiedProxyOutput=runObservation(root,spec);
  const qualifiedProxy=JSON.parse(qualifiedProxyOutput);
  assert.equal(qualifiedProxy.kind,"java_sequence",JSON.stringify(qualifiedProxy));
  assert.equal(qualifiedProxy.status,"observation_only",JSON.stringify(qualifiedProxy));
  assert.equal(qualifiedProxy.observations.steps[0].actual,"51");
  assert.equal(qualifiedProxy.observations.steps[0].passed,true);
  console.log("Package-qualified nested Java interface proxies: PASSED");


  console.log("Java package-private constructor + nested interface collaborator proxy: PASSED");
  console.log("Stateful Java constructor + mutation + getter in real isolated verifier: PASSED");
} finally {await rm(root,{recursive:true,force:true});}
