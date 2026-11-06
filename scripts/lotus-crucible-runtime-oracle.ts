/** Grader-only runtime oracle for owned Level 6 challenges.
 * Reproduces the hidden defect effects and checks safe controls WITHOUT
 * invoking the LOTUS model. This module is never imported by the investigator.
 */
import {execFileSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {generateCrucible} from './lotus-crucible-generator';
import {validateCrucibleChallenge,type CrucibleChallenge} from './lotus-crucible-contract';
import type {Language} from './lotus-gauntlet-fixtures';

const payload='<svg onload=alert(7)>';
const encoded='&lt;svg onload=alert(7)&gt;';
async function stage(c:CrucibleChallenge):Promise<string>{
 const root=await mkdtemp(join(tmpdir(),'lotus-crucible-oracle-'));
 for(const [p,s] of Object.entries(c.files)){
   const f=join(root,p);await mkdir(dirname(f),{recursive:true});
   await writeFile(f,s);
 }
 return root;
}
const verify=(results:string[],count:number):void=>{
 if(results.length!==count+8)throw Error('Oracle incorrect number of responses');
 results.slice(0,count).forEach((x,i)=>{
   if(!x.includes(payload))throw Error('Oracle defect '+i+' did not reproduce raw HTML');
 });
 results.slice(count).forEach((x,i)=>{
   if(x.includes(payload)||!x.includes(encoded))
     throw Error('Oracle negative control '+i+' failed');
 });
};
async function pythonOracle(c:CrucibleChallenge):Promise<void>{
 const root=await stage(c);
 try{
   const count=c.privateAnswerKey.defects.length;
   const names=Array.from({length:count},(_,i)=>'src.gateways.gateway_'+i)
      .concat(Array.from({length:8},(_,i)=>'src.gateways.gateway_'+(100+i)));
   const script='import json,importlib\n'+
     'names='+JSON.stringify(names)+'\n'+
     'print(json.dumps([importlib.import_module(n).response_body('+
     JSON.stringify('http://localhost/?message='+encodeURIComponent(payload))+
     ') for n in names]))\n';
   const data=execFileSync('python3',['-c',script],{
     cwd:root,encoding:'utf8',timeout:90000,env:{...process.env,PYTHONPATH:root}
   });
   verify(JSON.parse(data.trim()),count);
 }finally{await rm(root,{recursive:true,force:true});}
}
async function jsOracle(c:CrucibleChallenge):Promise<void>{
 const root=await stage(c);
 try{
   const runtime=createRequire(join(root,'runtime.cjs'));
   const values:string[]=[];
   for(const i of [...Array.from({length:c.privateAnswerKey.defects.length},(_,j)=>j),
                    ...Array.from({length:8},(_,j)=>100+j)]){
     const gateway=runtime(join(root,'src/gateways/gateway_'+i+'.cjs'));
     values.push(gateway.responseBody('http://localhost/?message='+encodeURIComponent(payload)));
   }
   verify(values,c.privateAnswerKey.defects.length);
 }finally{await rm(root,{recursive:true,force:true});}
}
async function javaOracle(c:CrucibleChallenge):Promise<void>{
 const root=await stage(c);
 try{
   const count=c.privateAnswerKey.defects.length;
   const cls=(i:number)=>'crucible.Gateway'+String(i).padStart(2,'0');
   const names=[...Array.from({length:count},(_,i)=>i),...Array.from({length:8},(_,i)=>100+i)];
   const code=['public class CrucibleOracleRun {',
     'public static void main(String[] args){',
     ...names.map(i=>'System.out.println(new '+cls(i)+'().responseBody('+JSON.stringify(payload)+'));'),
     '}', '}'].join('\n')+'\n';
   const run=join(root,'CrucibleOracleRun.java');await writeFile(run,code);
   const sources=Object.keys(c.files).filter(p=>p.endsWith('.java')).map(p=>join(root,p));
   execFileSync('javac',['-J-Xmx1536m','-d',root,run,...sources],
     {cwd:root,timeout:180000,stdio:'pipe',maxBuffer:8*1024*1024});
   const result=execFileSync('java',['-cp',root,'CrucibleOracleRun'],
     {cwd:root,encoding:'utf8',timeout:60000});
   verify(result.trim().split('\n'),count);
 }finally{await rm(root,{recursive:true,force:true});}
}
async function solidityOracle(c:CrucibleChallenge):Promise<void>{
 const requireRuntime=createRequire(join(process.cwd(),'scripts/reproduction-runtime/package.json'));
 const solc=requireRuntime('solc'),ethers=requireRuntime('ethers'),ganache=requireRuntime('ganache');
 const sources:Record<string,{content:string}>={};
 const targetGateways=c.privateAnswerKey.defects.map((_,i)=>'contracts/gateways/Gateway'+String(i).padStart(2,'0')+'.sol');
 const targetPaths=[...targetGateways,'contracts/interfaces/ICrucibleRoute.sol',...c.privateAnswerKey.defects.flatMap(d=>d.affectedPaths),
   ...c.privateAnswerKey.negativeControls.slice(0,8).flatMap(d=>d.affectedPaths)];
 for(const p of targetPaths){if(!c.files[p])throw Error('Missing Solidity oracle source '+p);sources[p]={content:c.files[p]};}
 const input={language:'Solidity',sources,settings:{optimizer:{enabled:false},
   outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}};
 const compiled=JSON.parse(solc.compile(JSON.stringify(input)));
 const errors=(compiled.errors||[]).filter((e:any)=>e.severity==='error');
 if(errors.length)throw Error('Oracle Solidity compilation failed: '+JSON.stringify(errors.slice(0,3)));
 const provider=new ethers.BrowserProvider(ganache.provider({logging:{quiet:true}}));
 const deployer=await provider.getSigner(0),attacker=await provider.getSigner(1);
 const deploy=async(path:string,name:string,args:any[]=[])=>{
   const artifact=compiled.contracts?.[path]?.[name];
   if(!artifact?.evm?.bytecode?.object)throw Error('Oracle missing Solidity artifact '+path+':'+name);
   const factory=new ethers.ContractFactory(artifact.abi,artifact.evm.bytecode.object,deployer);
   const instance=await factory.deploy(...args);await instance.waitForDeployment();
   return instance;
 };
 for(let i=0;i<targetGateways.length;i++){
   const chain=c.privateAnswerKey.defects[i].affectedPaths;
   const deployed:any[]=[];
   for(let j=chain.length-1;j>=0;j--){
     const path=chain[j],name=path.split('/').pop()!.replace('.sol','');
     const instance=await deploy(path,name);
     if(deployed.length){
       const tx=await instance.setNext(await deployed[deployed.length-1].getAddress());
       await tx.wait();
     }
     deployed.push(instance);
   }
   const first=deployed[deployed.length-1],terminal=deployed[0];
   const gateway=await deploy(targetGateways[i],'Gateway'+String(i).padStart(2,'0'),
     [await first.getAddress()]);
   const tx=await gateway.connect(attacker).rotateOperator(await attacker.getAddress());
   await tx.wait();
   if((await terminal.operator()).toLowerCase()!==(await attacker.getAddress()).toLowerCase())
     throw Error('Oracle Solidity defect '+i+' did not reproduce chained unauthorized operator change');
 }
 for(let i=0;i<8;i++){
   const path=c.privateAnswerKey.negativeControls[i].affectedPaths[0];
   const name=path.split('/').pop()!.replace('.sol','');
   const contract=await deploy(path,name);
   let rejected=false;
   try{const tx=await contract.connect(attacker).rotateOperator(await attacker.getAddress());await tx.wait();}
   catch{rejected=true;}
   if(!rejected)throw Error('Oracle Solidity safe authorization '+i+' did not reject attacker');
 }
}
export async function runCrucibleOracle(language:Language,seed:string,clean=false):Promise<void>{
 const challenge=generateCrucible({language,seed,clean});
 validateCrucibleChallenge(challenge);
 if(language==='javascript')await jsOracle(challenge);
 else if(language==='python')await pythonOracle(challenge);
 else if(language==='java')await javaOracle(challenge);
 else await solidityOracle(challenge);
}
if(process.argv[1]?.includes('lotus-crucible-runtime-oracle')){
 const language=process.argv[2] as Language;
 const seed=process.argv[3]||'runtime-oracle-verification-01';
 const clean=process.argv.includes('--clean');
 if(!['solidity','python','javascript','java'].includes(language))
   throw Error('Specify solidity, python, javascript, or java');
 runCrucibleOracle(language,seed,clean).then(()=>console.log('Level 6 independent runtime oracle PASSED '+language+(clean?' clean':'')))
 .catch(e=>{console.error(e);process.exitCode=1});
}
