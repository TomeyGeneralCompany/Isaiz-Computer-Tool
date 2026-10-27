/** Real local model, shared production controller, real isolated probes, sequential runs. */
import {spawn} from 'node:child_process';
import {mkdir,writeFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
const root=resolve('data/model-comparisons',new Date().toISOString().replaceAll(':','-'));
await mkdir(root,{recursive:true,mode:0o700});
const profiles=['deterministic','qwen','qwen-planner'];
const results:Array<{profile:string;variant:number;passed:boolean;log:string}>=[];
for(const profile of profiles)for(let variant=0;variant<3;variant++) {
  const log=join(root,profile+'-'+variant+'.log');
  console.log(`Testing ${profile}, variant ${variant+1}/3 with actual local model and probes`);
  let output='';
  const passed=await new Promise<boolean>((resolve,reject)=>{
    const child=spawn(process.execPath,['--import','tsx','scripts/test-production-workflow.ts','--real-model','--variant='+variant],{env:{...process.env,LOCAL_MODEL_PROFILE:profile},stdio:['ignore','pipe','pipe']});
    child.stdout.on('data',d=>{output=(output+d).slice(-1000000);process.stdout.write(d);});
    child.stderr.on('data',d=>{output=(output+d).slice(-1000000);process.stderr.write(d);});
    child.once('error',reject);child.once('exit',code=>resolve(code===0));
  });
  await writeFile(log,output,{mode:0o600});results.push({profile,variant,passed,log});
  await writeFile(join(root,'results.json'),JSON.stringify({mocked:false,results},null,2),{mode:0o600});
}
const passing=profiles.filter(profile=>results.filter(r=>r.profile===profile).every(r=>r.passed));
console.log(JSON.stringify({mocked:false,passingProfiles:passing,results,configurationChanged:false,evidence:root},null,2));
if(!passing.length)process.exitCode=1;
