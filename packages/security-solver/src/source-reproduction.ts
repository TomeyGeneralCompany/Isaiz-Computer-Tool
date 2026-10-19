import { createHash, randomBytes } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { authorizedSourceUrls, targetInExplicitScope, type SecurityProgram } from "@bounty/core";

const execute = promisify(execFile);
const driver = fileURLToPath(new URL("../../../scripts/source-reproduction.py",import.meta.url));
const sha = (value:string | Buffer) => createHash("sha256").update(value).digest("hex");
const digest = z.string().regex(/^[a-f0-9]{64}$/);
const specSchema = z.object({file:z.string().min(1).max(4096),function:z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,79}$/),
  kind:z.enum(["html_reflection","path_construction"]),nonce:z.string().regex(/^[a-f0-9]{32}$/)}).strict();
const resultSchema = z.object({status:z.string(),behavior_observed:z.boolean(),source_sha256:digest.optional(),
  kind:z.string().optional(),observations:z.object({control_input:z.string(),control_output:z.string(),attack_input:z.string(),attack_output:z.string()}).optional(),
  limitation:z.string().optional(),detail:z.string().optional(),exit_code:z.number().optional()});
const caseSchema = z.object({version:z.literal(1),programId:z.string(),repositoryUrl:z.string(),commit:z.string().regex(/^[a-f0-9]{40}$/),
  sourceSha256:digest,spec:specSchema,result:resultSchema});
export type SourceCase = z.infer<typeof caseSchema>;
export type ProbeRepository = {directory:string;url:string};
function caseDirectory():string {return join(process.env.PROJECT_ROOT || process.cwd(),"data","reproduction");}
export function sourceCaseId(record:SourceCase):string {return sha(JSON.stringify(record));}

async function commitAt(directory:string):Promise<string> {
  const result = await execute("git",["-c","core.hooksPath=/dev/null","rev-parse","HEAD"],{
    cwd:directory,timeout:10000,maxBuffer:4096,env:{PATH:process.env.PATH,GIT_CONFIG_NOSYSTEM:"1",GIT_CONFIG_GLOBAL:"/dev/null"},
  });
  return z.string().regex(/^[a-f0-9]{40}$/).parse(result.stdout.trim());
}
async function executeProbe(directory:string,spec:z.infer<typeof specSchema>):Promise<z.infer<typeof resultSchema>> {
  const temporary = await mkdtemp(join(caseDirectory(),"pending-"));
  try {
    const path=join(temporary,"spec.json");
    await writeFile(path,JSON.stringify(spec),{mode:0o600});
    let output:string;
    try {
      output=(await execute("python3",[driver,"--repository",directory,"--spec",path],{
        timeout:35000,maxBuffer:128000,env:{PATH:process.env.PATH},
      })).stdout;
    } catch(error:any) {
      if(typeof error.stdout!=="string" || !error.stdout.trim()) throw new Error("Source reproduction process failed or timed out");
      output=error.stdout;
    }
    return resultSchema.parse(JSON.parse(output));
  } finally {await rm(temporary,{recursive:true,force:true});}
}
export async function readSourceCase(id:string,program:SecurityProgram):Promise<SourceCase> {
  digest.parse(id);
  const record=caseSchema.parse(JSON.parse(await readFile(join(caseDirectory(),id+".json"),"utf8")));
  if(sourceCaseId(record)!==id || record.programId!==program.id) throw new Error("Reproduction record does not match finding/program");
  let scopes:unknown=[];try {const parsed=JSON.parse(program.scopeSummary || "{}");scopes=Array.isArray(parsed)?parsed:parsed.scopes;}catch{}
  if(!authorizedSourceUrls(scopes).includes(record.repositoryUrl) || !targetInExplicitScope(program.scopeSummary,record.repositoryUrl+"/"+record.spec.file))
    throw new Error("Reproduction source is outside current program scope");
  if(!record.result.behavior_observed || record.result.source_sha256!==record.sourceSha256 || !record.result.observations)
    throw new Error("Reproduction case has no successful observation");
  return record;
}
export async function createProbeSession(program:SecurityProgram,workspace:string,repositories:ProbeRepository[]) {
  await mkdir(caseDirectory(),{recursive:true,mode:0o700});
  const cases = new Map<string,SourceCase>();
  const workspaceRoot=await realpath(workspace);
  const probe=async(path:string,functionName:string,kind:string):Promise<string> => {
    const file=await realpath(resolve(workspaceRoot,path));
    const repo = repositories.find(candidate => {
      const rel=relative(candidate.directory,file);
      return rel && rel!==".." && !rel.startsWith(".."+sep) && !rel.startsWith(sep);
    });
    if(!repo) throw new Error("Probe file is not in an acquired source repository");
    const filePath=relative(repo.directory,file).split(sep).join("/");
    const spec=specSchema.parse({file:filePath,function:functionName,kind,nonce:randomBytes(16).toString("hex")});
    if(!targetInExplicitScope(program.scopeSummary,repo.url+"/"+filePath))throw new Error("Probe is outside program scope");
    const commit=await commitAt(repo.directory);
    const sourceSha256=sha(await readFile(file));
    const result=await executeProbe(repo.directory,spec);
    if(!result.behavior_observed)return JSON.stringify(result);
    if(result.source_sha256!==sourceSha256 || sha(await readFile(file))!==sourceSha256)throw new Error("Reproduction source changed");
    const record=caseSchema.parse({version:1,programId:program.id,repositoryUrl:repo.url,commit,sourceSha256,spec,result});
    const id=sourceCaseId(record);
    const temporary=join(caseDirectory(),id+"."+process.pid+".tmp");
    await writeFile(temporary,JSON.stringify(record),{mode:0o600});
    await rename(temporary,join(caseDirectory(),id+".json"));
    cases.set(id,record);
    return JSON.stringify({caseId:id,...result});
  };
  return {cases,probe};
}
export async function replaySourceCase(record:SourceCase,directory:string):Promise<z.infer<typeof resultSchema>> {
  if(await commitAt(directory)!==record.commit)throw new Error("Reproduction commit changed before review");
  const file=await realpath(resolve(directory,record.spec.file));
  const rel=relative(await realpath(directory),file);
  if(rel===".." || rel.startsWith(".."+sep) || sha(await readFile(file))!==record.sourceSha256)throw new Error("Reproduction source changed before review");
  const result=await executeProbe(directory,record.spec);
  if(!result.behavior_observed || result.source_sha256!==record.sourceSha256 ||
     JSON.stringify(result.observations)!==JSON.stringify(record.result.observations))throw new Error("Independent reproduction did not match recorded observation");
  return result;
}
