import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { join, resolve, relative, sep } from "node:path";
import { lstat, realpath } from "node:fs/promises";

const execute = promisify(execFile);

import { authorizedSourceUrls } from "@bounty/core";
export { authorizedSourceUrls };

export function submoduleSourceUrl(parent:string,value:string):string {
  const url=value.startsWith("./") || value.startsWith("../") ? new URL(value,parent.replace(/\/$/,"")+"/").href : value;
  if(!authorizedSourceUrls([{assetType:"SOURCE_CODE",eligibleForBounty:true,assetIdentifier:url}]).includes(url.replace(/\/$/,"")))
    throw new Error("Unsupported submodule repository URL");
  return url.replace(/\/$/,"");
}
export async function cloneAuthorizedSource(url: string, destination: string, options: { signal?: AbortSignal; commit?: string } = {}): Promise<void> {
  if (!authorizedSourceUrls([{assetType:"SOURCE_CODE", eligibleForBounty:true,
    assetIdentifier:url}]).includes(url)) throw new Error("Invalid authorized source repository URL");
  if (options.commit && !/^[a-f0-9]{40}$/.test(options.commit)) throw new Error("Invalid recorded source commit");
  options.signal?.throwIfAborted();
  // Do not inherit credential helpers, URL rewrite rules, hooks, or a global
  // Git configuration from the operator's shell. Never execute repository code.
  const env = {...process.env};
  for (const key of Object.keys(env)) if (key.startsWith("GIT_")) delete env[key];
  const gitConfig = ["-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
    "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "-c", "http.followRedirects=false"];
  const execution = {
    cwd: join(destination, ".."), timeout: 90_000, maxBuffer: 256 * 1024, signal: options.signal,
    env: {...env, GIT_CONFIG_NOSYSTEM:"1", GIT_CONFIG_GLOBAL:"/dev/null",
      GIT_TERMINAL_PROMPT:"0", GIT_LFS_SKIP_SMUDGE:"1"},
  };
  await execute("git", [...gitConfig, "clone", "--depth", "1", "--single-branch", "--", url, destination], execution);
  if (options.commit) {
    options.signal?.throwIfAborted();
    await execute("git", [...gitConfig, "fetch", "--depth", "1", "--no-tags", "--", "origin", options.commit],
      {...execution, cwd: destination});
    await execute("git", [...gitConfig, "checkout", "--detach", options.commit], {...execution, cwd: destination});
  }
  let submoduleCount=0;
  async function materialize(directory:string,parentUrl:string,depth:number):Promise<void> {
    options.signal?.throwIfAborted();
    const modules=join(directory,".gitmodules");
    let info;
    try {info=await lstat(modules);}catch(error:any){if(error.code==="ENOENT")return;throw error;}
    if(!info.isFile() || info.size>256000)throw new Error("Invalid submodule manifest");
    if(depth>=4)throw new Error("Submodule nesting exceeds four levels");
    let output:string;
    try {output=(await execute("git",[...gitConfig,"config","--no-includes","--null","--file",modules,"--get-regexp","^submodule\\..*\\.(path|url)$"],{...execution,cwd:directory})).stdout;}
    catch(error:any){if(error.code===1)return;throw error;}
    const entries=new Map<string,{path?:string;url?:string}>();
    for(const item of output.split("\0").filter(Boolean)) {
      const split=item.indexOf("\n"),key=item.slice(0,split),value=item.slice(split+1);
      const match=/^submodule\.([A-Za-z0-9_./-]+)\.(path|url)$/.exec(key);
      if(split<0 || !match)throw new Error("Invalid submodule configuration");
      const entry=entries.get(match[1]) || {};entry[match[2] as "path"|"url"]=value;entries.set(match[1],entry);
    }
    for(const [name,entry] of entries) {
      if(++submoduleCount>32)throw new Error("Submodule count exceeds 32");
      if(!entry.path || !entry.url || entry.path.split("/").some(p=>!p || p===".." || p===".") || entry.path.includes("\\"))throw new Error("Invalid submodule path");
      const child=resolve(directory,entry.path),rel=relative(directory,child);
      if(rel.startsWith(".."+sep)||rel===".."||rel.startsWith(sep))throw new Error("Submodule path escapes repository");
      let current=directory;
      for(const part of entry.path.split("/")) {
        current=join(current,part);
        try {if((await lstat(current)).isSymbolicLink())throw new Error("Submodule path is a symlink");}
        catch(error:any){if(error.code!=="ENOENT")throw error;}
      }
      const url=submoduleSourceUrl(parentUrl,entry.url);
      await execute("git",[...gitConfig,"-c",`submodule.${name}.url=${url}`,"submodule","update","--init","--checkout","--depth","1","--",entry.path],{...execution,cwd:directory});
      const actual=await realpath(child);
      if(actual!==child)throw new Error("Submodule checkout left repository path");
      await materialize(child,url,depth+1);
    }
  }
  await materialize(destination,url,0);

}
