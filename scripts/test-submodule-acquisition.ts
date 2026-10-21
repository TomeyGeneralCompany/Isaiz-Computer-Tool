import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,chmod,rm} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {cloneAuthorizedSource,submoduleSourceUrl} from '../packages/security-solver/src/authorized-source';
assert.equal(submoduleSourceUrl('https://github.com/owner/root','../library.git'),'https://github.com/owner/library.git');
for(const url of ['file:///tmp/x','ssh://git@github.com/owner/x','https://evil.invalid/x','https://github.com/owner/x?extra=1'])assert.throws(()=>submoduleSourceUrl('https://github.com/owner/root',url));
const root=await mkdtemp(join(tmpdir(),'submodule-fixture-')),old=process.env.PATH;
const realGit=execFileSync('which',['git'],{encoding:'utf8'}).trim();
try {
 const bin=join(root,'bin');await mkdir(bin);
 await writeFile(join(bin,'git'),`#!/usr/bin/env python3
import os,sys,json,pathlib
args=sys.argv[1:]
with open(${JSON.stringify(join(root,'calls'))},'a') as f:f.write(json.dumps(args)+'\\n')
if 'clone' in args:
 p=pathlib.Path(args[-1]);p.mkdir()
 (p/'.gitmodules').write_text('[submodule "library"]\\npath = lib/library\\nurl = ../library.git\\nupdate = !never-execute-me\\n')
elif 'config' in args:
 os.execv(${JSON.stringify(realGit)},[${JSON.stringify(realGit)}]+args)
elif 'submodule' in args:
 p=pathlib.Path.cwd()/args[-1];p.mkdir(parents=True)
 (p/'Library.sol').write_text('pragma solidity ^0.8.0; library Library {}')
else:
 raise Exception('Unexpected git invocation')
`);await chmod(join(bin,'git'),0o700);process.env.PATH=bin+':'+old;
 await cloneAuthorizedSource('https://github.com/owner/root',join(root,'checkout'));
 const calls=(await readFile(join(root,'calls'),'utf8')).trim().split('\n').map(x=>JSON.parse(x));
 const update=calls.find(x=>x.includes('submodule'));
 assert.ok(update.includes('--checkout'));assert.ok(!update.includes('--recursive'));
 assert.ok(update.includes('submodule.library.url=https://github.com/owner/library.git'));
 assert.match(await readFile(join(root,'checkout/lib/library/Library.sol'),'utf8'),/library Library/);
 console.log('Submodule URLs, declarative manifests, bounded checkout and dependency materialization PASSED');
} finally {process.env.PATH=old;await rm(root,{recursive:true,force:true});}
