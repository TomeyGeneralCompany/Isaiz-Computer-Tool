import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm,symlink,mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {prioritizeSourceCandidates} from '../packages/security-solver/src/source-candidates';
import {normalizeForcedOutlineCursor} from '../packages/security-solver/src/outline-cursor';
import {AuditNavigation} from '../packages/security-solver/src/audit-navigation';
import {collectStaticLeads} from '../packages/security-solver/src/local-static-leads';
const root=await mkdtemp(join(tmpdir(),'candidate-selection-'));
try {
  const paths=Array.from({length:200},(_,i)=>`file-${i}.py`);
  const source='# Unicode: 🦁\n'+'# unrelated\n'.repeat(100)+'def candidate(value):\n    return value\n';
  await Promise.all(paths.map(path=>writeFile(join(root,path),source)));
  const result=await prioritizeSourceCandidates(root,paths,paths.slice(0,8),[
    {path:paths[199],line:102,rule:'upstream-rule',message:'Inspect input handling'},
    {path:'../outside.py',line:1},{path:paths[198],line:-1}]);
  assert.equal(result.paths[0],paths[199],'A match beyond the old 128-file map must be first');
  assert.equal(result.paths.length,8);
  assert.equal(result.locations[0].line,99);
  assert.equal(source.slice(0,result.locations[0].offset).split('\n').length,99);
  assert(!result.paths.includes('../outside.py'));
  // Overnight 88mphV3 investigation first consumed an imported Solidity
  // library rather than the reachable application contract. Signature matches
  // in supporting libraries must not displace real application candidates.
  const application='contracts/protocol/Treasury.sol';
  const library='contracts/libs/ERC1155Upgradeable.sol';
  const imported='contracts/rewards/dumpers/imports/Curve.sol';
  for(const path of [application,library,imported])
    await mkdir(join(root,path,'..'),{recursive:true});
  const stateful=(contract:string)=>'pragma solidity ^0.8.20; contract '+contract+
    ' { function settle(address user) external { } }';
  await writeFile(join(root,application),stateful('Treasury'));
  await writeFile(join(root,library),stateful('ERC1155Upgradeable'));
  await writeFile(join(root,imported),stateful('Curve'));
  const solidityRank=await prioritizeSourceCandidates(root,
    [library,imported,application],[library,imported,application],[]);
  assert.equal(solidityRank.paths[0],application,
    'Application contract must outrank compatible imported library contracts');
  assert(solidityRank.paths.includes(library),'Supporting libraries must remain inspectable');
  assert(solidityRank.paths.includes(imported),'Imported dependencies must remain inspectable');
  // A complete top-eight navigation window must favor application source
  // across the four supported languages even when dependency files have
  // convenient probe signatures and arrive first in a static-lead list.
  const layouts=[
    {
      language:'python',
      application:'src/services/MessageRenderer.py',
      dependency:'src/vendor/htmltool/LegacyRenderer.py',
      generated:'src/build/GeneratedRenderer.py',
      source:'def render(value):\n    return "<p>" + value + "</p>"\n'
    },
    {
      language:'javascript',
      application:'src/routes/message.js',
      dependency:'src/node_modules/htmltool/renderer.js',
      generated:'dist/renderer.js',
      source:'export function render(value) { return "<p>" + value + "</p>"; }\n'
    },
    {
      language:'java',
      application:'src/main/java/com/tomey/api/MessageRenderer.java',
      dependency:'src/main/java/com/tomey/vendor/LegacyRenderer.java',
      generated:'src/test/java/com/tomey/api/GeneratedRenderer.java',
      source:'public class Renderer { public static String render(String input) { return input; } }\n'
    },
    {
      language:'solidity',
      application:'contracts/protocol/MessageVault.sol',
      dependency:'contracts/libs/MessageLibrary.sol',
      generated:'contracts/tests/MockMessageVault.sol',
      source:'pragma solidity ^0.8.20; contract MessageVault { function render(string memory input) public pure returns (string memory) { return input; } }\n'
    }
  ];
  for(const layout of layouts){
    // More supporting sources than the navigation window could contain.
    // The exact application path must be chosen, not merely left eligible.
    const filler=Array.from({length:9},(_,i)=>{
      const basename='Legacy'+String(i).padStart(2,'0');
      return layout.dependency.replace(/[^/]+$/,basename+layout.dependency.slice(layout.dependency.lastIndexOf('.')));
    });
    const paths=[...filler,layout.dependency,layout.generated,layout.application];
    for(const path of paths){
      await mkdir(join(root,path,'..'),{recursive:true});
      await writeFile(join(root,path),layout.source);
    }
    const ranked=await prioritizeSourceCandidates(root,paths,paths.slice(0,8),
      [{path:layout.dependency,line:1,rule:'unverified-scan-lead'}]);
    assert.equal(ranked.paths[0],layout.application,
      layout.language+': application must lead even when vendor has a detector hit');
    assert(!ranked.paths.includes(layout.generated),
      layout.language+': generated/test source must not displace application source');
    assert.equal(ranked.paths.length,8,layout.language+': preserve eight-file selection');
    // Only dependency sources: fallback still produces inspection candidates.
    const dependenciesOnly=await prioritizeSourceCandidates(root,paths.slice(0,10),paths.slice(0,8),[]);
    assert.equal(dependenciesOnly.paths.length,8,
      layout.language+': supporting-only repositories remain inspectable');
  }
  // read_file uses character offsets, but outline_solidity uses an item cursor.
  // Forced outlines always start at the first declaration; discretionary
  // outline pagination retains the model's item offset.
  assert.equal(normalizeForcedOutlineCursor('outline_solidity',10506,['outline_solidity']),0);
  assert.equal(normalizeForcedOutlineCursor('outline_solidity',4,['outline_solidity','read_file']),4);
  assert.equal(normalizeForcedOutlineCursor('read_file',10506,['read_file']),10506);
  const nav=new AuditNavigation();nav.seed(result.paths,result.locations);
  assert.equal(nav.snapshot().next[0].offset,result.locations[0].offset);
  nav.observe('read_file',paths[199],result.locations[0].offset,'',{nextOffset:result.locations[0].offset+156});
  assert.equal(nav.snapshot().next.find(item=>item.path===paths[199])?.offset,result.locations[0].offset+156,'Chunk continuation remains active');
  const fallback=await prioritizeSourceCandidates(root,paths,paths.slice(8,16),[]);
  assert.deepEqual(fallback.paths,paths.slice(8,16));
  // A probe-compatible Java method outranks equally prioritized callback-only files.
  await writeFile(join(root,'Callback.java'),'public class Callback { public void onUpdate(int x) {} }');
  await writeFile(join(root,'Compatible.java'),'public class Compatible { public static String reflect(String input) { return input; } }');
  const javaRank=await prioritizeSourceCandidates(root,['Callback.java','Compatible.java'],['Callback.java','Compatible.java'],[]);
  assert.equal(javaRank.paths[0],'Compatible.java','rank a compatible signature before unsupported callbacks');
  const focused=await prioritizeSourceCandidates(root,paths,[],[{path:paths[199],line:102}],paths[5]);
  assert.equal(focused.paths[0],paths[5]);
  await symlink('/etc/passwd',join(root,'outside.py'));
  assert.equal((await prioritizeSourceCandidates(root,['outside.py'],['outside.py'],[])).paths.length,0);
  const previous=process.env.PROJECT_ROOT;
  try {
    process.env.PROJECT_ROOT=root;
    const unavailable=await collectStaticLeads(root,[],[],join(root,'cache.json'),new AbortController().signal);
    assert.equal(unavailable.status,'unavailable','Missing optional scanners must not abort source inspection');
    assert.deepEqual(unavailable.leads,[]);
  } finally {if(previous===undefined)delete process.env.PROJECT_ROOT;else process.env.PROJECT_ROOT=previous;}
  console.log('Candidate prioritization, bounded offsets, scope boundaries and chunk continuation PASSED');
} finally {await rm(root,{recursive:true,force:true});}
