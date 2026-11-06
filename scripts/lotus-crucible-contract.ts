/** Level 6 Crucible: independent challenge construction contract.
 * This module is grader-side only. The production investigator must never
 * import, serialize, or receive a CrucibleAnswerKey.
 */
import {createHash} from 'node:crypto';
import type {Language} from './lotus-gauntlet-fixtures';

export const CRUCIBLE_REQUIREMENTS=Object.freeze({
  minimumSourceFiles:2000,
  maximumSourceFiles:5000,
  minimumDefects:5,
  maximumDefects:8,
  minimumFalseLeads:200,
  minimumNegativeControls:50,
  minimumSealedTrials:33,
});

export type CrucibleOracleCase={
  id:string;
  language:Language;
  entryPath:string;
  affectedPaths:string[];
  weakness:string;
  reproduction:{kind:string; selector:string; expectedEffect:string};
  requiredChains:string[][];
};
export type CrucibleControl={
  id:string;
  language:Language;
  affectedPaths:string[];
  safetyReason:string;
  replayExpectation:string;
};
export type CrucibleAnswerKey={
  challengeId:string;
  seed:string;
  language:Language;
  kind:'vulnerable'|'clean';
  defects:CrucibleOracleCase[];
  falseLeads:CrucibleControl[];
  negativeControls:CrucibleControl[];
};
export type CrucibleChallenge={
  files:Record<string,string>;
  privateAnswerKey:CrucibleAnswerKey;
};

function assertUnique(ids:string[], label:string):void {
  if(ids.some(x=>!x.trim())||new Set(ids).size!==ids.length)
    throw new Error('Crucible duplicate or empty '+label);
}
function assertReferenced(paths:string[],files:Record<string,string>,label:string):void {
  for(const p of paths)if(!Object.hasOwn(files,p))
    throw new Error('Crucible '+label+' references absent source path '+p);
}

/** Check structure without using the answer key to solve or classify findings.
 * A valid manifest is not itself proof of defect reproduction.
 */
export function validateCrucibleChallenge(challenge:CrucibleChallenge):{
  language:Language;sourceFiles:number;defects:number;falseLeads:number;
  negativeControls:number;sourceSha256:string
}{
  const {files,privateAnswerKey:key}=challenge;
  const paths=Object.keys(files).filter(p=>/\.(?:sol|py|js|mjs|cjs|java)$/.test(p));
  const r=CRUCIBLE_REQUIREMENTS;
  if(!key.challengeId.trim()||!key.seed.trim())throw new Error('Crucible missing challenge identity or seed');
  if(Object.keys(files).some(p=>p.startsWith('/')||p.includes('\\')||p.split('/').some(x=>x==='..'||x==='.'||!x)))
    throw new Error('Crucible unsafe source path');
  if(paths.length<r.minimumSourceFiles||paths.length>r.maximumSourceFiles)
    throw new Error('Crucible substantive source file count outside specification: '+paths.length);
  if(paths.some(p=>typeof files[p]!=='string'||files[p].trim().split('\n').length<8))
    throw new Error('Crucible source file too small; placeholder padding not accepted');
  if(key.kind==='vulnerable'&&(key.defects.length<r.minimumDefects||key.defects.length>r.maximumDefects))
    throw new Error('Crucible vulnerable challenge requires 5–8 distinct oracle cases');
  if(key.kind==='clean'&&key.defects.length!==0)
    throw new Error('Crucible clean challenge cannot contain known oracle defects');
  if(key.falseLeads.length<r.minimumFalseLeads)
    throw new Error('Crucible insufficient realistic false leads');
  if(key.negativeControls.length<r.minimumNegativeControls)
    throw new Error('Crucible insufficient secured negative controls');
  assertUnique(key.defects.map(x=>x.id),'defect IDs');
  assertUnique(key.falseLeads.map(x=>x.id),'false-lead IDs');
  assertUnique(key.negativeControls.map(x=>x.id),'negative-control IDs');
  assertUnique([...key.defects,...key.falseLeads,...key.negativeControls].map(x=>x.id),'global oracle IDs');
  for(const d of key.defects){
    if(d.language!==key.language||!d.requiredChains.length||d.requiredChains.some(x=>x.length<2))
      throw new Error('Crucible defect requires a multi-component oracle chain');
    assertReferenced([d.entryPath,...d.affectedPaths,...d.requiredChains.flat()],files,'defect');
  }
  for(const c of [...key.falseLeads,...key.negativeControls]){
    if(c.language!==key.language||!c.safetyReason.trim()||!c.replayExpectation.trim())
      throw new Error('Crucible negative control lacks grounded counterevidence');
    assertReferenced(c.affectedPaths,files,'control');
  }
  const hash=createHash('sha256');
  for(const path of paths.sort())hash.update(path+'\0'+files[path]+'\0');
  return {language:key.language,sourceFiles:paths.length,defects:key.defects.length,
    falseLeads:key.falseLeads.length,negativeControls:key.negativeControls.length,
    sourceSha256:hash.digest('hex')};
}

/** Construct the ONLY investigator-visible package. Never return the key, seed,
 * oracle selectors, defect IDs or control classifications in this boundary.
 * Grader callers must store the private answer key in a separate process/workspace.
 */
export function createCrucibleInvestigatorPackage(challenge:CrucibleChallenge):{
  challengeId:string; language:Language; files:Record<string,string>; sourceSha256:string
}{
  const summary=validateCrucibleChallenge(challenge);
  const files=Object.create(null) as Record<string,string>;
  for(const [path,content] of Object.entries(challenge.files)){
    if(path.startsWith('/')||path.includes('\\')||path.split('/').some(x=>x==='..'||x==='.'||!x))
      throw new Error('Crucible unsafe source path '+path);
    files[path]=content;
  }
  return {challengeId:challenge.privateAnswerKey.challengeId,
    language:summary.language,files,sourceSha256:summary.sourceSha256};
}
