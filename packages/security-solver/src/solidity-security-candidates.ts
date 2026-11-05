/** Narrow, source-supported authorization candidate detector.
 * It proposes a local differential test, never a finding. Missing code,
 * ambiguous role storage, or no privileged consumer produces no candidate.
 */
export function privilegedRoleMutationCandidate(
  file:string, source:string, authorizedSources:string[]
):{selector:string;role:string;method:string}|null {
  if(!file.endsWith('.sol') || source.length>256000 || !authorizedSources.length)return null;
  const contract=/\bcontract\s+([A-Za-z_]\w*)\b/.exec(source)?.[1];
  if(!contract)return null;
  const roles=[...source.matchAll(/\baddress\s+public\s+([A-Za-z_]\w*)\s*;/g)]
    .map(m=>m[1]).filter(role=>/^(?:operator|owner|administrator|admin|manager|guardian|controller|authority)$/i.test(role));
  for(const role of roles){
    if(!authorizedSources.some(text=>
      text.length<=256000 && new RegExp('\\brequire\\s*\\(\\s*msg\\s*\\.\\s*sender\\s*==\\s*'+role+'\\b').test(text)))continue;
    for(const match of source.matchAll(/\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)[^{;]*\{/g)) {
      if(!/\b(?:external|public)\b/.test(match[0]))continue;
      const start=match.index!+match[0].length;
      const end=source.indexOf('}',start);
      if(end<0||end-start>6000)continue;
      const body=source.slice(start,end);
      if(!new RegExp('\\b'+role+'\\s*=\\s*[A-Za-z_]\\w*\\s*;').test(body))continue;
      if(/msg\s*\.\s*sender|onlyOwner|onlyAdmin|onlyRole|hasRole|_checkRole/.test(match[0]+body))continue;
      return {selector:contract+'.'+match[1],role,method:match[1]};
    }
  }
  return null;
}
