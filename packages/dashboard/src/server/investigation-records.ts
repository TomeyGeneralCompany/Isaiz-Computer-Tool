import {readdir,lstat,readFile} from 'node:fs/promises';
import {join} from 'node:path';
/** Read application-authored records only; never accept a filesystem path from a client. */
export async function readInvestigationRecords(directory:string,programId:string) {
  const names=await readdir(directory).catch(()=>[] as string[]);
  const candidates=await Promise.all(names.filter(n=>/^local-hunt-[a-f0-9]{16}\.log\.summary\.json$/.test(n)).map(async name=>{
    const info=await lstat(join(directory,name)).catch(()=>null);
    return info?.isFile()&&!info.isSymbolicLink()&&info.size<=2_000_000?{name,modified:info.mtimeMs}:null;
  }));
  const records=[];
  for(const candidate of candidates.filter(x=>x!==null).sort((a,b)=>b.modified-a.modified).slice(0,200)) {
    const logName=candidate.name.replace(/\.summary\.json$/,'');
    try {
      const logPath=join(directory,logName),info=await lstat(logPath);
      if(!info.isFile()||info.isSymbolicLink()||info.size>8_000_000)continue;
      const log=await readFile(logPath,'utf8');
      const marker=log.split('\n').find(line=>line.startsWith('[AUDIT_PROGRAM] '));
      if(!marker||JSON.parse(marker.slice(16)).id!==programId)continue;
      const summary=JSON.parse(await readFile(join(directory,candidate.name),'utf8'));
      const activityPath=logPath+'.activity.jsonl';
      const activityInfo=await lstat(activityPath).catch(()=>null);
      const activity=activityInfo?.isFile()&&!activityInfo.isSymbolicLink()&&activityInfo.size<=8_000_000
        ?await readFile(activityPath,'utf8'):'';
      const events=activity.split('\n').filter(l=>l.startsWith('[ACTIVITY] ')).flatMap(l=>{try{return [JSON.parse(l.slice(11))];}catch{return [];}});
      const extensions=log.split('\n').filter(l=>l.startsWith('[ALLOWANCE_EXTENDED] ')).flatMap(l=>{try{return [JSON.parse(l.slice(21))];}catch{return [];}});
      records.push({id:logName,programId,...summary,events:events.slice(0,5000),extensions,
        recordLimited:events.length>5000||!!(activityInfo&&activityInfo.size>8_000_000),
        limitation:'Coverage describes only delivered source and recorded tests. Hypotheses are model claims, not verified findings. A completed pass does not establish that a repository has no flaws.'});
      if(records.length===20)break;
    }catch { /* An incomplete write must not hide other completed records. */ }
  }
  return records;
}
