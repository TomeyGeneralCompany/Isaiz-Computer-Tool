import {appendFile,readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';

export type AuditEvidenceKind='source'|'probe'|'route'|'review'|'decision'|'exchange';
export interface AuditEvidenceRecord {
  version:2; id:string; kind:AuditEvidenceKind; sha256:string;
  source?:string; caseId?:string; parentIds:string[]; payload:unknown;
}
const hash=(payload:unknown)=>createHash('sha256').update(JSON.stringify(payload)).digest('hex');
const validId=(id:string)=>/^[a-f0-9]{64}$/.test(id);
const makeId=(kind:AuditEvidenceKind,sha256:string,source?:string,caseId?:string,parentIds:string[]=[]) =>
  hash({kind,sha256,source,caseId,parentIds});

/** Append-only controller evidence; payloads are never replaced by model summaries. */
export class ControllerEvidenceArchive {
  private byId=new Map<string,AuditEvidenceRecord>();
  private byCase=new Map<string,string[]>();
  private bySource=new Map<string,string[]>();
  private loaded=false;
  constructor(readonly path:string){}
  private index(record:AuditEvidenceRecord) {
    this.byId.set(record.id,record);
    if(record.caseId)this.byCase.set(record.caseId,[...(this.byCase.get(record.caseId)||[]),record.id]);
    if(record.source)this.bySource.set(record.source,[...(this.bySource.get(record.source)||[]),record.id]);
  }
  async load() {
    if(this.loaded)return;
    let content:string;
    try {content=await readFile(this.path,'utf8');}
    catch(error:any) {if(error?.code==='ENOENT'){this.loaded=true;return;}throw error;}
    for(const line of content.split('\n')) {
      if(!line.trim())continue;
      const record=JSON.parse(line) as AuditEvidenceRecord;
      if(record.version!==2||!validId(record.id)||!validId(record.sha256)||
        hash(record.payload)!==record.sha256||
        makeId(record.kind,record.sha256,record.source,record.caseId,record.parentIds)!==record.id)
        throw new Error('Controller evidence archive integrity mismatch');
      if(!this.byId.has(record.id))this.index(record);
    }
    this.loaded=true;
  }
  async append(kind:AuditEvidenceKind,payload:unknown,metadata:{
    source?:string;caseId?:string;parentIds?:string[];
  }={}) {
    await this.load();
    const parentIds=metadata.parentIds||[];
    for(const id of parentIds)if(!this.byId.has(id))throw new Error('Missing controller evidence parent');
    // Snapshot mutable controller objects before hashing: later workflow mutations
    // must never alter the evidence record or invalidate its integrity digest.
    const snapshot=JSON.parse(JSON.stringify(payload)) as unknown;
    const sha256=hash(snapshot);
    const id=makeId(kind,sha256,metadata.source,metadata.caseId,parentIds);
    if(this.byId.has(id))return id;
    const record:AuditEvidenceRecord={version:2,id,kind,sha256,
      ...(metadata.source?{source:metadata.source}:{}),
      ...(metadata.caseId?{caseId:metadata.caseId}:{}),parentIds,payload:snapshot};
    await appendFile(this.path,JSON.stringify(record)+'\n',{mode:0o600});
    this.index(record);
    return id;
  }
  async retrieve(id:string) {
    if(!validId(id))throw new Error('Invalid evidence ID');
    await this.load();
    const record=this.byId.get(id);
    if(!record)return null;
    if(hash(record.payload)!==record.sha256)throw new Error('Controller evidence archive integrity mismatch');
    return record;
  }
  async forCase(caseId:string) {
    await this.load();
    return Promise.all((this.byCase.get(caseId)||[]).map(id=>this.retrieve(id)));
  }
  async forSource(source:string) {
    await this.load();
    return Promise.all((this.bySource.get(source)||[]).map(id=>this.retrieve(id)));
  }
  /** Controller-directed bounded retrieval. Only selected source/case records
   * enter active memory; the original full record remains available by ID. */
  async retrieveRelevant(options:{caseId?:string;source?:string;kinds?:AuditEvidenceKind[];maxRecords?:number;maxCharacters?:number}) {
    await this.load();
    const ids=options.caseId?this.byCase.get(options.caseId)||[]:
      options.source?this.bySource.get(options.source)||[]:[...this.byId.keys()];
    const maxRecords=Math.max(1,Math.min(options.maxRecords??8,32));
    const maxCharacters=Math.max(256,Math.min(options.maxCharacters??12000,65536));
    const selected: Array<{id:string;kind:AuditEvidenceKind;source?:string;caseId?:string;excerpt:string;truncated:boolean}>=[];
    let remaining=maxCharacters;
    for(const id of ids.slice().reverse()) {
      if(selected.length>=maxRecords||remaining<=0)break;
      const record=await this.retrieve(id);
      if(!record || (options.source&&record.source!==options.source) ||
        (options.kinds&&!options.kinds.includes(record.kind)))continue;
      const original=JSON.stringify(record.payload);
      const excerpt=original.slice(0,remaining);
      selected.push({id,kind:record.kind,source:record.source,caseId:record.caseId,
        excerpt,truncated:excerpt.length<original.length});
      remaining-=excerpt.length;
    }
    return selected;
  }
  async references(caseId?:string) {
    await this.load();
    const ids=caseId?this.byCase.get(caseId)||[]:[...this.byId.keys()];
    return ids.map(id=>{const r=this.byId.get(id)!;return {id,kind:r.kind,source:r.source,caseId:r.caseId,sha256:r.sha256};});
  }
}

/** Legacy exchange retrieval, with independent SHA-256 verification. */
export async function retrieveArchivedAuditExchange(archivePath:string,sha256:string):Promise<unknown|null> {
  if(!validId(sha256))throw new Error('Invalid archive digest');
  let content:string;
  try {content=await readFile(archivePath,'utf8');}
  catch(error:any) {if(error?.code==='ENOENT')return null;throw error;}
  for(const line of content.split('\n')) {
    if(!line.trim())continue;
    const record=JSON.parse(line) as {version:number;sha256:string;exchange:unknown};
    if(record.version!==1||record.sha256!==sha256)continue;
    if(hash(record.exchange)!==sha256)throw new Error('Archived audit exchange integrity mismatch');
    return record.exchange;
  }
  return null;
}
