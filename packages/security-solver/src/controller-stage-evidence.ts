import {createHash} from 'node:crypto';
export interface IndexedSource {path:string;sha256:string;characters:number}
export interface SourceRead {path:string;start:number;end:number;totalCharacters:number;text:string}
const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
export class ControllerSourceCoverage {
  private index=new Map<string,IndexedSource>();
  private ranges=new Map<string,[number,number,string][]>();
  private frozen=false;
  finishIndex(files:readonly IndexedSource[]){
    if(this.frozen||!files.length)throw new Error('INVALID_SOURCE_INDEX');
    for(const file of files){
      if(!/^source-[0-9]+\/.+\.(sol|java|py|js|mjs|cjs)$/.test(file.path)||
        file.path.split('/').includes('..')||!Number.isSafeInteger(file.characters)||
        file.characters<0||!/^[0-9a-f]{64}$/.test(file.sha256)||
        this.index.has(file.path))throw new Error('INVALID_INDEX_ENTRY');
      this.index.set(file.path,Object.freeze({...file}));
    }
    this.frozen=true;
  }
  get indexed(){return this.frozen;}
  get count(){return this.index.size;}
  record(page:SourceRead){
    if(!this.frozen)throw new Error('SOURCE_NOT_INDEXED');
    const file=this.index.get(page.path);
    if(!file||!Number.isSafeInteger(page.start)||!Number.isSafeInteger(page.end)||
      page.start<0||page.end<page.start||page.end>file.characters||
      page.totalCharacters!==file.characters||typeof page.text!=='string'||
      page.text.length!==page.end-page.start)throw new Error('INVALID_SOURCE_READ');
    const previous=this.ranges.get(page.path)||[];
    previous.push([page.start,page.end,hash(page.text)]);
    this.ranges.set(page.path,previous);
  }
  complete(path:string){
    const file=this.index.get(path),ranges=this.ranges.get(path);
    if(!file||!ranges?.length)return false;
    if(file.characters===0)return ranges.some(([a,b])=>a===0&&b===0);
    let offset=0;
    for(const [a,b] of [...ranges].sort((x,y)=>x[0]-y[0])){
      if(a>offset)return false;
      offset=Math.max(offset,b);
    }
    return offset===file.characters;
  }
  get completedCount(){return [...this.index.keys()].filter(p=>this.complete(p)).length;}
  get allComplete(){return this.frozen&&this.completedCount===this.index.size;}
  async assertUnchanged(read:(p:string)=>Promise<string>){
    if(!this.allComplete)throw new Error('READ_INCOMPLETE');
    for(const file of this.index.values()){
      const content=await read(file.path);
      if(content.length!==file.characters||hash(content)!==file.sha256)
        throw new Error('SOURCE_CHANGED_DURING_READ: '+file.path);
      for(const [start,end,pageHash] of this.ranges.get(file.path)||[])
        if(hash(content.slice(start,end))!==pageHash)
          throw new Error('SOURCE_PAGE_MISMATCH: '+file.path+' at '+start);
    }
  }
}
