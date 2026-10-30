import { parse, visit } from '@solidity-parser/parser';
import type { ASTNode, BaseASTNode, ContractDefinition, FunctionDefinition, ImportDirective } from '@solidity-parser/parser/dist/src/ast-types';
import { readFile, realpath, stat } from 'node:fs/promises';
import { dirname, relative, resolve, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const exec = promisify(execFile);
type Parsed = { text:string; ast:ReturnType<typeof parse> };
type Unit = Parsed & { path:string; imports:Map<ImportDirective,Unit>; unresolved:string[] };
type Definition = { unit:Unit; contract:ContractDefinition };
export type SourceExcerpt = { path:string; start:number; end:number; text:string };
const cache = new Map<string,Parsed>();
let cacheBytes=0;
const MAX_FILE=512_000, MAX_GRAPH=4_000_000;
const note='AST navigation is not compiler binding or proof of full coverage. Context includes all state/type declarations in resolved bases; helper candidates require explicit reads. Use read_file/search_files for unresolved dependencies.';
function bounds(node:BaseASTNode):[number,number] {
  if(!node.range)throw new Error('Parser omitted source ranges');
  return [node.range[0],node.range[1]+1];
}
function label(fn:FunctionDefinition):string {
  return fn.isConstructor?'constructor':fn.isReceiveEther?'receive':fn.isFallback?'fallback':fn.name || '<anonymous>';
}
/** Cache ASTs by commit AND content, bounded to 4 MB of source / 32 entries.
 * In-process only: untrusted persisted ASTs are never loaded as evidence. */
export class SoliditySourceIndex {
  private units=new Map<string,Promise<Unit>>();
  private bytes=0;
  constructor(private root:string, private signal?:AbortSignal) {}
  private async load(path:string):Promise<Unit> {
    this.signal?.throwIfAborted();
    const full=await realpath(path);
    const rel=relative(this.root,full);
    if(rel==='..'||rel.startsWith('..'+sep)||!full.endsWith('.sol'))throw new Error('Source is outside the Solidity workspace');
    const prior=this.units.get(full);if(prior)return prior;
    if(this.units.size>=32)throw new Error('Import index exceeds 32 files; use the paginated reader');
    const pending=(async()=>{
      const info=await stat(full);
      if(!info.isFile() || info.size>MAX_FILE || this.bytes+info.size>MAX_GRAPH)throw new Error('AST size limit reached; use the paginated reader');
      this.bytes+=info.size;
      const text=await readFile(full,'utf8');
      let revision='uncommitted';
      try {revision=(await exec('git',['-c','core.hooksPath=/dev/null','rev-parse','HEAD'],{cwd:dirname(full),timeout:2000,maxBuffer:1024})).stdout.trim();}catch{}
      const key=createHash('sha256').update('parser-0.20.2\0'+revision+'\0'+text).digest('hex');
      let parsed=cache.get(key);
      if(parsed) {cache.delete(key);cache.set(key,parsed);}
      else {
        this.signal?.throwIfAborted();
        parsed={text,ast:parse(text,{range:true,loc:true})};
        cache.set(key,parsed);cacheBytes+=Buffer.byteLength(text);
        while(cache.size>32 || cacheBytes>MAX_GRAPH) {
          const first=cache.keys().next().value!;cacheBytes-=Buffer.byteLength(cache.get(first)!.text);cache.delete(first);
        }
      }
      return {...parsed,path:rel.split(sep).join('/'),imports:new Map<ImportDirective,Unit>(),unresolved:[]};
    })();
    this.units.set(full,pending);return pending;
  }
  private async graph(path:string):Promise<Unit> {
    const entry=await this.load(path), seen=new Set<Unit>();
    const walk=async(unit:Unit):Promise<void>=>{
      if(seen.has(unit))return;seen.add(unit);
      for(const node of unit.ast.children) {
        if(node.type!=='ImportDirective')continue;
        try {
          // Remapped/package imports require compiler-specific resolution; never guess.
          if(!node.path.startsWith('.'))throw new Error('package/remapped import needs explicit resolution');
          const imported=await this.load(resolve(this.root,dirname(unit.path),node.path));
          unit.imports.set(node,imported);await walk(imported);
        } catch(error) {
          this.signal?.throwIfAborted();
          const message=`${unit.path}: import ${node.path}: ${String(error).slice(0,160)}`;
          if(!unit.unresolved.includes(message))unit.unresolved.push(message);
        }
      }
    };
    await walk(entry);return entry;
  }
  private resolveBase(unit:Unit,name:string):Definition|undefined {
    const matches:Definition[]=[];
    const add=(from:Unit,original:string)=>{
      for(const node of from.ast.children)if(node.type==='ContractDefinition'&&node.name===original)matches.push({unit:from,contract:node});
    };
    add(unit,name);
    for(const [directive,imported] of unit.imports) {
      if(directive.unitAlias) {
        const prefix=directive.unitAlias+'.';if(name.startsWith(prefix))add(imported,name.slice(prefix.length));
      } else if(directive.symbolAliases) {
        for(const [original,alias] of directive.symbolAliases)if((alias||original)===name)add(imported,original);
      } else add(imported,name);
    }
    // Ambiguous aliases/names are surfaced instead of selecting an arbitrary base.
    return matches.length===1?matches[0]:undefined;
  }
  /** Exact source declaration check for model-proposed Contract.function targets.
   * This is navigation validation, not a claim that the method is executable. */
  async hasFunction(path:string,selector:string):Promise<boolean> {
    const unit=await this.load(path);
    for(const node of unit.ast.children) {
      if(node.type!=='ContractDefinition')continue;
      for(const member of node.subNodes) {
        if(member.type==='FunctionDefinition' && selector===node.name+'.'+label(member as FunctionDefinition))return true;
      }
    }
    return false;
  }
  async outline(path:string,offset:number,budget:number) {
    const unit=await this.load(path);
    const items:Array<Record<string,unknown>>=[];
    const add=(node:BaseASTNode,contract?:ContractDefinition)=>{
      const [start,end]=bounds(node), source=unit.text.slice(start,end);
      const fn=node.type==='FunctionDefinition'?node as FunctionDefinition:undefined;
      items.push({id:'s'+start,kind:node.type,contract:contract?.name,start,end,line:node.loc?.start.line,
        signature:source.slice(0,fn?.body?bounds(fn.body)[0]-start:source.indexOf('{')>=0?source.indexOf('{'):200).replace(/\s+/g,' ').slice(0,200),
        ...(fn?{name:label(fn),visibility:fn.visibility,modifiers:fn.modifiers.map(m=>m.name)}:{})});
    };
    for(const node of unit.ast.children) {
      add(node);
      if(node.type==='ContractDefinition')for(const child of node.subNodes)add(child,node);
    }
    if(offset>items.length)throw new Error('Outline offset exceeds item count');
    const result={path:unit.path,items:[] as typeof items,nextOffset:null as number|null,totalItems:items.length,note:'Select a function ID with read_solidity. Outline metadata does not count as inspected source.'};
    let cursor=offset;
    while(cursor<items.length) {
      result.items.push(items[cursor]);result.nextOffset=cursor+1<items.length?cursor+1:null;
      if(JSON.stringify(result).length>budget) {result.items.pop();result.nextOffset=cursor;break;}
      cursor++;
    }
    if(cursor===offset&&cursor<items.length)throw new Error('Outline entry exceeds context budget; use read_file');
    return result;
  }
  async context(path:string,selector:string,offset:number,budget:number) {
    const unit=await this.graph(path);
    const functions:Array<{fn:FunctionDefinition;owner?:ContractDefinition}>=[];
    for(const node of unit.ast.children) {
      if(node.type==='FunctionDefinition')functions.push({fn:node});
      if(node.type==='ContractDefinition')for(const member of node.subNodes)if(member.type==='FunctionDefinition')functions.push({fn:member as FunctionDefinition,owner:node});
    }
    const selected=functions.filter(({fn,owner})=>selector==='s'+bounds(fn)[0] || selector===(owner?owner.name+'.':'')+label(fn));
    if(selected.length!==1)throw new Error('Function missing or overloaded; use an exact function ID from outline_solidity');
    const {fn,owner}=selected[0];
    const unresolved=new Set<string>();
    const definitions:Definition[]=[],seen=new Set<string>();
    const inherit=(definition:Definition)=>{
      const key=definition.unit.path+":"+bounds(definition.contract)[0];
      if(seen.has(key))return;seen.add(key);definitions.push(definition);
      for(const base of definition.contract.baseContracts) {
        const found=this.resolveBase(definition.unit,base.baseName.namePath);
        if(found)inherit(found);else unresolved.add(`Unresolved/ambiguous base: ${definition.unit.path}:${base.baseName.namePath}`);
      }
    };
    if(owner)inherit({unit,contract:owner});
    const segments:SourceExcerpt[]=[];
    const add=(from:Unit,node:BaseASTNode,endOverride?:number)=>{
      const [start,end]=bounds(node), stop=endOverride??end;
      if(stop>start&&!segments.some(s=>s.path===from.path&&s.start===start&&s.end===stop))segments.push({path:from.path,start,end:stop,text:from.text.slice(start,stop)});
    };
    add(unit,fn);
    const called=new Set<string>();
    const examine=(node:BaseASTNode)=>visit(node,{FunctionCall:n=>{
      if(n.expression.type==='Identifier')called.add(n.expression.name);
      else if(n.expression.type==='MemberAccess')called.add(n.expression.memberName);
    }});
    examine(fn);
    // Include every matching applied modifier conservatively; do not claim override binding.
    const modifiers=new Set(fn.modifiers.map(m=>m.name));
    const foundModifiers=new Set<string>();
    for(const definition of definitions)for(const child of definition.contract.subNodes) {
      const node=child as ASTNode;
      if(node.type==='ModifierDefinition'&&modifiers.has(node.name)) {add(definition.unit,node);examine(node);foundModifiers.add(node.name);}
    }
    for(const missing of modifiers)if(!foundModifiers.has(missing))unresolved.add('Unresolved modifier: '+missing);
    const helpers:Array<{path:string;id:string;name:string}>=[];
    for(const definition of definitions) {
      const {unit:from,contract}=definition;
      add(from,contract,contract.subNodes.length?bounds(contract.subNodes[0])[0]:bounds(contract)[1]);
      for(const child of contract.subNodes) {
        const node=child as ASTNode;
        // Conservative declarations avoid missing indirect state access in modifiers/helpers.
        if(['StateVariableDeclaration','StructDefinition','EnumDefinition','UsingForDeclaration','TypeDefinition'].includes(node.type))add(from,node);
        if(node.type==='FunctionDefinition'&&node!==fn&&called.has(label(node)))helpers.push({path:from.path,id:'s'+bounds(node)[0],name:contract.name+'.'+label(node)});
      }
    }
    for(const from of new Set([unit,...definitions.map(d=>d.unit)])) {
      for(const node of from.ast.children) {
        if(['ImportDirective','PragmaDirective','FileLevelConstant','StructDefinition','EnumDefinition','TypeDefinition'].includes(node.type))add(from,node);
        if(node.type==='FunctionDefinition'&&node!==fn&&called.has(label(node)))helpers.push({path:from.path,id:'s'+bounds(node)[0],name:label(node)});
      }
    }
    // Surface errors anywhere in the traversed import graph, including cyclic imports.
    for(const pending of this.units.values()) {
      try {for(const warning of (await pending).unresolved)unresolved.add(warning);}catch{}
    }
    for(const name of called)if(!helpers.some(h=>h.name.split('.').at(-1)===name))unresolved.add('Call not statically bound (may be builtin/external): '+name);
    const totalCharacters=segments.reduce((n,s)=>n+s.text.length,0);
    if(offset>totalCharacters)throw new Error('Context offset exceeds source bundle');
    const result={selector:'s'+bounds(fn)[0],excerpts:[] as SourceExcerpt[],nextOffset:offset as number|null,totalCharacters,
      helpers:helpers.slice(0,6),moreHelpers:helpers.length>6,unresolved:[...unresolved].slice(0,4),moreUnresolved:unresolved.size>4,note};
    // Metadata must not crowd out the actual evidence. Keep explicit incompleteness flags.
    while(JSON.stringify(result).length>budget/2 && (result.helpers.length||result.unresolved.length)) {
      if(result.helpers.length){result.helpers.pop();result.moreHelpers=true;}
      else {result.unresolved.pop();result.moreUnresolved=true;}
    }
    let base=0,cursor=offset;
    for(const segment of segments) {
      if(base+segment.text.length<=cursor){base+=segment.text.length;continue;}
      const local=cursor-base;
      let length=segment.text.length-local;
      const excerpt={...segment,start:segment.start+local,text:segment.text.slice(local)};
      result.excerpts.push(excerpt);
      // JSON escaping counts toward the bound too. Split at a line boundary where possible.
      while(length>0) {
        excerpt.text=segment.text.slice(local,local+length);excerpt.end=excerpt.start+length;
        result.nextOffset=cursor+length<totalCharacters?cursor+length:null;
        if(JSON.stringify(result).length<=budget)break;
        length=Math.floor(length*0.8);
      }
      if(!length){result.excerpts.pop();result.nextOffset=cursor;break;}
      if(length<segment.text.length-local) {
        const newline=excerpt.text.lastIndexOf('\n');
        if(newline>length/2){length=newline+1;excerpt.text=excerpt.text.slice(0,length);excerpt.end=excerpt.start+length;}
      }
      cursor+=length;result.nextOffset=cursor<totalCharacters?cursor:null;
      if(length<segment.text.length-local)break;
      base+=segment.text.length;
    }
    if(!result.excerpts.length&&offset<totalCharacters)throw new Error('Source context exceeds message budget; use read_file');
    if(offset===totalCharacters)result.nextOffset=null;
    return result;
  }
}
