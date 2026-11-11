/** Independent consumer-impact check, distinct from an observed role setter.
 * Declarative transactions only; source must declare each exercised function.
 * This is a narrow adapter for a fund/settle balance consumer, not a
 * general claim that every role mutation is exploitable.
 */
import type {SoliditySequence} from './solidity-sequence';

export function roleConsumerImpactSequence(source:string,role:string,mutator:string):SoliditySequence|null {
  if(!/^[A-Za-z_]\w*$/.test(role)||!/^[A-Za-z_]\w*$/.test(mutator))return null;
  const declared=(fn:string)=>new RegExp('\\bfunction\\s+'+fn+'\\s*\\(').test(source);
  if(!declared(mutator)||!declared('fund')||!declared('settle'))return null;
  const fund=/\bfunction\s+fund\s*\(\s*uint256\s+\w+\s*\)[^{]*\{/.exec(source);
  const settle=/\bfunction\s+settle\s*\(\s*address\s+\w+\s*,\s*uint256\s+\w+\s*\)[^{]*\{([^}]{0,2600})\}/.exec(source);
  const balance=/\bmapping\s*\(\s*address\s*=>\s*uint256\s*\)\s+public\s+credit\b/.test(source);
  const roleGuard=settle && new RegExp('\\brequire\\s*\\(\\s*msg\\.sender\\s*==\\s*'+role+'\\b').test(settle[1]);
  if(!fund||!settle||!balance||!roleGuard||
     !/\bcredit\s*\[\s*\w+\s*\]\s*\+=/.test(settle[1]))
    return null;
  return {constructorArgs:[],steps:[
    {operation:'call',function:role+'()',args:[],expect:'$account0'},
    {operation:'send',function:'fund(uint256)',args:['5'],sender:0},
    {operation:'send',function:'settle(address,uint256)',args:['$account1','1'],sender:2,expectRevert:true},
    {operation:'call',function:'credit(address)',args:['$account1'],expect:'0'},
    {operation:'send',function:mutator+'(address)',args:['$account2'],sender:1},
    {operation:'call',function:role+'()',args:[],expect:'$account2'},
    {operation:'send',function:'settle(address,uint256)',args:['$account1','1'],sender:2},
    {operation:'call',function:'credit(address)',args:['$account1'],expect:'1'}
  ]};
}

export function roleConsumerImpactObserved(observations:unknown,role:string,mutator:string):boolean {
  if(!observations||typeof observations!=='object')return false;
  const data=observations as {accounts?:unknown;steps?:unknown};
  if(!Array.isArray(data.accounts)||data.accounts.length<3||
     !Array.isArray(data.steps)||data.steps.length!==8)return false;
  const [before,fund,blocked,creditBefore,mutation,after,consumer,creditAfter]=data.steps as Array<Record<string,unknown>>;
  const eq=(a:unknown,b:unknown)=>typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();
  return before.operation==='call' && before.function===role+'()' &&
    before.passed===true && eq(before.actual,data.accounts[0]) &&
    fund.operation==='send' && fund.function==='fund(uint256)' && fund.passed===true && fund.reverted===false &&
    blocked.operation==='send' && blocked.function==='settle(address,uint256)' &&
    blocked.sender===2 && blocked.reverted===true && blocked.passed===true &&
    creditBefore.operation==='call' && creditBefore.function==='credit(address)' &&
    creditBefore.passed===true && creditBefore.actual==='0' &&
    mutation.operation==='send' && mutation.function===mutator+'(address)' &&
    mutation.sender===1 && mutation.passed===true && mutation.reverted===false &&
    after.operation==='call' && after.function===role+'()' &&
    after.passed===true && eq(after.actual,data.accounts[2]) &&
    consumer.operation==='send' && consumer.function==='settle(address,uint256)' &&
    consumer.sender===2 && consumer.passed===true && consumer.reverted===false &&
    creditAfter.operation==='call' && creditAfter.function==='credit(address)' &&
    creditAfter.passed===true && creditAfter.actual==='1';
}


// An inherited consumer is tested on its real derived deployment, not on a
// standalone base that cannot execute the consumer. The source conditions
// below are intentionally narrow; unsupported funding layouts stay unsupported.
export function inheritedRoleConsumerImpactSequence(
  baseSource:string,derivedSource:string,role:string,mutator:string,
  baseFile:string,derivedFile:string,derivedContract:string
):SoliditySequence|null {
  if(!/^[A-Za-z_]\w*$/.test(role)||!/^[A-Za-z_]\w*$/.test(mutator)||
     !/^[A-Za-z_]\w*$/.test(derivedContract)||
     !baseFile.endsWith('.sol')||!derivedFile.endsWith('.sol'))return null;
  const clean=(s:string)=>s.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g,'');
  const base=clean(baseSource),source=clean(derivedSource);
  const baseContract=/\bcontract\s+([A-Za-z_]\w*)\b/.exec(base)?.[1];
  if(!baseContract || !new RegExp('\\bfunction\\s+'+mutator+'\\s*\\(').test(base))return null;
  const importNames=[...source.matchAll(/\bimport\b[^;]{0,1000}["']([^"']+)["']\s*;/g)].map(m=>m[1]);
  const normalize=(s:string)=>{const parts:string[]=[];for(const part of s.split('/')) {
    if(part==='.'||!part)continue;if(part==='..')parts.pop();else parts.push(part);
  }return parts.join('/');};
  const parent=derivedFile.split('/').slice(0,-1).join('/');
  if(!importNames.some(name=>normalize(parent+'/'+name)===normalize(baseFile)) ||
     !new RegExp('\\bcontract\\s+'+derivedContract+'\\s+is\\s+'+baseContract+'\\s*\\{').test(source))
    return null;
  if(!/\bmapping\s*\(\s*address\s*=>\s*uint256\s*\)\s+public\s+credit\s*;/.test(source) ||
     !/\buint256\s+public\s+totalCredit\s*;/.test(source))return null;
  const fund=/\bfunction\s+fund\s*\(\s*address\s+(\w+)\s*,\s*uint256\s+(\w+)\s*\)\s+external\s*\{([^}]{0,1800})\}/.exec(source);
  const settle=/\bfunction\s+settle\s*\(\s*address\s+(\w+)\s*,\s*uint256\s+(\w+)\s*\)\s+external\s*\{([^}]{0,1800})\}/.exec(source);
  if(!fund||!settle)return null;
  const funded=/\bcredit\s*\[\s*(\w+)\s*\]\s*\+=\s*(\w+)\s*;\s*totalCredit\s*\+=\s*\2\s*;/.exec(fund[3]);
  if(!funded||funded[1]!==fund[1])return null;
  const fundedValue=funded[2];
  if(fundedValue!==fund[2] &&
     !new RegExp('\\buint256\\s+'+fundedValue+'\\s*=\\s*'+fund[2]+
       '\\s*\\.\\s*bounded\\s*\\(\\s*type\\s*\\(\\s*uint128\\s*\\)\\s*\\.max\\s*\\)\\s*;').test(fund[3]))
    return null;
  if(!new RegExp('\\brequire\\s*\\(\\s*msg\\.sender\\s*==\\s*'+role+'\\b').test(settle[3]) ||
     !new RegExp('\\bcredit\\s*\\[\\s*'+settle[1]+'\\s*\\]\\s*\\+=\\s*'+settle[2]+'\\s*;').test(settle[3]) ||
     !new RegExp('\\btotalCredit\\s*-=\\s*'+settle[2]+'\\s*;').test(settle[3]) ||
     !/\bamount\s*>\s*0/.test(settle[3]) ||
     !/\bamount\s*<=\s*totalCredit/.test(settle[3]))return null;
  return {constructorArgs:[],deployment:{file:derivedFile,contract:derivedContract},steps:[
    {operation:'call',function:role+'()',args:[],expect:'$account0'},
    {operation:'send',function:'fund(address,uint256)',args:['$account1','5'],sender:0},
    {operation:'call',function:'totalCredit()',args:[],expect:'5'},
    {operation:'send',function:'settle(address,uint256)',args:['$account2','1'],sender:2,expectRevert:true},
    {operation:'call',function:'credit(address)',args:['$account2'],expect:'0'},
    {operation:'send',function:mutator+'(address)',args:['$account2'],sender:1},
    {operation:'call',function:role+'()',args:[],expect:'$account2'},
    {operation:'send',function:'settle(address,uint256)',args:['$account2','1'],sender:2},
    {operation:'call',function:'credit(address)',args:['$account2'],expect:'1'},
    {operation:'call',function:'totalCredit()',args:[],expect:'4'}
  ]};
}

export function inheritedRoleConsumerImpactObserved(observations:unknown,role:string,mutator:string):boolean {
  if(!observations||typeof observations!=='object')return false;
  const data=observations as {accounts?:unknown;steps?:unknown};
  if(!Array.isArray(data.accounts)||data.accounts.length!==3||
     !Array.isArray(data.steps)||data.steps.length!==10)return false;
  const s=data.steps as Array<Record<string,unknown>>;
  const eq=(a:unknown,b:unknown)=>typeof a==='string'&&typeof b==='string'&&a.toLowerCase()===b.toLowerCase();
  const call=(i:number,fn:string,value:unknown)=>s[i].operation==='call'&&s[i].function===fn&&
    s[i].passed===true&&eq(s[i].actual,value);
  const send=(i:number,fn:string,sender:number,reverted:boolean)=>s[i].operation==='send'&&
    s[i].function===fn&&s[i].sender===sender&&s[i].reverted===reverted&&s[i].passed===true;
  return call(0,role+'()',data.accounts[0])&&
    send(1,'fund(address,uint256)',0,false)&&call(2,'totalCredit()','5')&&
    send(3,'settle(address,uint256)',2,true)&&call(4,'credit(address)','0')&&
    send(5,mutator+'(address)',1,false)&&call(6,role+'()',data.accounts[2])&&
    send(7,'settle(address,uint256)',2,false)&&call(8,'credit(address)','1')&&
    call(9,'totalCredit()','4');
}
