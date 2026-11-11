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
