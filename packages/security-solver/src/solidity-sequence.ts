import { z } from "zod";
// ABI integers are decimal strings: JSON numbers cannot faithfully carry uint256.
const scalar = z.union([z.string().max(2048), z.boolean()]);
const abiValue = z.union([scalar, z.array(z.union([scalar,z.array(scalar).max(32)])).max(32)]);
const args = z.array(abiValue).max(32);
const sender = z.number().int().min(0).max(2);
const wei = z.string().regex(/^(0|[1-9][0-9]{0,29})$/);
const signature = z.string().min(1).max(200).regex(/^[A-Za-z_][A-Za-z0-9_]*(?:\([A-Za-z0-9_,()[\]]*\))?$/);
const send = z.object({operation:z.literal("send"),function:signature,args,sender:sender.optional(),
  valueWei:wei.optional(),expectRevert:z.boolean().optional()}).strict();
const observe = z.object({operation:z.literal('observe'),function:signature,args,sender:sender.optional()}).strict();
const call = z.object({operation:z.literal("call"),function:signature,args,sender:sender.optional(),expect:abiValue}).strict();
export const soliditySequenceSchema = z.object({constructorArgs:args,constructorValueWei:wei.optional(),
  steps:z.array(z.discriminatedUnion("operation",[send,call,observe])).min(1).max(16)}).strict()
  .refine(s=>s.steps.some(step=>step.operation === "call" || step.operation === "observe"),"Include at least one read observation")
  .refine(s=>JSON.stringify(s).length<=16000,"Sequence exceeds 16KB");
export type SoliditySequence = z.infer<typeof soliditySequenceSchema>;
export const soliditySequencePrompt = `For Solidity constructor arguments and state changes, use verify_source with kind/answer=solidity_sequence and a sequence object.
Set query to Contract.function for the primary function being tested. Sequence format:
{"constructorArgs":["5"],"steps":[{"operation":"send","function":"set(uint256)","args":["7"],"sender":0},{"operation":"call","function":"value()","args":[],"expect":"7"}]}.
Use decimal strings for ABI integers and wei, booleans for bools, arrays for ABI arrays/tuples. $account0, $account1 and $account2 resolve to three local test accounts; $contract resolves to this deployment after construction.
Optional constructorValueWei and send valueWei transfer only local test currency. send expectRevert=true tests a required revert. At most 16 steps; include at least one call with an expected result. A single return is a scalar; multiple returns are an array. Calls must be view/pure; sends must be nonpayable/payable. Use full ABI signatures for overloads.
Use operation=observe with a source-declared view/pure method to record actual state without fabricating expect; pair observations before and after a send to establish baseline and transition. Observe records what happened, not proof of a violated invariant. Use operation=call with expect when a source-derived property justifies an assertion. Each sequence starts from a fresh deterministic local EVM. Output records actual receipts and read/assertion results. An assertion mismatch is only a test discrepancy, not evidence that the expected value or a vulnerability claim is correct. Compiler remains solc 0.8.30; external-chain state, proxies requiring external deployments, and linked libraries are not supplied.`;

const scalarJson = {anyOf:[{type:"string",maxLength:2048},{type:"boolean"}]};
const valueJson = {anyOf:[...scalarJson.anyOf,{type:"array",maxItems:32,items:{anyOf:[...scalarJson.anyOf,{type:"array",maxItems:32,items:scalarJson}]}}]};
const argsJson = {type:"array",maxItems:32,items:valueJson};
const stepBase = {function:{type:"string",maxLength:200},args:argsJson,sender:{type:"integer",minimum:0,maximum:2}};
const weiJson = {type:"string",pattern:"^(0|[1-9][0-9]{0,29})$"};
export const soliditySequenceJsonSchema = {type:"object",additionalProperties:false,
  properties:{constructorArgs:argsJson,constructorValueWei:weiJson,steps:{type:"array",minItems:1,maxItems:16,items:{anyOf:[
    {type:"object",additionalProperties:false,properties:{operation:{const:"send"},...stepBase,valueWei:weiJson,expectRevert:{type:"boolean"}},required:["operation","function","args"]},
    {type:"object",additionalProperties:false,properties:{operation:{const:"call"},...stepBase,expect:valueJson},required:["operation","function","args","expect"]},
    {type:"object",additionalProperties:false,properties:{operation:{const:"observe"},...stepBase},required:["operation","function","args"]},
  ]}}},required:["constructorArgs","steps"]};
