import { z } from "zod";
// ABI integers are decimal strings: JSON numbers cannot faithfully carry uint256.
const scalar = z.union([z.string().max(2048), z.boolean()]);
const abiValue = z.union([scalar, z.array(z.union([scalar,z.array(scalar).max(32)])).max(32)]);
const args = z.array(abiValue).max(32);
const sender = z.number().int().min(0).max(2);
const wei = z.string().regex(/^(0|[1-9][0-9]{0,29})$/);
const deployment = z.object({
  file:z.string().min(1).max(512).regex(/^[A-Za-z0-9_.\/-]+\.sol$/)
    .refine(v=>!v.startsWith('/')&&!v.split('/').some(part=>part==='..'||part==='.'),'Repository-relative Solidity path required'),
  contract:z.string().regex(/^[A-Za-z_]\w*$/)
}).strict();
const signature = z.string().min(1).max(200).regex(/^[A-Za-z_][A-Za-z0-9_]*(?:\([A-Za-z0-9_,()[\]]*\))?$/);
const send = z.object({operation:z.literal("send"),function:signature,args,sender:sender.optional(),
  valueWei:wei.optional(),expectRevert:z.boolean().optional()}).strict();
const observe = z.object({operation:z.literal('observe'),function:signature,args,sender:sender.optional()}).strict();
const call = z.object({operation:z.literal("call"),function:signature,args,sender:sender.optional(),expect:abiValue}).strict();
const prepId=z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/);
const prepDeployment=z.object({id:prepId,file:deployment.shape.file,contract:deployment.shape.contract,
  constructorArgs:args,valueWei:wei.optional()}).strict();
const prepSend=z.object({id:prepId,deploymentId:prepId,function:signature,args,
  sender,valueWei:wei.optional(),expectRevert:z.boolean().optional()}).strict();
const prepCheck=z.object({id:prepId,deploymentId:prepId,function:signature,args,
  sender,expect:abiValue}).strict();
export const solidityPreparationSchema=z.object({
  deployments:z.array(prepDeployment).max(8),
  operations:z.array(prepSend).max(24),
  checks:z.array(prepCheck).max(16)
}).strict().superRefine((plan,ctx)=>{
  const ids=new Set<string>();
  const deployed=new Set<string>();
  for(const d of plan.deployments) {
    if(ids.has(d.id))ctx.addIssue({code:z.ZodIssueCode.custom,message:'Duplicate preparation ID '+d.id});
    ids.add(d.id);deployed.add(d.id);
  }
  for(const item of [...plan.operations,...plan.checks]) {
    if(ids.has(item.id))ctx.addIssue({code:z.ZodIssueCode.custom,message:'Duplicate preparation ID '+item.id});
    ids.add(item.id);
    if(!deployed.has(item.deploymentId))ctx.addIssue({code:z.ZodIssueCode.custom,
      message:'Unknown preparation deployment '+item.deploymentId});
  }
});
export type SolidityPreparation=z.infer<typeof solidityPreparationSchema>;
export const soliditySequenceSchema = z.object({constructorArgs:args,constructorValueWei:wei.optional(),deployment:deployment.optional(),preparation:solidityPreparationSchema.optional(),
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
  properties:{constructorArgs:argsJson,constructorValueWei:weiJson,
    preparation:{type:'object',additionalProperties:false,properties:{
      deployments:{type:'array',maxItems:8,items:{type:'object',additionalProperties:false,
        properties:{id:{type:'string'},file:{type:'string'},contract:{type:'string'},constructorArgs:argsJson,valueWei:weiJson},
        required:['id','file','contract','constructorArgs']}},
      operations:{type:'array',maxItems:24,items:{type:'object',additionalProperties:false,
        properties:{id:{type:'string'},deploymentId:{type:'string'},...stepBase,valueWei:weiJson,expectRevert:{type:'boolean'}},
        required:['id','deploymentId','function','args','sender']}},
      checks:{type:'array',maxItems:16,items:{type:'object',additionalProperties:false,
        properties:{id:{type:'string'},deploymentId:{type:'string'},...stepBase,expect:valueJson},
        required:['id','deploymentId','function','args','sender','expect']}}
    },required:['deployments','operations','checks']},
    deployment:{type:'object',additionalProperties:false,properties:{file:{type:'string',maxLength:512},contract:{type:'string',maxLength:100}},required:['file','contract']},steps:{type:"array",minItems:1,maxItems:16,items:{anyOf:[
    {type:"object",additionalProperties:false,properties:{operation:{const:"send"},...stepBase,valueWei:weiJson,expectRevert:{type:"boolean"}},required:["operation","function","args"]},
    {type:"object",additionalProperties:false,properties:{operation:{const:"call"},...stepBase,expect:valueJson},required:["operation","function","args","expect"]},
    {type:"object",additionalProperties:false,properties:{operation:{const:"observe"},...stepBase},required:["operation","function","args"]},
  ]}}},required:["constructorArgs","steps"]};
