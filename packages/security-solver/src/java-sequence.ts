import {z} from "zod";
const primitive=z.union([z.string().max(2048),z.number().finite(),z.boolean(),z.null()]);
const proxyName=z.string().regex(/^[A-Za-z_$][\\w$]*(?:\\.[A-Za-z_$][\\w$]*)*$/).max(160);
// Bounded declarative interface proxies let offline tests construct collaborator
// graphs without running project build scripts or model-generated Java code.
const leafProxy=z.object({proxy:proxyName,returns:z.record(z.string().max(100),primitive)}).strict();
const collaboratorProxy=z.object({proxy:proxyName,returns:z.record(z.string().max(100),z.union([primitive,leafProxy]))}).strict();
const javaArg=z.union([primitive,collaboratorProxy]);
export const javaSequenceSchema=z.object({
  constructor:z.array(javaArg).max(8).default([]),
  steps:z.array(z.object({
    method:z.string().regex(/^[A-Za-z_$][\w$]{0,79}$/),
    args:z.array(javaArg).max(8).default([]),
    expected:javaArg.optional()
  })).min(1).max(12)
}).strict();
export type JavaSequence=z.infer<typeof javaSequenceSchema>;
