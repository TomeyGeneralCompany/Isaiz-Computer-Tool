import {z} from "zod";
/** Declarative stateful execution. Interface mocks specify return values for
 * named methods; they contain data only and are never compiled as Java. */
const primitive=z.union([z.string().max(2048),z.number().finite(),z.boolean(),z.null()]);
const methodName=z.string().regex(/^[A-Za-z_$][A-Za-z0-9_$]{0,79}$/);
const shallowMock=z.object({mock:z.record(methodName,primitive).refine(x=>Object.keys(x).length<=16)}).strict();
const javaArg=z.union([primitive,shallowMock,z.object({
  mock:z.record(methodName,z.union([primitive,shallowMock])).refine(x=>Object.keys(x).length<=16)
}).strict()]);
export const javaSequenceSchema=z.object({
  constructor:z.array(javaArg).max(8).default([]),
  steps:z.array(z.object({
    method:methodName,
    args:z.array(javaArg).max(8).default([]),
    expected:primitive.optional()
  })).min(1).max(12)
}).strict();
export type JavaSequence=z.infer<typeof javaSequenceSchema>;
