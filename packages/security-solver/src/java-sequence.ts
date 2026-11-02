import {z} from "zod";
const javaArg=z.union([z.string().max(2048),z.number().finite(),z.boolean()]);
export const javaSequenceSchema=z.object({
  constructor:z.array(javaArg).max(8).default([]),
  steps:z.array(z.object({
    method:z.string().regex(/^[A-Za-z_$][\w$]{0,79}$/),
    args:z.array(javaArg).max(8).default([]),
    expected:javaArg.optional()
  })).min(1).max(12)
}).strict();
export type JavaSequence=z.infer<typeof javaSequenceSchema>;
