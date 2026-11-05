import {z} from 'zod';

/** Fixed, declarative sequence of callable invocations inside one sandbox.
 * The controller supplies data, never executable code or arbitrary commands.
 * Each step executes against the same loaded module or factory instance.
 * Expected-value mismatches are observations, not vulnerability proof.
 */
const value=z.union([z.string().max(2048),z.number().finite(),z.boolean(),z.null(),
  z.array(z.union([z.string().max(2048),z.number().finite(),z.boolean(),z.null()])).max(8)]);
const identifier=z.string().regex(/^[A-Za-z][A-Za-z0-9_]{0,79}$/);
export const polyglotSequenceSchema=z.object({
  factory:identifier.optional(),
  constructor:z.array(value).max(8).default([]),
  steps:z.array(z.object({
    method:identifier,
    args:z.array(value).max(8).default([]),
    expected:value.optional()
  }).strict()).min(2).max(12)
}).strict().superRefine((v,ctx)=>{
  if(!v.factory && v.constructor.length)
    ctx.addIssue({code:z.ZodIssueCode.custom,message:'Constructor arguments require a factory'});
});
export type PolyglotSequence=z.infer<typeof polyglotSequenceSchema>;
