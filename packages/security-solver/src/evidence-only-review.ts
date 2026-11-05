import {appendFile} from 'node:fs/promises';
import {postOllamaChat} from '../../core/src/ollama-chat';

type VerdictResponse={message?:{content?:string;thinking?:string};eval_count?:number;prompt_eval_count?:number;done_reason?:string};

/** After source acquisition, replay and caller checking, review is a
 * SCHEMA-BOUND JUDGMENT, NOT another source-navigation agent. No tool or
 * controller action schema is exposed to the model.
 *
 * A failed validation yields one targeted correction; the model never gets
 * authority to alter the case evidence or request arbitrary source paths.
 */
export async function runEvidenceOnlyReview(input:{
  prompt:string;
  schema:Record<string,unknown>;
  model:string;
  signal:AbortSignal;
  logFile:string;
  numCtx:number;
  numPredict:number;
  validate:(answer:string)=>string|null|Promise<string|null>;
  maxAttempts?:number;
  transport?:(payload:Record<string,unknown>,signal:AbortSignal)=>Promise<VerdictResponse>;
}):Promise<string>{
  const attempts=input.maxAttempts??3;
  if(!Number.isSafeInteger(attempts)||attempts<1||attempts>5)
    throw new Error('Invalid independent review attempt limit');
  if(!input.schema||!Object.keys(input.schema).length)
    throw new Error('Independent reviewer requires a nonempty verdict schema');
  const messages:Array<{role:string;content:string}>=[
    {role:'system',content:'You are an independent technical security reviewer. The controller has already acquired and replayed source evidence and checked caller locations. You have no source navigation or probe tools. Decide the precise question posed by the controller evidence. Output ONLY a JSON object matching the requested review schema. Do not output an audit action, a final-action wrapper, or a request to read files. A supported rejection is permitted. Do not claim that query parameter parsing HTML-escapes input.'},
    {role:'user',content:input.prompt}
  ];
  let lastFeedback='No verdict returned';
  let previousRejectedContent='';
  let repeatedRejectionCount=0;
  const url=process.env.AUTOHACK_OLLAMA_URL||'http://127.0.0.1:11434/api/chat';
  for(let attempt=1;attempt<=attempts;attempt++){
    input.signal.throwIfAborted();
    await appendFile(input.logFile,'[EVIDENCE_ONLY_REVIEW_REQUEST] '+JSON.stringify({attempt,model:input.model})+'\n');
    // Snapshot the message sequence per request. Reusing the mutable
    // array lets later feedback retroactively alter an in-flight request
    // (and makes mock transports observe a different turn than Ollama).
    // This reviewer needs a JSON verdict, not Qwen3's hidden thinking output.
    // Under a bounded generation budget reasoning-only responses have empty content.
    const payload={model:input.model,stream:false,think:false,format:input.schema,
      keep_alive:'10m',messages:messages.map(message=>({...message})),
      options:{num_ctx:input.numCtx,num_predict:input.numPredict,num_thread:4,
        // A deterministic rejected verdict can recur forever with temperature 0.
        // Diversify only on a repeated rejected verdict; evidence stays immutable.
        temperature:repeatedRejectionCount>0 ? 0.25 : 0}};
    const response=await (input.transport
      ?input.transport(payload,input.signal)
      :postOllamaChat(url,payload,input.signal)) as VerdictResponse;
    const content=response.message?.content?.trim()||'';
    await appendFile(input.logFile,'[EVIDENCE_ONLY_REVIEW_RESPONSE] '+JSON.stringify({attempt,contentCharacters:content.length,thinkingCharacters:response.message?.thinking?.length??0,generatedTokens:response.eval_count??null,finishReason:response.done_reason??null})+'\n');
    let feedback:string|null;
    if(!content)feedback='The review returned empty content. Return a JSON review object, not an audit action.';
    else {
      try {
        const data=JSON.parse(content);
        if(!data||typeof data!=='object'||Array.isArray(data)||'action' in data)
          feedback='The response was an audit action, not the required review verdict. Output the review JSON object with verdict and recommendation.';
        else feedback=await input.validate(content);
      }catch{feedback='The response was not a complete JSON review object. Output a valid review JSON object.';}
    }
    if(!feedback){
      await appendFile(input.logFile,'[EVIDENCE_ONLY_REVIEW_ACCEPTED] '+JSON.stringify({
        attempt,promptTokens:response.prompt_eval_count??null,
        generatedTokens:response.eval_count??null})+'\n');
      return content;
    }
    if(content && content===previousRejectedContent) {
      repeatedRejectionCount++;
      await appendFile(input.logFile,'[EVIDENCE_ONLY_REVIEW_STALLED] '+JSON.stringify({
        attempt,repeated:repeatedRejectionCount,
        note:'Identical rejected verdict; escalate correction, not evidence or approval'})+'\\n');
    } else repeatedRejectionCount=0;
    previousRejectedContent=content;
    lastFeedback=feedback.slice(0,600);
    await appendFile(input.logFile,'[EVIDENCE_ONLY_REVIEW_CORRECTED] '+JSON.stringify({attempt,reason:lastFeedback})+'\n');
    // Replace rejected messages instead of accumulating a self-reinforcing
    // chain of identical invalid judgments. The verified evidence is unchanged.
    messages.splice(2);
    const policyConfusion=/external submission prohibition|submission prohibition|policy.*technical defect/i.test(lastFeedback);
    const corrective=policyConfusion
      ? 'Your previous verdict was INVALID because its fatal reason concerned whether the finding could be SUBMITTED, not whether the recorded security behavior is technically supported. The controller has already set external submission to DISABLED. This is not a technical defect. Evaluate ONLY the source-replayed behavior and the input-to-sink/authorization path. If the evidence supports the security issue, verdict=approve with recommendation=dont_submit. If it has an actual technical flaw, verdict=reject, name the exact flaw and source line, and recommendation=dont_submit. Never cite submission policy as a fatal issue.'
      : 'Previous verdict failed factual evidence validation: '+lastFeedback+
        '. Re-evaluate the same verified source and replay; a well-supported technical rejection is allowed.';
    messages.push({role:'system',content:corrective+
      (repeatedRejectionCount>0?' Do NOT repeat the previous rejected verdict unchanged; independently reconsider its fatal technical reason.':'')});
    messages.push({role:'user',content:'Return a fresh complete schema-valid technical verdict grounded in the unchanged controller evidence. No source navigation or tool requests.'});
  }
  throw new Error('Independent evidence-only review failed validation after '+attempts+
    ' attempts: '+lastFeedback);
}
