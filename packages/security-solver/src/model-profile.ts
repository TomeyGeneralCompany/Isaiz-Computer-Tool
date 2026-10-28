/** Qwen3's non-thinking sampling guidance is the default; deterministic is an explicit opt-in. */
export function modelProfile(stage?:string) {
  const name=process.env.LOCAL_MODEL_PROFILE || 'qwen';
  if(!['deterministic','qwen','qwen-planner'].includes(name))throw new Error('Unknown LOCAL_MODEL_PROFILE');
  const think=name==='qwen-planner' && ['hypothesize','review'].includes(stage||'');
  return {name,think,options:name==='deterministic'?{temperature:0}:
    {temperature:think?0.6:0.7,top_p:think?0.95:0.8,top_k:20,min_p:0,presence_penalty:1.5}};
}
