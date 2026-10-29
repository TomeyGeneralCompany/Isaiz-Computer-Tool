/** Normalize the same default chosen by runtime-settings.ts and acceptance.py.
 * Do not write .env or override an explicit local research model.
 */
export function ensureOneBountyLocalModel(env:NodeJS.ProcessEnv):string {
  const selected=env.LOCAL_OLLAMA_MODEL?.trim()||env.OLLAMA_MODEL?.trim()||'qwen3:4b';
  env.LOCAL_OLLAMA_MODEL=selected;
  return selected;
}
