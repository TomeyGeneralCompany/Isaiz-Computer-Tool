'use strict';
// Fixed harness: never evaluates model-supplied JavaScript or Solidity snippets.
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const spec = JSON.parse(fs.readFileSync('/spec.json', 'utf8'));
const control = 'TOMEY_CONTROL_' + spec.nonce;
const attack = spec.kind === 'html_reflection'
  ? '<em data-tomey="' + spec.nonce + '">TOMEY_PROBE</em>'
  : '../../TOMEY_ESCAPE_' + spec.nonce;
const output = process.stdout.write.bind(process.stdout);
process.stdout.write = () => true; // Target logging must not corrupt the protocol.
function sourceFile(name) {
  const file = fs.realpathSync(path.resolve('/repo', name));
  if (!file.startsWith('/repo/')) throw new Error('Source outside repository');
  if (fs.statSync(file).size > 256000) throw new Error('Source too large');
  return file;
}
async function javascript() {
  const module = await import(pathToFileURL(sourceFile(spec.file)).href);
  const fn = module[spec.function] ?? module.default?.[spec.function];
  if (typeof fn !== 'function') throw new Error('Exported function required');
  return [await fn(control), await fn(attack)];
}
async function solidity() {
  const solc = require('solc');
  const ganache = require('ganache');
  const { BrowserProvider, ContractFactory } = require('ethers');
  const compiled = JSON.parse(solc.compile(JSON.stringify({
    language: 'Solidity',
    sources: {[spec.file]: {content: fs.readFileSync(sourceFile(spec.file), 'utf8')}},
    settings: {evmVersion: 'shanghai', outputSelection: {'*': {'*': ['abi', 'evm.bytecode.object']}}}
  }), {import: name => {
    try { return {contents: fs.readFileSync(sourceFile(name), 'utf8')}; }
    catch (error) { return {error: String(error)}; }
  }}));
  const errors = (compiled.errors || []).filter(e => e.severity === 'error');
  if (errors.length) throw new Error(errors.map(e => e.formattedMessage).join('\n').slice(0, 2000));
  const parts = spec.function.split('.');
  const functionName = parts.pop();
  const contractName = parts.pop();
  const candidates = Object.entries(compiled.contracts?.[spec.file] || {}).filter(([name, artifact]) =>
    (!contractName || name === contractName) && artifact.evm.bytecode.object &&
    !artifact.abi.some(a => a.type === 'constructor' && a.inputs.length) &&
    artifact.abi.some(a => a.type === 'function' && a.name === functionName &&
      ['pure', 'view'].includes(a.stateMutability) &&
      a.inputs.length === 1 && a.inputs[0].type === 'string' &&
      a.outputs.length === 1 && a.outputs[0].type === 'string'));
  if (candidates.length !== 1) throw new Error('Select one deployable contract with a view/pure string -> string function using Contract.function');
  const artifact = candidates[0][1];
  const transport = ganache.provider({
    logging: {quiet: true}, wallet: {deterministic: true, totalAccounts: 1},
    chain: {hardfork: 'shanghai'}, miner: {blockGasLimit: 12000000}
  });
  try {
    const provider = new BrowserProvider(transport);
    const signer = await provider.getSigner();
    const contract = await new ContractFactory(artifact.abi, artifact.evm.bytecode.object, signer)
      .deploy({gasLimit: 10000000});
    await contract.waitForDeployment();
    const fn = contract.getFunction(functionName + '(string)');
    return [await fn.staticCall(control, {gasLimit: 1000000}),
            await fn.staticCall(attack, {gasLimit: 1000000})];
  } finally { await transport.disconnect(); }
}
(async () => {
  const [normal, observed] = await (spec.file.endsWith('.sol') ? solidity() : javascript());
  if (typeof normal !== 'string' || typeof observed !== 'string')
    throw new Error('Probe requires string return values');
  if (normal.length > 16000 || observed.length > 16000) throw new Error('Probe output too large');
  output(JSON.stringify({control_input: control, control_output: normal,
    attack_input: attack, attack_output: observed}));
})().catch(error => { process.stderr.write(String(error).slice(0, 2000)); process.exitCode = 1; });
