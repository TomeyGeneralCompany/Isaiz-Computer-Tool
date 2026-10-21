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
const missingImports = new Set();
function solidityImport(name) {
  const candidates = [name, 'node_modules/' + name, 'lib/' + name];
  // Read only declarative remappings; never load Hardhat/Foundry executable config.
  const remappingsFile = '/repo/remappings.txt';
  {
    const text = (spec.remappings || []).join('\n') + '\n' + (fs.existsSync(remappingsFile) ? fs.readFileSync(sourceFile('remappings.txt'), 'utf8') : '');
    const remappings = text.split(/\r?\n/).map(s => s.trim())
      .filter(s => s && !s.startsWith('#'))
      .map(s => s.split('=')).filter(p => p.length === 2 && p[0] && !p[0].includes(':'))
      .sort((a,b) => a[0].length-b[0].length);
    for (const [prefix, replacement] of remappings)
      if (name.startsWith(prefix)) candidates.unshift(replacement + name.slice(prefix.length));
  }
  for (const candidate of candidates) {
    try { return {contents: fs.readFileSync(sourceFile(candidate), 'utf8')}; } catch {}
  }
  missingImports.add(name);
  return {error: 'Unresolved repository/package/remapping import: ' + name};
}
async function solidity() {
  const sequenceMode = spec.kind === 'solidity_sequence';
  if (sequenceMode) require('./solidity-sequence.cjs').validateSequence(spec.sequence);
  const solc = require('solc');
  const ganache = require('ganache');
  const { BrowserProvider, ContractFactory } = require('ethers');
  const compiled = JSON.parse(solc.compile(JSON.stringify({
    language: 'Solidity',
    sources: {[spec.file]: {content: fs.readFileSync(sourceFile(spec.file), 'utf8')}},
    settings: {...spec.compilerSettings, evmVersion: 'shanghai', outputSelection: {'*': {'*': ['abi', 'evm.bytecode.object']}}}
  }), {import: solidityImport}));
  const errors = (compiled.errors || []).filter(e => e.severity === 'error');
  if (errors.length) {
    const error = new Error(errors.map(e => e.formattedMessage).join('\n').slice(0, 2000));
    error.missingImports = [...missingImports];
    throw error;
  }
  const parts = spec.function.split('.');
  const functionName = parts.pop();
  const contractName = parts.pop();
  const candidates = Object.entries(compiled.contracts?.[spec.file] || {}).filter(([name, artifact]) =>
    (!contractName || name === contractName) && artifact.evm.bytecode.object &&
    (sequenceMode || !artifact.abi.some(a => a.type === 'constructor' && a.inputs.length)) &&
    artifact.abi.some(a => a.type === 'function' && a.name === functionName &&
      (sequenceMode || ['pure', 'view'].includes(a.stateMutability) &&
      a.inputs.length === 1 && a.inputs[0].type === 'string' &&
      a.outputs.length === 1 && a.outputs[0].type === 'string')));
  if (candidates.length !== 1) throw new Error(sequenceMode ? 'Select one deployable contract and public/external function using Contract.function' : 'Select one deployable contract with a view/pure string -> string function using Contract.function');
  if (sequenceMode && (!contractName || !spec.sequence.steps.some(step=>step.function.split('(')[0]===functionName))) throw new Error('Sequence must exercise the selected Contract.function');
  const artifact = candidates[0][1];
  const transport = ganache.provider({
    logging: {quiet: true}, wallet: {deterministic: true, totalAccounts: sequenceMode ? 3 : 1},
    chain: {hardfork: 'shanghai', ...(sequenceMode ? {chainId:1337,time:new Date('2020-01-01T00:00:00Z')} : {})},
    miner: {blockGasLimit: 12000000, ...(sequenceMode ? {timestampIncrement:1} : {})}
  });
  await transport.request({method: 'eth_chainId', params: []});
  try {
    if (sequenceMode) return await require('./solidity-sequence.cjs').runSequence(artifact, spec.sequence, transport);
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
  if (spec.kind === 'solidity_sequence') {
    if (!spec.file.endsWith('.sol')) throw new Error('Solidity source required');
    output(JSON.stringify(await solidity()));
    return;
  }
  const [normal, observed] = await (spec.file.endsWith('.sol') ? solidity() : javascript());
  if (typeof normal !== 'string' || typeof observed !== 'string')
    throw new Error('Probe requires string return values');
  if (normal.length > 16000 || observed.length > 16000) throw new Error('Probe output too large');
  output(JSON.stringify({control_input: control, control_output: normal,
    attack_input: attack, attack_output: observed}));
})().catch(error => { process.stderr.write('\nTOMEY_ERROR ' + JSON.stringify({detail:String(error).slice(0,2000),missingImports:error.missingImports || []})); process.exitCode = 1; });
