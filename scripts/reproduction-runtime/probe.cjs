'use strict';
// Fixed harness: never evaluates model-supplied JavaScript or Solidity snippets.
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const spec = JSON.parse(fs.readFileSync('/spec.json', 'utf8'));
const control = 'TOMEY_CONTROL_' + spec.nonce;
const attack = ['html_reflection', 'entry_html_reflection'].includes(spec.kind)
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
  if (spec.kind === 'entry_html_reflection') {
    const source = fs.readFileSync(sourceFile(spec.file), 'utf8');
    const params = [...source.matchAll(/\.searchParams\.get\s*\(\s*["']([A-Za-z_][A-Za-z0-9_-]{0,63})["']\s*\)/g)]
      .map(match => match[1]);
    if (new Set(params).size !== 1 || !params.length)
      throw new Error('Unsupported or ambiguous JavaScript request-parameter extraction');
    const param = params[0];
    const controlUrl = 'http://localhost/?' + param + '=' + encodeURIComponent(control);
    const attackUrl = 'http://localhost/?' + param + '=' + encodeURIComponent(attack);
    return [await fn(controlUrl), await fn(attackUrl), controlUrl, attackUrl, param];
  }
  return [await fn(control), await fn(attack)];
}
async function javascriptSequence() {
  const module = await import(pathToFileURL(sourceFile(spec.file)).href);
  const sequence = spec.sequence;
  if (!sequence || !Array.isArray(sequence.steps) || sequence.steps.length < 2 ||
      sequence.steps.length > 12) throw new Error('Invalid stateful sequence');
  const factory = sequence.factory ? (module[sequence.factory] ?? module.default?.[sequence.factory]) : null;
  const receiver = factory ? await factory(...(sequence.constructor || [])) : (module.default ?? module);
  if (!receiver) throw new Error('Stateful sequence receiver unavailable');
  const steps = [];
  for (const step of sequence.steps) {
    if (!/^[A-Za-z][A-Za-z0-9_]{0,79}$/.test(step.method) ||
        !Array.isArray(step.args || []) || (step.args || []).length > 8)
      throw new Error('Invalid stateful step');
    const fn = receiver[step.method];
    if (typeof fn !== 'function') throw new Error('Stateful method not callable: ' + step.method);
    const actual = await fn.apply(receiver, step.args || []);
    if (JSON.stringify(actual) === undefined || JSON.stringify(actual).length > 16000)
      throw new Error('Unsupported sequence output');
    steps.push({operation:'call',function:step.method,actual,
      ...(Object.hasOwn(step,'expected') ? {expected:step.expected} : {}),
      passed:!Object.hasOwn(step,'expected') || JSON.stringify(actual) === JSON.stringify(step.expected)});
  }
  return {factory:sequence.factory || null,steps};
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
function resolveSolc(sourceText) {
  const match = sourceText.match(/\bpragma\s+solidity\s+([^;]+);/);
  if (!match) return { solc: require('solc'), evmVersion: 'shanghai' };
  const pragma = match[1].trim();
  if (/\b0\.5\./.test(pragma) || (/>=\s*0\.5\./.test(pragma) && !/>=\s*0\.[678]\./.test(pragma))) {
    try { return { solc: require('solc_0_5'), evmVersion: 'petersburg' }; } catch {}
  }
  if (/\b0\.6\./.test(pragma) || (/>=\s*0\.6\./.test(pragma) && !/>=\s*0\.[78]\./.test(pragma))) {
    try { return { solc: require('solc_0_6'), evmVersion: 'istanbul' }; } catch {}
  }
  if (/\b0\.7\./.test(pragma) || (/>=\s*0\.7\./.test(pragma) && !/>=\s*0\.8\./.test(pragma))) {
    try { return { solc: require('solc_0_7'), evmVersion: 'berlin' }; } catch {}
  }
  // 88mph V3's actual application contracts pin pragma solidity 0.8.4.
  // Do not try compiling an exact 0.8.4 pragma with solc 0.8.30.
  if (/^(?:=\s*)?0\.8\.4(?:\s|$)/.test(pragma)) {
    return { solc: require('solc_0_8_4'), evmVersion: 'berlin' };
  }
  return { solc: require('solc'), evmVersion: 'shanghai' };
}

async function solidity() {
  const sequenceMode = spec.kind === 'solidity_sequence';
  if (sequenceMode) require('./solidity-sequence.cjs').validateSequence(spec.sequence);
  const sourceText = fs.readFileSync(sourceFile(spec.file), 'utf8');
  const { solc, evmVersion } = resolveSolc(sourceText);
  const ganache = require('ganache');
  const { BrowserProvider, ContractFactory } = require('ethers');
  // ERC1155Upgradeable exposes internal minting only. Compile a bounded, local
  // derived harness so transfer probes can establish real balances on-chain.
  // Never modify the target source or use the harness as impact evidence.
  const erc1155Harness = sequenceMode &&
    /(?:^|\/)ERC1155Upgradeable\.sol$/.test(spec.file) &&
    /\bcontract\s+ERC1155Upgradeable\b/.test(sourceText) &&
    /^ERC1155Upgradeable\.(?:safeTransferFrom|safeBatchTransferFrom|setApprovalForAll)$/.test(spec.function);
  const harnessName = 'TomeyERC1155ProbeHarness';
  const harnessSource = erc1155Harness ? sourceText + `
contract TomeyERC1155ProbeHarness is ERC1155Upgradeable {
    constructor() { __ERC1155_init("probe"); }
    function tomeyMint(address to, uint256 id, uint256 amount) external {
        _mint(to, id, amount, "");
    }
    function tomeyMintBatch(address to, uint256[] memory ids, uint256[] memory amounts) external {
        _mintBatch(to, ids, amounts, "");
    }
}` : sourceText;
  const effectiveSpec = erc1155Harness ? {...spec, function: spec.function.replace('ERC1155Upgradeable.', harnessName + '.')} : spec;
  const compiled = JSON.parse(solc.compile(JSON.stringify({
    language: 'Solidity',
    sources: {[spec.file]: {content: harnessSource}},
    settings: {...spec.compilerSettings, evmVersion, outputSelection: {'*': {'*': ['abi', 'evm.bytecode.object']}}}
  }), {import: solidityImport}));
  const errors = (compiled.errors || []).filter(e => e.severity === 'error');
  if (errors.length) {
    const error = new Error(errors.map(e => e.formattedMessage).join('\n').slice(0, 2000));
    error.missingImports = [...missingImports];
    throw error;
  }
  const parts = effectiveSpec.function.split('.');
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
    chain: {hardfork: evmVersion, ...(sequenceMode ? {chainId:1337,time:new Date('2020-01-01T00:00:00Z')} : {})},
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
  if (spec.kind === 'javascript_sequence') {
    if (!/\.(?:js|mjs|cjs)$/.test(spec.file)) throw new Error('JavaScript source required');
    output(JSON.stringify(await javascriptSequence()));
    return;
  }
  if (spec.kind === 'solidity_sequence') {
    if (!spec.file.endsWith('.sol')) throw new Error('Solidity source required');
    output(JSON.stringify(await solidity()));
    return;
  }
  const [normal, observed, entryControlUrl, entryAttackUrl, entryParameter] = await (spec.file.endsWith('.sol') ? solidity() : javascript());
  if (typeof normal !== 'string' || typeof observed !== 'string')
    throw new Error('Probe requires string return values');
  if (normal.length > 16000 || observed.length > 16000) throw new Error('Probe output too large');
  output(JSON.stringify({control_input: control, control_output: normal,
    attack_input: attack, attack_output: observed,
    ...(spec.kind === 'entry_html_reflection' ? {entry_control_url:entryControlUrl,
       entry_attack_url:entryAttackUrl,entry_selector:spec.function,entry_parameter:entryParameter} : {})}));
})().catch(error => { process.stderr.write('\nTOMEY_ERROR ' + JSON.stringify({detail:String(error).slice(0,2000),missingImports:error.missingImports || []})); process.exitCode = 1; });
