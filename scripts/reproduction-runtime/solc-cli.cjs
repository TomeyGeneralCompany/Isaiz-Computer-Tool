#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

function loadSolc() {
  const pkg = process.env.TOMEY_SOLC_PKG || 'solc';
  const resolved = require.resolve(pkg, {
    paths: ['/runtime-node-modules', path.join(__dirname, 'node_modules'), __dirname],
  });
  return require(resolved);
}

const solc = loadSolc();
const args = process.argv.slice(2);

if (args.includes('--version') || args.includes('--ver')) {
  process.stdout.write(`solc, the solidity compiler commandline interface\nVersion: ${solc.version()}\n`);
  process.exit(0);
}

let standardJson = false;
let combinedJsonFields = null;
let basePath = process.cwd();
const includePaths = [];
const cliRemappings = [];
const positionalFiles = [];
let optimize = false;
let optimizeRuns = 200;
let evmVersion = null;

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--standard-json') {
    standardJson = true;
  } else if (arg === '--combined-json' && i + 1 < args.length) {
    combinedJsonFields = new Set(args[++i].split(',').map(s => s.trim()).filter(Boolean));
  } else if (arg.startsWith('--combined-json=')) {
    combinedJsonFields = new Set(arg.slice('--combined-json='.length).split(',').map(s => s.trim()).filter(Boolean));
  } else if (arg === '--base-path' && i + 1 < args.length) {
    basePath = args[++i];
  } else if (arg.startsWith('--base-path=')) {
    basePath = arg.slice('--base-path='.length);
  } else if ((arg === '--include-path' || arg === '-I') && i + 1 < args.length) {
    includePaths.push(args[++i]);
  } else if (arg.startsWith('--include-path=')) {
    includePaths.push(arg.slice('--include-path='.length));
  } else if (arg === '--allow-paths' && i + 1 < args.length) {
    i++;
  } else if (arg.startsWith('--allow-paths=')) {
    // sandbox binds restrict paths
  } else if (arg === '--optimize') {
    optimize = true;
  } else if (arg === '--optimize-runs' && i + 1 < args.length) {
    optimizeRuns = Number(args[++i]) || 200;
  } else if (arg.startsWith('--optimize-runs=')) {
    optimizeRuns = Number(arg.slice('--optimize-runs='.length)) || 200;
  } else if (arg === '--evm-version' && i + 1 < args.length) {
    evmVersion = args[++i];
  } else if (arg.startsWith('--evm-version=')) {
    evmVersion = arg.slice('--evm-version='.length);
  } else if (arg === '--pretty-json' || arg === '--json-indent') {
    if (arg === '--json-indent' && i + 1 < args.length && /^\d+$/.test(args[i + 1])) i++;
  } else if (arg.startsWith('-')) {
    // ignore unknown flags safely
  } else if (/^[^=\s]+=\S*$/.test(arg) && !arg.endsWith('.sol')) {
    cliRemappings.push(arg);
  } else {
    positionalFiles.push(arg);
  }
}

function loadRemappings(extraRemappings = []) {
  const lines = [...cliRemappings, ...extraRemappings];
  for (const dir of [basePath, process.cwd(), '/repo']) {
    const rf = path.join(dir, 'remappings.txt');
    try {
      if (fs.existsSync(rf) && fs.statSync(rf).isFile()) {
        lines.push(...fs.readFileSync(rf, 'utf8').split(/\r?\n/));
      }
    } catch {}
  }
  const pairs = [];
  for (const raw of lines) {
    const trimmed = String(raw || '').trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    const prefix = trimmed.slice(0, eq);
    const target = trimmed.slice(eq + 1);
    if (prefix && !prefix.includes(':')) pairs.push([prefix, target]);
  }
  pairs.sort((a, b) => b[0].length - a[0].length);
  return pairs;
}

function makeImportResolver(extraRemappings = []) {
  const remappings = loadRemappings(extraRemappings);
  const searchRoots = [...new Set([
    basePath,
    ...includePaths,
    process.cwd(),
    '/repo',
    path.join(basePath, 'node_modules'),
    path.join(basePath, 'lib'),
    '/repo/node_modules',
    '/repo/lib',
  ])].filter(Boolean);

  return function resolveImport(importPath) {
    const candidates = [importPath];
    for (const [prefix, target] of remappings) {
      if (importPath.startsWith(prefix)) {
        candidates.unshift(target + importPath.slice(prefix.length));
      }
    }
    for (const cand of candidates) {
      if (path.isAbsolute(cand)) {
        try {
          if (fs.existsSync(cand) && fs.statSync(cand).isFile()) {
            return { contents: fs.readFileSync(cand, 'utf8') };
          }
        } catch {}
      }
      for (const root of searchRoots) {
        const joined = path.resolve(root, cand);
        try {
          if (fs.existsSync(joined) && fs.statSync(joined).isFile()) {
            return { contents: fs.readFileSync(joined, 'utf8') };
          }
        } catch {}
      }
    }
    return { error: `File not found: ${importPath}` };
  };
}

if (standardJson) {
  const raw = fs.readFileSync(0, 'utf8');
  const parsed = JSON.parse(raw);
  const extraRemappings = Array.isArray(parsed?.settings?.remappings) ? parsed.settings.remappings : [];
  const out = solc.compile(JSON.stringify(parsed), { import: makeImportResolver(extraRemappings) });
  process.stdout.write(out);
  process.exit(0);
}

if (positionalFiles.length === 0) {
  process.stderr.write('No input Solidity files supplied\n');
  process.exit(1);
}

const sources = {};
for (const fileArg of positionalFiles) {
  const resolved = path.isAbsolute(fileArg) ? fileArg : path.resolve(basePath, fileArg);
  sources[fileArg] = { content: fs.readFileSync(resolved, 'utf8') };
}

const stdInput = {
  language: 'Solidity',
  sources,
  settings: {
    ...(optimize ? { optimizer: { enabled: true, runs: optimizeRuns } } : {}),
    ...(evmVersion ? { evmVersion } : {}),
    outputSelection: {
      '*': {
        '*': [
          'abi',
          'evm.bytecode.object',
          'evm.deployedBytecode.object',
          'evm.bytecode.sourceMap',
          'evm.deployedBytecode.sourceMap',
          'evm.methodIdentifiers',
          'devdoc',
          'userdoc',
          'metadata',
          'storageLayout',
        ],
        '': ['ast'],
      },
    },
  },
};

const compiled = JSON.parse(solc.compile(JSON.stringify(stdInput), { import: makeImportResolver() }));
const errors = (compiled.errors || []).filter(e => e.severity === 'error');
if (errors.length) {
  for (const err of errors) {
    process.stderr.write((err.formattedMessage || err.message || 'Solidity compile error') + '\n');
  }
  process.exit(1);
}

if (combinedJsonFields) {
  const contractsOut = {};
  for (const [fileName, fileContracts] of Object.entries(compiled.contracts || {})) {
    for (const [contractName, artifact] of Object.entries(fileContracts || {})) {
      const key = `${fileName}:${contractName}`;
      const entry = {};
      if (combinedJsonFields.has('abi')) entry.abi = artifact.abi || [];
      if (combinedJsonFields.has('bin')) entry.bin = artifact.evm?.bytecode?.object || '';
      if (combinedJsonFields.has('bin-runtime')) entry['bin-runtime'] = artifact.evm?.deployedBytecode?.object || '';
      if (combinedJsonFields.has('srcmap')) entry.srcmap = artifact.evm?.bytecode?.sourceMap || '';
      if (combinedJsonFields.has('srcmap-runtime')) entry['srcmap-runtime'] = artifact.evm?.deployedBytecode?.sourceMap || '';
      if (combinedJsonFields.has('hashes')) entry.hashes = artifact.evm?.methodIdentifiers || {};
      if (combinedJsonFields.has('devdoc')) entry.devdoc = artifact.devdoc || {};
      if (combinedJsonFields.has('userdoc')) entry.userdoc = artifact.userdoc || {};
      if (combinedJsonFields.has('metadata')) entry.metadata = artifact.metadata || '';
      if (combinedJsonFields.has('storage-layout')) entry['storage-layout'] = artifact.storageLayout || {};
      contractsOut[key] = entry;
    }
  }
  const sourcesOut = {};
  for (const [fileName, fileData] of Object.entries(compiled.sources || {})) {
    sourcesOut[fileName] = { AST: fileData.ast || {} };
  }
  const result = {
    contracts: contractsOut,
    sourceList: Object.keys(compiled.sources || {}),
    sources: sourcesOut,
    version: solc.version(),
  };
  process.stdout.write(JSON.stringify(result));
  process.exit(0);
}

process.stdout.write(JSON.stringify(compiled));
