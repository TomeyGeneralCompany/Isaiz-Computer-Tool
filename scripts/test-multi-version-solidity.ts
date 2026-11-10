import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
/** Verifies offline multi-version Solidity compilation and execution across 0.5.17, 0.6.12, 0.7.6, and 0.8.30 */
import assert from "node:assert/strict";
import { compilerCompatible } from "../packages/security-solver/src/source-capability";

// 1. Verify capability preflight across compiler ranges
assert.equal(compilerCompatible("0.5.17"), true, "Solidity 0.5.17 exact pragma must be compatible");
assert.equal(compilerCompatible("^0.5.0"), true, "Solidity ^0.5.0 pragma range must be compatible");
assert.equal(compilerCompatible(">=0.5.0 <0.6.0"), true, "Solidity >=0.5.0 <0.6.0 must be compatible");
assert.equal(compilerCompatible("0.6.12"), true, "Solidity 0.6.12 must be compatible");
assert.equal(compilerCompatible("^0.6.0"), true, "Solidity ^0.6.0 must be compatible");
assert.equal(compilerCompatible("0.7.6"), true, "Solidity 0.7.6 must be compatible");
assert.equal(compilerCompatible("^0.7.0"), true, "Solidity ^0.7.0 must be compatible");
assert.equal(compilerCompatible("0.8.30"), true, "Solidity 0.8.30 must be compatible");
assert.equal(compilerCompatible("^0.8.0"), true, "Solidity ^0.8.0 must be compatible");
assert.equal(compilerCompatible("^0.8.24"), true, "Solidity ^0.8.24 must be compatible");
assert.equal(compilerCompatible("0.4.24"), false, "Unsupported legacy compiler 0.4.x must be rejected");

console.log("compilerCompatible preflight checks across 0.5.17, 0.6.12, 0.7.6, 0.8.30: PASSED");

// 2. Test compilation and execution across all 4 compiler versions
const ganache = require("./reproduction-runtime/node_modules/ganache");
const { validateSequence, runSequence } = require("./reproduction-runtime/solidity-sequence.cjs");

const versions = [
  {
    name: "0.5.17",
    pkg: "./reproduction-runtime/node_modules/solc_0_5",
    evm: "petersburg",
    source: `pragma solidity 0.5.17;
contract LegacyStorage05 {
    uint256 public stored;
    constructor(uint256 initial) public { stored = initial; }
    function update(uint256 next) public { stored = next; }
    function query() public view returns (uint256) { return stored; }
}`
  },
  {
    name: "0.6.12",
    pkg: "./reproduction-runtime/node_modules/solc_0_6",
    evm: "istanbul",
    source: `pragma solidity 0.6.12;
contract LegacyStorage06 {
    uint256 public stored;
    constructor(uint256 initial) public { stored = initial; }
    function update(uint256 next) public { stored = next; }
    function query() public view returns (uint256) { return stored; }
}`
  },
  {
    name: "0.7.6",
    pkg: "./reproduction-runtime/node_modules/solc_0_7",
    evm: "berlin",
    source: `pragma solidity 0.7.6;
contract LegacyStorage07 {
    uint256 public stored;
    constructor(uint256 initial) { stored = initial; }
    function update(uint256 next) public { stored = next; }
    function query() public view returns (uint256) { return stored; }
}`
  },
  {
    name: "0.8.30",
    pkg: "./reproduction-runtime/node_modules/solc",
    evm: "shanghai",
    source: `pragma solidity 0.8.30;
contract Storage08 {
    uint256 public stored;
    constructor(uint256 initial) { stored = initial; }
    function update(uint256 next) public { stored = next; }
    function query() public view returns (uint256) { return stored; }
}`
  }
];

for (const v of versions) {
  const compiler = require(v.pkg);
  const compiled = JSON.parse(compiler.compile(JSON.stringify({
    language: "Solidity",
    sources: { "Storage.sol": { content: v.source } },
    settings: {
      evmVersion: v.evm,
      outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } }
    }
  })));
  assert.equal((compiled.errors || []).filter((e: any) => e.severity === "error").length, 0,
    `Solidity ${v.name} compilation should have 0 errors`);

  const contractName = Object.keys(compiled.contracts["Storage.sol"])[0];
  const artifact = compiled.contracts["Storage.sol"][contractName];

  const transport = ganache.provider({
    logging: { quiet: true },
    wallet: { deterministic: true, totalAccounts: 3 },
    chain: { hardfork: v.evm, chainId: 1337, time: new Date("2020-01-01T00:00:00Z") },
    miner: { blockGasLimit: 12000000, timestampIncrement: 1 }
  });

  const sequence = {
    constructorArgs: ["100"],
    steps: [
      { operation: "observe", function: "query()", args: [] },
      { operation: "send", function: "update(uint256)", args: ["200"] },
      { operation: "observe", function: "query()", args: [] }
    ]
  };

  const observations = await runSequence(artifact, sequence, transport);
  assert.equal(observations.steps[0].actual, "100", `Initial query in ${v.name} must be 100`);
  assert.equal(observations.steps[1].passed, true, `Send in ${v.name} must pass`);
  assert.equal(observations.steps[2].actual, "200", `Observed update in ${v.name} must be 200`);

  console.log(`Solidity ${v.name} (EVM: ${v.evm}) compile + deploy + sequence execution: PASSED`);
}

console.log("All multi-version Solidity compiler tests PASSED");
