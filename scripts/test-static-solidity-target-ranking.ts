import assert from 'node:assert/strict';
import {rankSolidityStaticTargets} from '../packages/security-solver/src/local-static-leads';

const prefix='source-1';
const paths=[
  'source-1/contracts/libs/Math.sol',
  'source-1/contracts/mocks/Vault.sol',
  'source-1/contracts/vesting/Vesting02.sol',
  'source-1/contracts/test/VaultTest.sol',
  'source-1/contracts/core/DInterest.sol',
  'source-1/contracts/token/ERC20.sol',
  'source-1/contracts/MPHMinter.sol',
  'source-1/contracts/helpers/Address.sol',
  'source-1/contracts/vaults/Vault.sol',
  'source-1/vendor/Pool.sol',
];
assert.deepEqual(rankSolidityStaticTargets(paths,prefix),[
  'contracts/vesting/Vesting02.sol',
  'contracts/core/DInterest.sol',
  'contracts/MPHMinter.sol',
  'contracts/vaults/Vault.sol',
  'contracts/libs/Math.sol',
  'contracts/token/ERC20.sol',
], 'Core project contracts should outrank generic files and excluded test assets');
assert.deepEqual(rankSolidityStaticTargets(paths,prefix,2),[
  'contracts/vesting/Vesting02.sol','contracts/core/DInterest.sol'
], 'Target count is bounded and deterministic');
assert.deepEqual(rankSolidityStaticTargets(['other/contracts/Vault.sol'],prefix),[],
  'A repository must not scan paths belonging to a different acquired repository');
console.log('Static Solidity target ranking tests passed');
