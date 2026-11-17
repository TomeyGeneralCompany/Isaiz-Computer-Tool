#!/usr/bin/env python3
"""Offline tests for multi-class Solidity security evidence, compile caching, and pragma selection."""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from solidity_security_evidence import security_behavior_observed, security_experiment_disposition  # noqa: E402

repro_spec = importlib.util.spec_from_file_location('source_repro', SCRIPTS_DIR / 'source-reproduction.py')
repro_mod = importlib.util.module_from_spec(repro_spec)
repro_spec.loader.exec_module(repro_mod)

static_spec = importlib.util.spec_from_file_location('source_static', SCRIPTS_DIR / 'source-static.py')
static_mod = importlib.util.module_from_spec(static_spec)
static_spec.loader.exec_module(static_mod)


ACCOUNTS = [
    "0x" + "11" * 20,
    "0x" + "22" * 20,
    "0x" + "33" * 20,
]
CONTRACT_ADDR = "0x" + "44" * 20


class SoliditySecurityEvidenceTests(unittest.TestCase):
    def test_reinit_takeover_positive_and_single_init_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vault = root / "contracts" / "Vault.sol"
            vault.parent.mkdir(parents=True)
            vault.write_text(
                "pragma solidity ^0.8.4;\n"
                "contract Vault {\n"
                "  address public owner;\n"
                "  function initialize(address _owner, uint256 _fee) external {\n"
                "    owner = _owner;\n"
                "  }\n"
                "}\n",
                encoding="utf8",
            )
            steps_takeover = [
                {"operation": "send", "function": "initialize(address,uint256)", "sender": 0, "reverted": False, "passed": True},
                {"operation": "call", "function": "owner()", "sender": 0, "actual": ACCOUNTS[0], "passed": True},
                {"operation": "send", "function": "initialize(address,uint256)", "sender": 1, "reverted": False, "passed": True},
                {"operation": "call", "function": "owner()", "sender": 0, "actual": ACCOUNTS[1], "passed": False},
            ]
            ok, cls, _ = security_behavior_observed(
                root, vault, "Vault.initialize", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": steps_takeover}
            )
            self.assertTrue(ok)
            self.assertEqual(cls, "reinit_or_constructor_takeover")

            # Upgradeable proxy guarded on 2nd init: $account1 reverts, owner remains $account0
            steps_guarded = [
                {"operation": "send", "function": "initialize(address,uint256)", "sender": 0, "reverted": False, "passed": True},
                {"operation": "call", "function": "owner()", "sender": 0, "actual": ACCOUNTS[0], "passed": True},
                {"operation": "send", "function": "initialize(address,uint256)", "sender": 1, "reverted": True, "passed": True},
                {"operation": "call", "function": "owner()", "sender": 0, "actual": ACCOUNTS[0], "passed": True},
            ]
            ok2, cls2, _ = security_behavior_observed(
                root, vault, "Vault.initialize", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": steps_guarded}
            )
            self.assertFalse(ok2)
            self.assertIsNone(cls2)
            # An explicit, fully asserted denied unauthorized transition is a
            # genuine negative outcome, not an unclassified observation.
            guarded_spec = {"sequence": {"steps": [
                {"operation": "send", "function": "initialize(address,uint256)", "sender": 0},
                {"operation": "call", "function": "owner()"},
                {"operation": "send", "function": "initialize(address,uint256)",
                 "sender": 1, "expectRevert": True},
                {"operation": "call", "function": "owner()"},
            ]}}
            status, category, reason = security_experiment_disposition(
                root, vault, "Vault.initialize",
                {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": steps_guarded},
                guarded_spec,
            )
            self.assertEqual(status, "behavior_not_observed")
            self.assertEqual(category, "guarded_negative")
            self.assertIn("unchanged", reason)

            # No explicit falsification or a failed assertion remains inconclusive.
            status_unproven, _, _ = security_experiment_disposition(
                root, vault, "Vault.initialize",
                {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": steps_guarded},
            )
            self.assertEqual(status_unproven, "observation_only")
            failing = [dict(step) for step in steps_guarded]
            failing[-1]["passed"] = False
            status_failed, _, _ = security_experiment_disposition(
                root, vault, "Vault.initialize",
                {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": failing},
                guarded_spec,
            )
            self.assertEqual(status_failed, "observation_only")
            status_positive, classification_positive, _ = security_experiment_disposition(
                root, vault, "Vault.initialize",
                {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": steps_takeover},
                guarded_spec,
            )
            self.assertEqual(status_positive, "behavior_observed")
            self.assertEqual(classification_positive, "reinit_or_constructor_takeover")

    def test_eth_and_erc20_extraction_and_guard_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            treasury = root / "contracts" / "Treasury.sol"
            treasury.parent.mkdir(parents=True)
            treasury.write_text(
                "pragma solidity ^0.8.4;\n"
                "contract Treasury {\n"
                "  address public owner;\n"
                "  constructor() { owner = msg.sender; }\n"
                "  function sweepETH(address payable to) external {\n"
                "    to.transfer(address(this).balance);\n"
                "  }\n"
                "  function rescueToken(address token, address to, uint256 amt) external {\n"
                "    IERC20(token).transfer(to, amt);\n"
                "  }\n"
                "}\n",
                encoding="utf8",
            )
            eth_steps = [
                {"operation": "eth_balance", "account": "$contract", "address": CONTRACT_ADDR, "balanceWei": "1000000000000000000"},
                {"operation": "eth_balance", "account": "$account1", "address": ACCOUNTS[1], "balanceWei": "500000000000000000"},
                {"operation": "send", "function": "sweepETH(address)", "sender": 1, "reverted": False, "passed": True},
                {"operation": "eth_balance", "account": "$contract", "address": CONTRACT_ADDR, "balanceWei": "0"},
                {"operation": "eth_balance", "account": "$account1", "address": ACCOUNTS[1], "balanceWei": "1500000000000000000"},
            ]
            ok_eth, cls_eth, _ = security_behavior_observed(
                root, treasury, "Treasury.sweepETH", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": eth_steps}
            )
            self.assertTrue(ok_eth)
            self.assertEqual(cls_eth, "unauthorized_value_extraction")

            erc20_steps = [
                {"operation": "call", "deploymentId": "token", "function": "balanceOf(address)", "sender": 0, "actual": "1000", "passed": True},
                {"operation": "call", "deploymentId": "token", "function": "balanceOf(address)", "sender": 0, "actual": "0", "passed": True},
                {"operation": "send", "function": "rescueToken(address,address,uint256)", "sender": 1, "reverted": False, "passed": True},
                {"operation": "call", "deploymentId": "token", "function": "balanceOf(address)", "sender": 0, "actual": "0", "passed": True},
                {"operation": "call", "deploymentId": "token", "function": "balanceOf(address)", "sender": 0, "actual": "1000", "passed": True},
            ]
            ok_erc, cls_erc, _ = security_behavior_observed(
                root, treasury, "Treasury.rescueToken", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": erc20_steps}
            )
            self.assertTrue(ok_erc)
            self.assertEqual(cls_erc, "unauthorized_value_extraction")

            # Source guard blocks classification even on unexpected trace
            treasury.write_text(
                treasury.read_text(encoding="utf8").replace(
                    "function sweepETH(address payable to) external {",
                    "function sweepETH(address payable to) external { require(msg.sender == owner);",
                ),
                encoding="utf8",
            )
            ok_guarded, _, _ = security_behavior_observed(
                root, treasury, "Treasury.sweepETH", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": eth_steps}
            )
            self.assertFalse(ok_guarded)

    def test_non_mock_mint_vs_mock_exclusion_and_primitives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tok = root / "contracts" / "Token.sol"
            tok.parent.mkdir(parents=True)
            tok.write_text(
                "pragma solidity ^0.8.4;\n"
                "contract Token {\n"
                "  uint256 public totalSupply;\n"
                "  mapping(address => uint256) public balanceOf;\n"
                "  function mint(address to, uint256 amount) external {\n"
                "    totalSupply += amount; balanceOf[to] += amount;\n"
                "  }\n"
                "  function exec(address target, bytes calldata data) external {\n"
                "    target.delegatecall(data);\n"
                "  }\n"
                "}\n",
                encoding="utf8",
            )
            mint_steps = [
                {"operation": "call", "function": "balanceOf(address)", "sender": 0, "actual": "0", "passed": True},
                {"operation": "call", "function": "totalSupply()", "sender": 0, "actual": "0", "passed": True},
                {"operation": "send", "function": "mint(address,uint256)", "sender": 1, "reverted": False, "passed": True},
                {"operation": "call", "function": "balanceOf(address)", "sender": 0, "actual": "500", "passed": True},
                {"operation": "call", "function": "totalSupply()", "sender": 0, "actual": "500", "passed": True},
            ]
            ok_mint, cls_mint, _ = security_behavior_observed(
                root, tok, "Token.mint", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": mint_steps}
            )
            self.assertTrue(ok_mint)
            self.assertEqual(cls_mint, "unauthorized_value_extraction")

            # Mock path must never be flagged for unguarded minting
            mock = root / "contracts" / "mocks" / "ERC20Mock.sol"
            mock.parent.mkdir(parents=True)
            mock.write_text(tok.read_text(encoding="utf8"), encoding="utf8")
            ok_mock, _, _ = security_behavior_observed(
                root, mock, "Token.mint", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": mint_steps}
            )
            self.assertFalse(ok_mock)

            # Unguarded delegatecall primitive
            prim_steps = [
                {"operation": "send", "function": "exec(address,bytes)", "sender": 1, "reverted": False, "passed": True},
            ]
            ok_prim, cls_prim, _ = security_behavior_observed(
                root, tok, "Token.exec", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": prim_steps}
            )
            self.assertTrue(ok_prim)
            self.assertEqual(cls_prim, "unguarded_dangerous_primitive")

    def test_expected_mismatch_alone_never_classifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pool = root / "contracts" / "Pool.sol"
            pool.parent.mkdir(parents=True)
            pool.write_text(
                "pragma solidity ^0.8.4;\n"
                "contract Pool {\n"
                "  uint256 public totalDeposited;\n"
                "  function deposit(uint256 amt) external { totalDeposited += amt; }\n"
                "}\n",
                encoding="utf8",
            )
            steps = [
                {"operation": "send", "function": "deposit(uint256)", "sender": 1, "reverted": False, "passed": True},
                {"operation": "call", "function": "totalDeposited()", "sender": 0, "actual": "7", "expected": "99", "passed": False},
            ]
            ok, cls, _ = security_behavior_observed(
                root, pool, "Pool.deposit", {"accounts": ACCOUNTS, "contract": CONTRACT_ADDR, "steps": steps}
            )
            self.assertFalse(ok)
            self.assertIsNone(cls)

    def test_compile_cache_path_and_pragma_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            cache_dir = Path(tmp) / "cache"
            root.mkdir()
            sol = root / "Vault.sol"
            sol.write_text("pragma solidity 0.8.4; contract Vault {}", encoding="utf8")
            spec = {"file": "Vault.sol", "function": "Vault.deposit", "compilerSettings": {}, "remappings": []}

            prev = os.environ.get("TOMEY_SOLC_CACHE")
            try:
                os.environ["TOMEY_SOLC_CACHE"] = str(cache_dir)
                p1 = repro_mod.solidity_compile_cache_path(root, spec)
                self.assertIsNotNone(p1)
                self.assertEqual(p1.parent, cache_dir)
                sol.write_text("pragma solidity 0.8.4; contract Vault { uint256 x; }", encoding="utf8")
                p2 = repro_mod.solidity_compile_cache_path(root, spec)
                self.assertNotEqual(p1, p2)
                os.environ["TOMEY_SOLC_CACHE"] = "0"
                self.assertIsNone(repro_mod.solidity_compile_cache_path(root, spec))
            finally:
                if prev is None:
                    os.environ.pop("TOMEY_SOLC_CACHE", None)
                else:
                    os.environ["TOMEY_SOLC_CACHE"] = prev

        self.assertEqual(static_mod.detect_solc_pkg("pragma solidity 0.8.4;"), "solc_0_8_4")
        self.assertEqual(static_mod.detect_solc_pkg("pragma solidity ^0.8.0;"), "solc_0_8_4")
        self.assertEqual(static_mod.detect_solc_pkg("pragma solidity 0.5.16;"), "solc_0_5")
        self.assertEqual(static_mod.detect_solc_pkg("pragma solidity ^0.6.12;"), "solc_0_6")
        self.assertEqual(static_mod.detect_solc_pkg("pragma solidity 0.7.6;"), "solc_0_7")
        self.assertEqual(static_mod.detect_solc_pkg("pragma solidity ^0.8.24;"), "solc")


if __name__ == "__main__":
    unittest.main()
