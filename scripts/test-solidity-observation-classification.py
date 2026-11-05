#!/usr/bin/env python3
"""No EVM/network needed: classify recorded transactions, not guessed output."""
import importlib.util
from pathlib import Path
spec=importlib.util.spec_from_file_location('lotus_source_reproduction',Path(__file__).with_name('source-reproduction.py'))
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
evaluate=module.observed_non_deployer_state_transition
before={'operation':'observe','function':'operator()','sender':0,'actual':'0x0000000000000000000000000000000000000001'}
send={'operation':'send','function':'rotateOperator(address)','sender':1,'reverted':False,'passed':True}
after={**before,'actual':'0x0000000000000000000000000000000000000002'}
assert evaluate([before,send,after])
assert not evaluate([before,{**send,'reverted':True},after]), 'reverted send cannot establish state mutation'
assert not evaluate([before,{**send,'sender':0},after]), 'deployer action does not prove cross-account mutation'
assert not evaluate([before,send,before]), 'no state change cannot be a positive behavior'
assert not evaluate([before,send,{**after,'function':'administrator()'}]), 'unrelated getter cannot prove the send effect'
assert not evaluate([before,send,{**after,'sender':2}]), 'different getter caller context is not comparable'
assert not evaluate([before,{'operation':'call','function':'value()','passed':False},after])
print('Solidity non-deployer state-transition classifier PASSED')
