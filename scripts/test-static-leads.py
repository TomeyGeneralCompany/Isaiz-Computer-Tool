#!/usr/bin/env python3
"""Integration checks use real scanners on owned source only."""
import importlib.util
import subprocess
import tempfile
from pathlib import Path
spec = importlib.util.spec_from_file_location('static', Path(__file__).with_name('source-static.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    (root/'example.py').write_text('def render(value):\n    return "<p>" + value + "</p>"\n')
    (root/'Example.sol').write_text('pragma solidity ^0.8.30; contract Example { address owner; function check() public view { require(tx.origin == owner); } }')
    subprocess.run(['git','init','-q',temp],check=True)
    subprocess.run(['git','-C',temp,'add','.'],check=True)
    result = module.analyze(temp, 'semgrep')
    assert result['status'] in ('completed','partial'), result
    assert any(lead['path']=='example.py' for lead in result['leads']), result
    result = module.analyze(temp, 'slither', 'Example.sol')
    assert result['status'] in ('completed','partial'), result
    assert any(lead['path']=='Example.sol' for lead in result['leads']), result
    assert module.analyze(temp, 'slither', '../escape.sol')['status']=='unsupported_target'
print('Real offline Semgrep and Slither owned-fixture leads PASSED')
