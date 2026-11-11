#!/usr/bin/env python3
"""Regression: read only literal pinned Hardhat compiler settings, never execute config."""
from pathlib import Path
from tempfile import TemporaryDirectory
import importlib.util

spec=importlib.util.spec_from_file_location('source_reproduction',Path('scripts/source-reproduction.py'))
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with TemporaryDirectory() as tmp:
    root=Path(tmp)
    config=root/'hardhat.config.ts'
    config.write_text("""
    throw new Error('this must never be executed');
    const config = { solidity: { version: '0.8.4', settings: {
      optimizer: { enabled: true, runs: 200 }
    }}};
    """)
    assert module.static_hardhat_compiler_settings(root,'pragma solidity 0.8.4;') == {
        'optimizer':{'enabled':True,'runs':200}}
    assert module.static_hardhat_compiler_settings(root,'pragma solidity 0.8.30;') == {}
    config.write_text("const config={solidity:{version: getVersion(),settings:{optimizer:{enabled:true,runs:200}}}}")
    assert module.static_hardhat_compiler_settings(root,'pragma solidity 0.8.4;') == {}
    config.unlink()
    config.symlink_to('/etc/passwd')
    try:
        module.static_hardhat_compiler_settings(root,'pragma solidity 0.8.4;')
        raise AssertionError('Symlinked target config was accepted')
    except ValueError:
        pass
print('Static Hardhat compiler settings regression passed')
