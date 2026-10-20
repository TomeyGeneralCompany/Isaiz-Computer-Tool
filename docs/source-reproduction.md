# Source reproduction

The active source audit exposes verify_source; verify_python remains a backwards-compatible action alias. Both route through the same source-case persistence and independent replay path.

Supported source files:
- Python .py: public top-level string -> string functions.
- JavaScript .js, .mjs, .cjs: exported string -> string functions, including async functions and CommonJS named/default object exports. The repository's package.json determines .js module semantics.
- Solidity .sol: public/external pure or view string -> string functions on contracts deployable without constructor arguments. Select Contract.function when multiple contracts exist. Solidity compiles with solc 0.8.30 targeting Shanghai and deploys to a deterministic in-memory Ganache EVM. No RPC endpoint or wallet credentials are used.

The two existing probe kinds remain html_reflection and path_construction. This is bounded behavior reproduction, not general-purpose execution of generated exploit scripts. Stateful/multi-transaction Solidity exploits, constructor arguments, external services, and incompatible compiler pragmas need additional probe types. Compilation or execution errors produce probe_failed, never a successful observation.

## Personal machine setup

Keep Node.js 22, Python 3, and bubblewrap installed. After pulling this branch or its merged changes, run from the repository root:

    npm install --prefix scripts/reproduction-runtime --ignore-scripts --no-audit --no-fund

This is a one-time local toolchain installation (repeat after runtime dependency updates); sandboxed target execution never accesses the network. JavaScript can run without the Solidity dependencies installed. Solidity reports blocked_no_runtime with the installation command if its toolchain is missing. Target npm dependencies are prepared from package-lock.json v2/v3 before sandbox execution. The preparer downloads only npm registry tarballs, verifies SHA-256/SHA-512 integrity, and extracts packages without running install scripts. Packages are reused within the checkout; independent replay prepares its own copy from the same committed lockfile. Limits: 512 lockfile package entries, 20 MiB per archive, 256 MiB extracted content, and a bounded download period. Projects requiring native build scripts, other package managers, or absent lockfiles without vendored dependencies return unsupported_dependencies. This preparation uses the network; target execution remains network-isolated.

Solidity imports resolve repository paths, node_modules, lib, remappings.txt and the remappings array in foundry.toml profile.default (Python 3.11+). Executable project configuration is never loaded.

The automatic lead queue accepts all supported extensions and retries JavaScript/Solidity leads skipped by the previous Python-only implementation. Per-target failures are counted separately from infrastructure failures, so a failed function does not discard later successful evidence.

Run the full language regression suite on a Linux host that permits bubblewrap namespaces:

    TOMEY_REPRODUCTION_INTEGRATION=1 python3 -m unittest discover -s tests -p test_source_reproduction.py -v

All three languages retain the read-only repository, network namespace isolation, wall/CPU/output limits and source hash checks. Node receives a larger virtual address-space limit for V8/Wasm reservations, with a 256 MiB V8 heap limit. Solidity deployment and calls have explicit gas limits.

Full host acceptance now runs the real language tests without requiring an environment flag. Offline-only acceptance remains independent of installed sandbox/EVM dependencies. CI also runs scripts/test-source-workflow.ts against actual owned Git source, model tool actions, sandbox execution, report creation, persisted cases and independent replay.
