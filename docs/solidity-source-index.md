# Solidity source navigation

The local audit supports `outline_solidity` and `read_solidity` through both its JSON action protocol and native tools. These tools parse source locally; they do not compile or execute contracts and do not contact a model to build the index.

## Model workflow

1. Call `outline_solidity` with a workspace-relative `.sol` file. It lists declarations, including contracts, constructors, functions, modifiers, state variables, imports and inheritance headers. Each item includes its source range, line and a stable `s<source-offset>` ID. `offset` pages by declaration; follow `nextOffset`.
2. Call `read_solidity` with the same file and a function ID in `query`. A unique `Contract.function` name also works; overloaded names require an exact ID.
3. Inspect the returned function, modifier definitions, contract headers, state/type declarations, import directives and helper candidates. Follow `nextOffset` to retrieve the remaining context. Here `offset` counts characters across the deterministic source bundle, not within the original file.
4. Request helper bodies using their returned file/ID pairs. Use the original `read_file` and `search_files` tools for unresolved dependencies.

The selected function is first in its bundle. A complete function is returned when the tool message budget permits it; otherwise pagination prefers newline boundaries. Additional declarations follow at declaration boundaries when they fit. Every excerpt carries its original workspace-relative path and exact UTF-16 `[start,end)` source offsets. Tool output, including JSON escaping, is bounded by the audit's available message budget and an 8,000-character ceiling.

Outline metadata does not count as a source read. Only source excerpts actually included in a successful `read_solidity` response enter the existing evidence ledger. Pagination never marks the undisplayed remainder of a function as inspected. Existing probe and final-report validation still apply.

## Resolution and resource limits

Relative imports, named import aliases, unit aliases and recursive base contracts are supported. Cyclic imports terminate. State/type declarations from resolved bases are included conservatively rather than assuming a text match identifies every relevant variable. Matching applied modifiers are included conservatively; helper references are candidates, not compiler-resolved call bindings. Ambiguous bases, unresolved calls and imports are reported explicitly. Lists abbreviated for context budget retain `moreHelpers`/`moreUnresolved` flags.

Package imports and Foundry remappings are not guessed. Compiler overload resolution, C3 dispatch, dynamic calls and library binding are not established by this syntax index. Use explicit source reads where the index reports missing context. Parsing failure, unsupported syntax or resource limits produce tool feedback; the model can continue with the original paginated reader. No claim of whole-program coverage follows from a complete bundle.

ASTs are cached in memory by parser version, Git commit and content hash, allowing unchanged files in repeated hunts to reuse parsed data while changed content invalidates it. This is an evictable cache, not a persisted evidence store. It is limited to 32 files / 4 MB of source; each parsed file is limited to 512 KB. Each audit's import graph also has 32-file / 4-MB limits. Files too large for indexing remain eligible for the ordinary reader's separate limits. Resolved paths must stay inside the authorized hunt workspace, including when imports or symlinks are supplied.

## Validation

`scripts/test-solidity-source-index.ts` checks constructors, overload IDs, aliased inheritance, inherited modifiers and state, cyclic imports, helper references, Unicode offsets, paginated evidence coverage, bounded JSON output, content-cache invalidation, oversized/malformed source fallback, path escapes and both production model protocols. It also verifies that an outline alone cannot satisfy the runner's successful-source-read requirement.
