import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { runLocalAudit } from '../packages/security-solver/src/local-ollama-runner';
import { InvestigationWorkflow } from '../packages/security-solver/src/investigation-workflow';
import { ControllerStageLock } from '../packages/security-solver/src/controller-stage-lock';

const hash = (s: string) => createHash('sha256').update(s).digest('hex');

async function withEnv(overrides: Record<string, string | undefined>, fn: () => Promise<void>) {
  const saved: Record<string, string | undefined> = {};
  for (const key of Object.keys(overrides)) {
    saved[key] = process.env[key];
    const val = overrides[key];
    if (val === undefined) delete process.env[key];
    else process.env[key] = val;
  }
  try {
    await fn();
  } finally {
    for (const key of Object.keys(overrides)) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  }
}

function buildDInterestSource(totalChars = 59255): string {
  // First 58000 chars page cleanly; final 1255 chars contain quotes/backslashes whose
  // double JSON-escaping inside TOOL_RESULT forces fitAuditToolOutput to truncate raw EOF
  // (rawPage.nextOffset === null -> delivered page.end < 59255, page.nextOffset = page.end).
  const head = '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract DInterest {\n';
  const midUnit = '  uint256 constant X = 1;\n';
  let prefix = head;
  while (prefix.length + midUnit.length <= 58000) prefix += midUnit;
  if (prefix.length < 58000) prefix += '//' + ' '.repeat(58000 - prefix.length - 3) + '\n';
  assert.equal(prefix.length, 58000);
  const tailTarget = totalChars - 58000;
  const footer = '}\n';
  const tailPattern = '"\\';
  let tail = '// ';
  while (tail.length + tailPattern.length <= tailTarget - footer.length) tail += tailPattern;
  tail += 'a'.repeat(tailTarget - footer.length - tail.length) + footer;
  const result = prefix + tail;
  assert.equal(result.length, totalChars, 'Expected exact 59255-char fixture');
  return result;
}

// 1 & 2. Truncated-terminal-page + Stage-vs-legacy recovery test
async function testTruncatedTerminalPageAndStagePriority() {
  const root = await mkdtemp(join(tmpdir(), 'lotus-stage-read-truncated-'));
  let generations = 0;
  const server = createServer(async (req, res) => {
    for await (const _ of req) {}
    generations++;
    res.end(JSON.stringify({
      message: {
        role: 'assistant',
        content: JSON.stringify({ action: 'final', path: '', query: '', answer: '{"findings":[]}' }),
      },
    }));
  });

  try {
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as any).port;
    const dInterest = buildDInterestSource(59255);
    const fee = '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract DInterestWithDepositFee {}\n';
    const lens = '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract DInterestLens {}\n';
    const mock = '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract AaveMiningMock {}\n';

    const pDInterest = 'source-1/contracts/DInterest.sol';
    const pFee = 'source-1/contracts/DInterestWithDepositFee.sol';
    const pLens = 'source-1/contracts/DInterestLens.sol';
    const pMock = 'source-1/contracts/mocks/AaveMiningMock.sol';

    for (const [rel, content] of [
      [pDInterest, dInterest],
      [pFee, fee],
      [pLens, lens],
      [pMock, mock],
    ] as const) {
      const full = join(root, rel);
      await mkdir(dirname(full), { recursive: true });
      await writeFile(full, content);
    }

    const spans: Array<{ path: string; start: number; end: number }> = [];
    const log = join(root, 'audit.log');
    await withEnv({
      AUTOHACK_OLLAMA_URL: `http://127.0.0.1:${port}/api/chat`,
      LOCAL_OLLAMA_TOOL_PROTOCOL: 'json',
      AUTOHACK_AUTO_SOURCE_PREFETCH: 'false',
      LOCAL_CONTROLLER_OWNED_ACTIONS: 'true',
      LOCAL_CONTROLLER_FULL_SOURCE_INDEX: 'true',
    }, async () => {
      // numCtx=6200 produces a context budget where a ~1255-char raw final page with escaped quotes
      // shrinks inside fitAuditToolOutput on the final chunk while earlier chunks fit cleanly.
      const out = await runLocalAudit('Inspect contracts', log, 30000, root, 'mock', undefined, {
        productionWorkflow: true,
        dynamicAllowance: true,
        verifyPython: async () => JSON.stringify({ status: 'behavior_not_observed', behavior_observed: false }),
        maxTurns: 200,
        numCtx: 5000,
        numPredict: 256,
        initialSourcePaths: [pDInterest, pFee, pLens, pMock],
        onRead: (path, span) => spans.push({ path, ...span }),
      });
      assert.equal(JSON.parse(out).outcome, 'no_testable_candidate');
    });

    const logText = await readFile(log, 'utf8');
    // Verify DInterest.sol had a truncated near-terminal page followed immediately by its exact tail
    const dInterestSpans = spans.filter(s => s.path === pDInterest);
    assert.ok(dInterestSpans.length >= 2, 'Expected multi-page reading of DInterest.sol');
    const firstNonDInterestIdx = spans.findIndex(s => s.path !== pDInterest);
    const lastDInterestIdx = spans.map(s => s.path).lastIndexOf(pDInterest);
    assert.ok(
      firstNonDInterestIdx === -1 || lastDInterestIdx < firstNonDInterestIdx,
      `Expected DInterest.sol to complete 100% before any other file began (lastDInterest=${lastDInterestIdx}, firstOther=${firstNonDInterestIdx})`
    );
    // Verify contiguous [0, 59255) coverage with zero gaps
    let cursor = 0;
    for (const s of dInterestSpans) {
      assert.equal(s.start, cursor, `Expected contiguous offset ${cursor}, got ${s.start}`);
      cursor = s.end;
    }
    assert.equal(cursor, 59255, 'Expected full 59255 characters of DInterest.sol to be delivered');
    // Confirm the fitted truncation scenario actually happened (the penultimate span ended < 59255 and last span finished the tail)
    assert.ok(dInterestSpans.length >= 3, 'Expected paginated chunks plus fitted tail chunk');
    const tailLen = dInterestSpans.at(-1)!.end - dInterestSpans.at(-1)!.start;
    assert.ok(tailLen > 0 && tailLen < 1000, `Expected small truncated tail chunk, got ${tailLen} chars`);

    assert.ok(!logText.includes('[INDEXED_COMPLETED_READ_REJECTED]'), 'Must not misclassify truncated final page as complete');
    assert.ok(!logText.includes('[INDEXED_SOURCE_RECOVERY_DECISION]'), 'Must not invoke legacy recovery during locked READ');
    assert.ok(!logText.includes('[INDEXED_CONTROLLER_SOURCE_HANDOFF]'), 'Must not hand off away from incomplete DInterest.sol');
    assert.ok(!logText.includes('[WORKFLOW_REJECTED]'), 'Must not emit WORKFLOW_REJECTED during locked READ');
    assert.equal(generations, 0, 'Model should not be asked to pick files during deterministic READ/empty-queue flow');
    console.log('1 & 2. Truncated-terminal-page & strict READ stage priority PASSED');
  } finally {
    server.closeAllConnections();
    server.close();
    await rm(root, { recursive: true, force: true });
  }
}

// 3. Required-source conflict test (under stageLock + post-probe EXPERIMENT + legacy !stageLock)
async function testRequiredSourceConflictAndLegacyPreservation() {
  // 3a. Workflow unit behavior under stageLock vs !stageLock
  const lockedWf = new InvestigationWorkflow();
  const lock = new ControllerStageLock();
  const srcA = 'const a = 1;\n';
  const srcB = 'const b = 2;\n';
  lock.completeIndex([
    { path: 'source-1/a.js', characters: srcA.length, sha256: hash(srcA) },
    { path: 'source-1/b.js', characters: srcB.length, sha256: hash(srcB) },
  ]);
  lockedWf.bindStageLock(lock);
  lockedWf.requireSource('source-1/b.js');
  lockedWf.requireSources(['source-1/b.js']);
  assert.equal(lockedWf.requireNextUnreadSource(['source-1/a.js', 'source-1/b.js']), null);
  assert.deepEqual(await lockedWf.constraints(), { action: ['read_file'] });
  assert.equal(lockedWf.validate({ action: 'read_file', path: 'source-1/a.js', query: '', answer: '', offset: 0 } as any), null);

  // Legacy !stageLock preserves requireSource / requireSources / requireNextUnreadSource enforcement
  const legacyWf = new InvestigationWorkflow();
  legacyWf.requireSource('source-1/b.js');
  assert.deepEqual(await legacyWf.constraints(), { action: ['read_file'], path: ['source-1/b.js'] });
  assert.match(
    legacyWf.validate({ action: 'read_file', path: 'source-1/a.js', query: '', answer: '', offset: 0 } as any) || '',
    /Read the required candidate source source-1\/b\.js/
  );

  // 3b. End-to-end post-probe EXPERIMENT stagedPlans test:
  // Candidate 1 reproduces behavior -> post-probe calls requireSource/requireSources -> Candidate 2 MUST STILL RUN (not get rejected)
  const root = await mkdtemp(join(tmpdir(), 'lotus-stage-experiment-req-'));
  let reviewCalls = 0;
  const probedPaths: string[] = [];
  const server = createServer(async (req, res) => {
    for await (const _ of req) {}
    reviewCalls++;
    res.end(JSON.stringify({
      message: {
        role: 'assistant',
        content: JSON.stringify({
          action: 'final',
          path: '',
          query: '',
          answer: JSON.stringify({
            findings: [],
            outcome: 'no_finding',
            reason: 'Reviewed all observations cleanly.',
          }),
        }),
      },
    }));
  });

  try {
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as any).port;
    const p1 = 'source-1/routes/first.js';
    const p2 = 'source-1/routes/second.js';
    const p3 = 'source-1/routes/caller.js';
    const code1 = 'export function renderFirst(value) {\n  return "<p>" + value + "</p>";\n}\n';
    const code2 = 'export function renderSecond(value) {\n  return "<p>" + value + "</p>";\n}\n';
    const code3 = '// passive caller module with no probe function\nexport const ENTRY = true;\n';
    for (const [rel, c] of [[p1, code1], [p2, code2], [p3, code3]] as const) {
      await mkdir(dirname(join(root, rel)), { recursive: true });
      await writeFile(join(root, rel), c);
    }

    const log = join(root, 'audit.log');
    const fakeCaseId = 'a'.repeat(64);
    await withEnv({
      AUTOHACK_OLLAMA_URL: `http://127.0.0.1:${port}/api/chat`,
      LOCAL_OLLAMA_TOOL_PROTOCOL: 'json',
      AUTOHACK_AUTO_SOURCE_PREFETCH: 'false',
      LOCAL_CONTROLLER_OWNED_ACTIONS: 'true',
      LOCAL_CONTROLLER_FULL_SOURCE_INDEX: 'true',
    }, async () => {
      const out = await runLocalAudit('Inspect JS routes', log, 30000, root, 'mock', undefined, {
        productionWorkflow: true,
        dynamicAllowance: true,
        maxTurns: 40,
        numCtx: 8192,
        numPredict: 256,
        initialSourcePaths: [p1, p2, p3],
        onVerifiedCase: async () => ({ callers: [p3] }),
        verifyPython: async (path, query, kind) => {
          probedPaths.push(path);
          if (path === p1) {
            return JSON.stringify({
              status: 'behavior_observed',
              behavior_observed: true,
              caseId: fakeCaseId,
              observations: [{ input: '<b>x</b>', output: '<p><b>x</b></p>' }],
            });
          }
          return JSON.stringify({
            status: 'behavior_not_observed',
            behavior_observed: false,
            observations: [{ input: '<b>x</b>', output: '&lt;b&gt;x&lt;/b&gt;' }],
          });
        },
        validateFinal: async () => null,
      });
      assert.ok(out.includes('no_finding'));
    });

    assert.ok(probedPaths.includes(p1), 'Candidate 1 must be probed');
    assert.ok(probedPaths.includes(p2), 'Candidate 2 must ALSO be probed without being rejected by post-probe requiredSource');
    assert.ok(reviewCalls >= 1, 'Must reach REVIEW stage and invoke model for final assessment');
    const logText = await readFile(log, 'utf8');
    assert.ok(!logText.includes('Read the required candidate source'), 'requiredSource must never reject stagedPlans in EXPERIMENT');
    console.log('3. Required-source conflict & post-probe EXPERIMENT safety + legacy preservation PASSED');
  } finally {
    server.closeAllConnections();
    server.close();
    await rm(root, { recursive: true, force: true });
  }
}

// 4. Stall test under allowance.unbounded (synthetic controller stall + model rejection stall + productive unbounded run)
async function testBoundedNoProgressStallAndProductiveUnbounded() {
  // 4a. Model loop stuck emitting rejected actions in REVIEW under stageLock + allowance.unbounded
  const rootA = await mkdtemp(join(tmpdir(), 'lotus-stage-stall-review-'));
  let reviewAttempts = 0;
  const serverA = createServer(async (req, res) => {
    for await (const _ of req) {}
    reviewAttempts++;
    // Keep proposing an action forbidden in REVIEW stageLock
    res.end(JSON.stringify({
      message: {
        role: 'assistant',
        content: JSON.stringify({ action: 'read_file', path: 'source-1/routes/first.js', query: '', answer: '', offset: 0 }),
      },
    }));
  });
  try {
    await new Promise<void>(r => serverA.listen(0, '127.0.0.1', r));
    const portA = (serverA.address() as any).port;
    const p1 = 'source-1/routes/first.js';
    await mkdir(dirname(join(rootA, p1)), { recursive: true });
    await writeFile(join(rootA, p1), 'export function renderFirst(value) {\n  return "<p>" + value + "</p>";\n}\n');
    const logA = join(rootA, 'audit.log');
    await withEnv({
      AUTOHACK_OLLAMA_URL: `http://127.0.0.1:${portA}/api/chat`,
      LOCAL_OLLAMA_TOOL_PROTOCOL: 'json',
      AUTOHACK_AUTO_SOURCE_PREFETCH: 'false',
      LOCAL_CONTROLLER_OWNED_ACTIONS: 'true',
      LOCAL_CONTROLLER_FULL_SOURCE_INDEX: 'true',
    }, async () => {
      await assert.rejects(
        runLocalAudit('Inspect JS', logA, 30000, rootA, 'mock', undefined, {
          productionWorkflow: true,
          dynamicAllowance: true,
          maxTurns: 20,
          numCtx: 8192,
          numPredict: 256,
          initialSourcePaths: [p1],
          verifyPython: async () => JSON.stringify({ status: 'behavior_observed', behavior_observed: true, caseId: 'b'.repeat(64), observations: [{ ok: true }] }),
          validateFinal: async () => null,
        }),
        /STAGE_CONTROLLER_NO_PROGRESS/
      );
    });
    assert.ok(reviewAttempts >= 20 && reviewAttempts <= 26, `Expected bounded termination around 24 turns, got ${reviewAttempts}`);
    const logTextA = await readFile(logA, 'utf8');
    assert.ok(logTextA.includes('[STAGE_CONTROLLER_NO_PROGRESS]'));
    assert.ok(logTextA.includes('[AUDIT_NO_PROGRESS_TERMINATED]'));
  } finally {
    serverA.closeAllConnections();
    serverA.close();
    await rm(rootA, { recursive: true, force: true });
  }

  // 4b. Synthetic READ stall (12 consecutive identical failing synthetic turns -> throws STAGE_CONTROLLER_NO_PROGRESS)
  const rootB = await mkdtemp(join(tmpdir(), 'lotus-stage-stall-synthetic-'));
  const serverB = createServer(async (req, res) => {
    for await (const _ of req) {}
    res.end(JSON.stringify({ message: { role: 'assistant', content: '{}' } }));
  });
  try {
    await new Promise<void>(r => serverB.listen(0, '127.0.0.1', r));
    const portB = (serverB.address() as any).port;
    const p1 = 'source-1/routes/locked.js';
    const fullP1 = join(rootB, p1);
    await mkdir(dirname(fullP1), { recursive: true });
    await writeFile(fullP1, 'export const a = 1;\n');
    const logB = join(rootB, 'audit.log');
    // Remove file permissions right before read? wait: stageLock.completeIndex reads the file first during setup!
    // Instead, pass a path that gets chmod 000 in onRead? No, onRead isn't called before readSourcePage.
    // Pass a tiny file where fitAuditToolOutput cannot fit? No, even cleaner: simulate a read error on turn 1 by making a second file unreadable via onRead of first file!
    const p2 = 'source-1/routes/unreadable.js';
    const fullP2 = join(rootB, p2);
    await writeFile(fullP2, 'export const b = 2;\n');
    await withEnv({
      AUTOHACK_OLLAMA_URL: `http://127.0.0.1:${portB}/api/chat`,
      LOCAL_OLLAMA_TOOL_PROTOCOL: 'json',
      AUTOHACK_AUTO_SOURCE_PREFETCH: 'false',
      LOCAL_CONTROLLER_OWNED_ACTIONS: 'true',
      LOCAL_CONTROLLER_FULL_SOURCE_INDEX: 'true',
    }, async () => {
      try {
        await assert.rejects(
          runLocalAudit('Inspect JS', logB, 30000, rootB, 'mock', undefined, {
            productionWorkflow: true,
            dynamicAllowance: true,
            maxTurns: 20,
            numCtx: 8192,
            numPredict: 256,
            initialSourcePaths: [p1, p2],
            verifyPython: async () => JSON.stringify({ status: 'behavior_not_observed' }),
            onRead: (path) => {
              if (path === p1) {
                rmSync(fullP2, { force: true });
                mkdirSync(fullP2);
              }
            },
          }),
          /STAGE_CONTROLLER_NO_PROGRESS/
        );
      } finally {
        rmSync(fullP2, { recursive: true, force: true });
      }
    });
    const summaryB = JSON.parse(await readFile(logB + '.summary.json', 'utf8'));
    assert.ok(summaryB.turns <= 15, `Expected synthetic stall termination within 15 turns, got ${summaryB.turns}`);
    assert.equal(summaryB.successfulReads, 1, 'Failing second file must not receive any fake read credit');
    const logTextB = await readFile(logB, 'utf8');
    assert.ok(logTextB.includes('[INDEXED_CONTROLLER_PROGRESS_STALL]'));
    assert.ok(logTextB.includes('[STAGE_CONTROLLER_NO_PROGRESS]'));
    console.log('4. Bounded no-progress termination under allowance.unbounded (model & synthetic) PASSED');
  } finally {
    serverB.closeAllConnections();
    serverB.close();
    await rm(rootB, { recursive: true, force: true });
  }
}

// 5. Full 91-file inventory + productive multi-page unbounded run test
async function testFull91FileInventoryAndStageOrder() {
  const root = await mkdtemp(join(tmpdir(), 'lotus-stage-91files-'));
  const server = createServer(async (req, res) => {
    for await (const _ of req) {}
    res.end(JSON.stringify({ message: { role: 'assistant', content: '{}' } }));
  });
  try {
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as any).port;
    const paths: string[] = [];
    const expectedTexts = new Map<string, string>();
    for (let i = 0; i < 91; i++) {
      const rel = `source-1/contracts/Contract_${String(i).padStart(2, '0')}.sol`;
      paths.push(rel);
      // Make first 5 files multi-page (~4500 chars) and remaining 86 single-page
      const content = i < 5
        ? `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Contract_${i} {\n` +
          `  uint256 constant v = ${i};\n`.repeat(180) + '}\n'
        : `// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Contract_${i} { uint256 constant v = ${i}; }\n`;
      expectedTexts.set(rel, content);
      const full = join(root, rel);
      await mkdir(dirname(full), { recursive: true });
      await writeFile(full, content);
    }

    const spansByFile = new Map<string, Array<{ start: number; end: number }>>();
    const log = join(root, 'audit.log');
    await withEnv({
      AUTOHACK_OLLAMA_URL: `http://127.0.0.1:${port}/api/chat`,
      LOCAL_OLLAMA_TOOL_PROTOCOL: 'json',
      AUTOHACK_AUTO_SOURCE_PREFETCH: 'false',
      LOCAL_CONTROLLER_OWNED_ACTIONS: 'true',
      LOCAL_CONTROLLER_FULL_SOURCE_INDEX: 'true',
    }, async () => {
      // maxTurns=15 is deliberately far smaller than the >100 turns needed for 91 multi-page files,
      // proving allowance.unbounded lets genuine productive READ coverage run to completion.
      const out = await runLocalAudit('Inspect 91 contracts', log, 30000, root, 'mock', undefined, {
        productionWorkflow: true,
        dynamicAllowance: true,
        verifyPython: async () => JSON.stringify({ status: 'behavior_not_observed' }),
        maxTurns: 15,
        numCtx: 8192,
        numPredict: 256,
        initialSourcePaths: paths,
        onRead: (path, span) => {
          const list = spansByFile.get(path) || [];
          list.push(span);
          spansByFile.set(path, list);
        },
      });
      assert.equal(JSON.parse(out).outcome, 'no_testable_candidate');
    });

    assert.equal(spansByFile.size, 91, 'Every single one of the 91 indexed files must be read');
    for (const [path, text] of expectedTexts.entries()) {
      const spans = spansByFile.get(path) || [];
      let cursor = 0;
      for (const s of spans) {
        assert.equal(s.start, cursor, `Gap in ${path} coverage at ${cursor}`);
        cursor = s.end;
      }
      assert.equal(cursor, text.length, `Incomplete byte coverage for ${path}`);
    }

    const logText = await readFile(log, 'utf8');
    const readCompleteIdx = logText.indexOf('[READ_COMPLETE] {"indexed":91,"complete":91}');
    assert.ok(readCompleteIdx !== -1, 'Expected [READ_COMPLETE] with indexed=91, complete=91');
    const stageUnlockMatches = logText.match(/\[STAGE_UNLOCK\] READ -> ANALYZE/g) || [];
    assert.equal(stageUnlockMatches.length, 1, 'Expected exactly one monotonic READ -> ANALYZE transition');
    for (const lateMarker of ['[STAGE_UNLOCK] ANALYZE -> EXPERIMENT', '[STAGE_UNLOCK] EXPERIMENT -> REVIEW', '[REPORT_COMPLETE]', '"action":"plan_probe"', '"action":"verify_source"']) {
      const idx = logText.indexOf(lateMarker);
      if (idx !== -1) assert.ok(idx > readCompleteIdx, `${lateMarker} occurred before READ_COMPLETE!`);
    }
    console.log('5. Full 91-file inventory byte coverage, productive unbounded run & stage order PASSED');
  } finally {
    server.closeAllConnections();
    server.close();
    await rm(root, { recursive: true, force: true });
  }
}

await testTruncatedTerminalPageAndStagePriority();
await testRequiredSourceConflictAndLegacyPreservation();
await testBoundedNoProgressStallAndProductiveUnbounded();
await testFull91FileInventoryAndStageOrder();
console.log('ALL stage READ repair acceptance tests PASSED');
