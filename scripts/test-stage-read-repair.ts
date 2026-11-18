import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { normalizeNegativeHuntProse } from '../packages/security-solver/src/local-program-flow';
import { runLocalAudit } from '../packages/security-solver/src/local-ollama-runner';
import { InvestigationWorkflow } from '../packages/security-solver/src/investigation-workflow';
import { ControllerStageLock } from '../packages/security-solver/src/controller-stage-lock';
import { compactAuditContextWithRequiredTail } from '../packages/security-solver/src/audit-context';

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
        controllerIndex: true,
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
        controllerIndex: true,
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
          controllerIndex: true,
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
        controllerIndex: true,
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

async function testReviewStageStrictResultAndLoopRecovery() {
  // 6. Malformed final in REVIEW triggers strictResult (maxItems=0 when 0 behavior_observed)
  //    and repeated identical rejections recover cleanly within 3 turns instead of 24.
  const root = await mkdtemp(join(tmpdir(), 'lotus-review-recovery-'));
  let reviewCalls = 0;
  let sawStrictResult = false;
  let strictMaxItems: number | undefined;
  let sawStaticLeadsInReview = false;
  const server = createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    const body = JSON.parse(raw);
    reviewCalls++;
    if (body.format?.properties?.result) {
      sawStrictResult = true;
      strictMaxItems = body.format.properties.result.properties?.findings?.maxItems;
    }
    if (Array.isArray(body.messages) && body.messages.some((m: { content?: string }) =>
      typeof m.content === 'string' && m.content.includes('Controller static scanner leads') && m.content.includes('paragraph-interpolation-python')
    )) {
      sawStaticLeadsInReview = true;
    }
    if (reviewCalls === 1) {
      res.end(JSON.stringify({
        message: { role: 'assistant', content: JSON.stringify({ action: 'final', path: '', query: '', answer: 'Not valid JSON findings summary' }) },
      }));
      return;
    }
    res.end(JSON.stringify({
      message: {
        role: 'assistant',
        content: JSON.stringify({
          action: 'final',
          path: '',
          query: '',
          answer: '',
          result: { findings: [], outcome: 'no_testable_candidate', reason: 'Observed administrative functions require owner; zero exploitable behaviors.' },
        }),
      },
    }));
  });
  try {
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as any).port;
    const solPath = 'source-1/src/render.py';
    await mkdir(dirname(join(root, solPath)), { recursive: true });
    await writeFile(join(root, solPath), 'def render(value):\n    return "<p>" + value + "</p>"\n');
    const log1 = join(root, 'strict-recovery.log');
    await withEnv({
      AUTOHACK_OLLAMA_URL: `http://127.0.0.1:${port}/api/chat`,
      LOCAL_OLLAMA_TOOL_PROTOCOL: 'json',
      AUTOHACK_AUTO_SOURCE_PREFETCH: 'false',
      LOCAL_CONTROLLER_OWNED_ACTIONS: 'true',
      LOCAL_CONTROLLER_FULL_SOURCE_INDEX: 'true',
    }, async () => {
      const out = await runLocalAudit('Inspect Admin.sol', log1, 30000, root, 'mock', undefined, {
        productionWorkflow: true,
        controllerIndex: true,
        dynamicAllowance: true,
        finalSchema: {
          type: 'object',
          properties: {
            findings: { type: 'array', items: { type: 'object', properties: { caseId: { type: 'string' } } } },
            outcome: { type: 'string', enum: ['inspected', 'no_testable_candidate'] },
            reason: { type: 'string' },
          },
          required: ['findings'],
        },
        staticLeads: [{ path: solPath, line: 2, rule: 'paragraph-interpolation-python', message: 'Inspect escaping before testing markup handling.', severity: 'INFO', engine: 'semgrep' }],
        verifyPython: async () => JSON.stringify({ status: 'observation_only', behavior_observed: false, caseId: 'c'.repeat(64) }),
        validateFinal: async (answer) => {
          try {
            const parsed = JSON.parse(answer);
            return Array.isArray(parsed.findings) && parsed.outcome === 'no_testable_candidate' ? null : 'Return valid findings JSON';
          } catch {
            return 'Your final answer was not valid JSON (SyntaxError). Return only valid findings JSON.';
          }
        },
        maxTurns: 20,
        numCtx: 8192,
        numPredict: 256,
        initialSourcePaths: [solPath],
      });
      assert.equal(JSON.parse(out).outcome, 'no_testable_candidate');
    });
    assert.equal(reviewCalls, 2, `Expected strictResult recovery in 2 REVIEW turns, got ${reviewCalls}`);
    assert.ok(sawStrictResult, 'Second REVIEW turn must enforce typed result schema (strictResult)');
    assert.equal(strictMaxItems, 0, 'With 0 behavior_observed probes, strictResult must set findings.maxItems = 0');
    const log1Text = await readFile(log1, 'utf8');
    assert.ok(log1Text.includes('[FINAL_SCHEMA_ACTIVATED]'));
    assert.ok(log1Text.includes('[REPORT_COMPLETE]'));
    assert.ok(log1Text.includes('"outcome":"observation_only"'), 'observation_only must map cleanly instead of incomplete');
    assert.ok(!log1Text.includes('"outcome":"incomplete"'), 'observation_only probe must not emit outcome=incomplete');
    assert.ok(sawStaticLeadsInReview, 'REVIEW turn must receive bounded controller static scanner leads');

    // 6b. Stubborn model repeating identical unparseable answer recovers cleanly at 3 turns instead of 24.
    let stubbornCalls = 0;
    const stubbornServer = createServer(async (req, res) => {
      for await (const _ of req) {}
      stubbornCalls++;
      res.end(JSON.stringify({
        message: { role: 'assistant', content: JSON.stringify({ action: 'final', path: '', query: '', answer: 'repeated non-json final output' }) },
      }));
    });
    await new Promise<void>(r => stubbornServer.listen(0, '127.0.0.1', r));
    const stubbornPort = (stubbornServer.address() as any).port;
    const log2 = join(root, 'stubborn-recovery.log');
    try {
      await withEnv({
        AUTOHACK_OLLAMA_URL: `http://127.0.0.1:${stubbornPort}/api/chat`,
        LOCAL_OLLAMA_TOOL_PROTOCOL: 'json',
        AUTOHACK_AUTO_SOURCE_PREFETCH: 'false',
        LOCAL_CONTROLLER_OWNED_ACTIONS: 'true',
        LOCAL_CONTROLLER_FULL_SOURCE_INDEX: 'true',
      }, async () => {
        const out = await runLocalAudit('Inspect Admin.sol', log2, 30000, root, 'mock', undefined, {
          productionWorkflow: true,
          controllerIndex: true,
          dynamicAllowance: true,
          verifyPython: async () => JSON.stringify({ status: 'observation_only', behavior_observed: false, caseId: 'd'.repeat(64) }),
          validateFinal: async (answer) => {
            try {
              const parsed = JSON.parse(answer);
              return parsed.outcome === 'no_testable_candidate' ? null : 'Return valid findings JSON';
            } catch {
              return 'Your final answer was not valid JSON (SyntaxError).';
            }
          },
          maxTurns: 20,
          numCtx: 8192,
          numPredict: 256,
          initialSourcePaths: [solPath],
        });
        assert.equal(JSON.parse(out).outcome, 'no_testable_candidate');
      });
      assert.equal(stubbornCalls, 3, `Expected REVIEW loop breaker recovery after 3 identical turns, got ${stubbornCalls}`);
    } finally {
      stubbornServer.closeAllConnections();
      stubbornServer.close();
    }
        assert.deepEqual(
      normalizeNegativeHuntProse('No verified vulnerability found in the provided evidence across inspected contracts.')?.outcome,
      'no_testable_candidate',
    );
    assert.deepEqual(
      normalizeNegativeHuntProse('no_testable_candidate: all entry points require owner privileges')?.outcome,
      'no_testable_candidate',
    );
    assert.equal(normalizeNegativeHuntProse('Not valid JSON findings summary'), null);
console.log('6. REVIEW strictResult recovery & identical-rejection fast recovery PASSED');
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
async function testReviewContextBudgetAndTruncationRetry() {
  // 7. Large pinned prompt (~5.3KB) + 3.2KB EXPERIMENT verify_source exchange +
  //    REVIEW truncation retry (done_reason="length") must NOT overflow
  //    compactAuditContext ("Latest audit exchange exceeds the context budget"),
  //    and REVIEW Turn 1 must immediately constrain strictResult + answer="".
  const root = await mkdtemp(join(tmpdir(), 'lotus-review-budget-'));
  let reviewCalls = 0;
  let firstTurnHadStrictResult = false;
  let firstTurnAnswerEnum: unknown;
  let firstTurnNumPredict: number | undefined;
  const server = createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk;
    const body = JSON.parse(raw);
    reviewCalls++;
    if (reviewCalls === 1) {
      firstTurnHadStrictResult = Boolean(body.format?.properties?.result);
      firstTurnAnswerEnum = body.format?.properties?.answer?.enum;
      firstTurnNumPredict = body.options?.num_predict;
      res.end(JSON.stringify({
        done_reason: 'length',
        eval_count: body.options?.num_predict || 512,
        message: { role: 'assistant', content: '{"action":"final","path":"","query":"","answer":"truncated' },
      }));
      return;
    }
    res.end(JSON.stringify({
      message: {
        role: 'assistant',
        content: JSON.stringify({
          action: 'final',
          path: '',
          query: '',
          answer: '',
          result: {
            findings: [],
            outcome: 'no_testable_candidate',
            reason: 'All 64 experiments completed with zero exploitable behaviors observed.',
          },
        }),
      },
    }));
  });
  try {
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as any).port;
    const pyPath = 'source-1/src/render.py';
    await mkdir(dirname(join(root, pyPath)), { recursive: true });
    await writeFile(join(root, pyPath), 'def render(value):\n    return "<p>" + value + "</p>"\n');
    const logPath = join(root, 'review-budget.log');
    const largePrompt = 'Inspect the repository. ' + 'Context inventory: ' + 'A'.repeat(3600);
    const bigProbeDetail = 'D'.repeat(2600);
    await withEnv({
      AUTOHACK_OLLAMA_URL: `http://127.0.0.1:${port}/api/chat`,
      LOCAL_OLLAMA_TOOL_PROTOCOL: 'json',
      AUTOHACK_AUTO_SOURCE_PREFETCH: 'false',
      LOCAL_CONTROLLER_OWNED_ACTIONS: 'true',
      LOCAL_CONTROLLER_FULL_SOURCE_INDEX: 'true',
    }, async () => {
      const out = await runLocalAudit(largePrompt, logPath, 30000, root, 'mock', undefined, {
        productionWorkflow: true,
        controllerIndex: true,
        dynamicAllowance: true,
        finalSchema: {
          type: 'object',
          additionalProperties: false,
          properties: {
            findings: {
              type: 'array',
              maxItems: 8,
              items: {
                type: 'object',
                properties: {
                  caseId: { type: 'string' },
                  severity: { type: 'string' },
                  ratingReason: { type: 'string' },
                  impact: { type: 'string' },
                  callerFile: { type: 'string' },
                  callerLine: { type: 'integer' },
                  falsification: { type: 'string' },
                },
              },
            },
            outcome: { type: 'string', enum: ['inspected', 'no_testable_candidate'] },
            reason: { type: 'string', minLength: 20, maxLength: 1000 },
          },
          required: ['findings'],
        },
        staticLeads: Array.from({ length: 6 }, (_, i) => ({
          path: pyPath,
          line: 2,
          rule: `lead-rule-${i}`,
          message: 'Advisory static scanner lead detail for review context testing.',
          severity: 'INFO',
          engine: 'semgrep',
        })),
        verifyPython: async () => JSON.stringify({
          status: 'observation_only',
          behavior_observed: false,
          caseId: 'e'.repeat(64),
          detail: bigProbeDetail,
        }),
        validateFinal: async (answer) => {
          const parsed = JSON.parse(answer);
          return Array.isArray(parsed.findings) && parsed.outcome === 'no_testable_candidate' ? null : 'Invalid final';
        },
        maxTurns: 20,
        numCtx: 8192,
        numPredict: 2048,
        initialSourcePaths: [pyPath],
      });
      assert.equal(JSON.parse(out).outcome, 'no_testable_candidate');
    });
    assert.equal(reviewCalls, 2);
    assert.equal(firstTurnHadStrictResult, true, 'REVIEW Turn 1 must immediately enforce strictResult');
    assert.deepEqual(firstTurnAnswerEnum, [''], 'REVIEW Turn 1 must constrain answer to empty string when result is required');
    assert.ok((firstTurnNumPredict ?? 9999) <= 512, `Expected bounded num_predict in zero-observed REVIEW, got ${firstTurnNumPredict}`);
    const logText = await readFile(logPath, 'utf8');
    assert.ok(logText.includes('truncated JSON action; retrying with generation_limit='));
    assert.ok(logText.includes('[REPORT_COMPLETE]'));
    console.log('7. REVIEW context budget + truncation retry survival PASSED');
  } finally {
    server.closeAllConnections();
    server.close();
    await rm(root, { recursive: true, force: true });
  }
}


// Force eviction of historical exchanges while retaining an immutable live task.
function testRequiredControllerTailIsNotEvictable(){
  const history=[{role:'system',content:'System task'},{role:'user',content:'Original task'},
    ...Array.from({length:20},(_,i)=>({role:i%2?'assistant':'user',content:'Historical '+i+' '+ 'X'.repeat(1200)}))];
  const active={role:'user',content:'CURRENT ANALYZE TASK leadId='+ 'a'.repeat(64)};
  const result=compactAuditContextWithRequiredTail(history,4800,[active],0,1000);
  assert.equal(result.requestMessages.at(-1)?.content,active.content);
  assert.ok(result.history.length<history.length,'Historical exchanges must be compacted');
  assert.ok(result.requestMessages.some(msg=>msg.content.includes(active.content)));
  assert.ok(JSON.stringify(result.requestMessages).length<=4800);
  assert.throws(()=>compactAuditContextWithRequiredTail(history,100,[active],0,0),
    /CONTROLLER_REQUIRED_INSTRUCTION_EXCEEDS_CONTEXT_BUDGET/);
  console.log('8a. Required controller instruction survives archive compaction PASSED');
}
testRequiredControllerTailIsNotEvictable();

async function testActiveAnalysisPacketSurvivesCompactionAndRejection() {
  const root=await mkdtemp(join(tmpdir(),'lotus-analysis-handoff-'));
  const path='source-1/contracts/Deposit.sol';
  const source='// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Deposit {\n'+
    '  uint256 public total;\n'+
    '  function deposit(uint256 amount) external { total += amount; }\n'+
    '  function withdraw(uint256 amount) external { require(total >= amount); total -= amount; }\n'+
    '}\n';
  const log=join(root,'analysis.log');
  let analysisRequests=0;
  const received:Array<{leadId:string;sourceEvidence:string;chars:number;budget:number}>=[];
  const server=createServer(async(req,res)=>{
    let raw='';
    for await(const chunk of req)raw+=chunk;
    const body=JSON.parse(raw);
    const active=(body.messages as Array<{content:string}>).at(-1)?.content||'';
    const match=active.match(/Controller-verified identity and bounded source excerpt: (\{.*?\})\. Reply using/);
    if(match){
      const packet=JSON.parse(match[1]);
      analysisRequests++;
      assert.equal(packet.path,path);
      assert.equal(packet.sourceSha256,hash(source));
      assert.match(packet.id,/^[a-f0-9]{64}$/);
      assert.match(packet.sourceCommit,/^[a-f0-9]{40}$/);
      assert.ok(packet.sourceEvidence.includes(packet.sourceSha256));
      assert.ok(packet.sourceExcerpt.includes('function'));
      received.push({leadId:packet.id,sourceEvidence:packet.sourceEvidence,
        chars:JSON.stringify(body.messages).length,
        budget:body.options.num_ctx});
      const answer=analysisRequests===1
        ? {action:'finalize_analysis',path:'',query:'',answer:''}
        : {action:'defer_lead',path:packet.path,query:packet.selector,leadId:packet.id,
            answer:'The source alone does not establish a defensible unauthorized-caller invariant or complete executable fixture.',
            hypothesis:'none'};
      res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify(answer)}}));
      return;
    }
    if(active.includes('All selected lead assessments have dispositions')){
      res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify({
        action:'finalize_analysis',path:'',query:'',answer:''})}}));
      return;
    }
    res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify({
      action:'final',path:'',query:'',answer:'',
      result:{findings:[],outcome:'no_testable_candidate',
        reason:'No supported executable security property was demonstrated.'}
    })}}));
  });
  try{
    await mkdir(dirname(join(root,path)),{recursive:true});
    await writeFile(join(root,path),source);
    execFileSync('git',['init','-q'],{cwd:root});
    execFileSync('git',['add','.'],{cwd:root});
    execFileSync('git',['-c','user.name=Test','-c','user.email=test@example.invalid',
      'commit','-qm','Fixture'],{cwd:root});
    await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
    const port=(server.address() as any).port;
    await withEnv({
      AUTOHACK_OLLAMA_URL:'http://127.0.0.1:'+port+'/api/chat',
      LOCAL_OLLAMA_TOOL_PROTOCOL:'json',
      LOCAL_CONTROLLER_FULL_SOURCE_INDEX:'true',
      LOCAL_CONTROLLER_OWNED_ACTIONS:'true',
      AUTOHACK_AUTO_SOURCE_PREFETCH:'false',
      LOCAL_MODEL_SOLIDITY_ANALYZE:'true',
      LOCAL_ANALYZE_MODEL_TURNS:'4',
    },async()=>{
      await runLocalAudit('Inspect these source contracts. '+'Historical notes: '+'A'.repeat(2400),
        log,30000,root,'mock',undefined,{
          productionWorkflow:true,controllerIndex:true,dynamicAllowance:true,
          maxTurns:30,numCtx:8192,numPredict:512,
          initialSourcePaths:[path],
          staticLeads:[{path,line:5,rule:'source-review',message:'Assess missing caller authority on deposit'}],
          verifyPython:async()=>JSON.stringify({status:'behavior_not_observed',behavior_observed:false}),
          validateFinal:async()=>null,
        });
    });
    const logText=await readFile(log,'utf8');
    assert.ok(analysisRequests>=2,
      'Premature final must be rejected and active packet resent for the next request');
    assert.equal(received[0].leadId,received[1].leadId,
      'Immutable pending lead must survive first rejected action');
    assert.ok(logText.includes('[ANALYSIS_FINALIZATION_REJECTED]'),
      'Stage lock must reject premature analysis finalization');
    assert.ok(logText.includes('[ANALYSIS_LEAD_DEFERRED]'),
      'Controller must accept an evidence-grounded disposition');
    assert.ok(logText.includes('[ANALYSIS_REQUEST_BOUND]'),
      'Controller must certify identity and budget in the actual request');
    assert.ok(received.every(x=>x.chars<x.budget*3),
      'Actual messages must fit 8192-token approximate character reservation');
    console.log('8. ANALYZE packet retained across compaction and rejected final PASSED');
  }finally{
    server.closeAllConnections();server.close();
    await rm(root,{recursive:true,force:true});
  }
}

await testActiveAnalysisPacketSurvivesCompactionAndRejection();

await testReviewStageStrictResultAndLoopRecovery();
await testReviewContextBudgetAndTruncationRetry();
console.log('ALL stage READ repair acceptance tests PASSED');
