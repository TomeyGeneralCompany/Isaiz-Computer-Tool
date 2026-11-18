import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { soliditySequenceSchema } from "../packages/security-solver/src/solidity-sequence";
import { normalizeSolidityPreparationPaths } from "../packages/security-solver/src/source-reproduction";
import {
  controllerGroundedSolidityOptions,
  prioritizeSolidityStagedPlans,
  runLocalAudit,
} from "../packages/security-solver/src/local-ollama-runner";
import { decodeAuditAction } from "../packages/security-solver/src/local-audit-protocol";
import { runEvidenceOnlyReview } from "../packages/security-solver/src/evidence-only-review";
import { rankSolidityStaticTargets } from "../packages/security-solver/src/local-static-leads";

import {reconcileHuntReason,type HuntCoverageLedger} from '../packages/security-solver/src/local-program-flow';

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
// #227 field evidence: 31 guarded negatives, 13 observation-only, 12
// incomplete/failed; 56 selected, no observed positive. A model's reversed
// word-order blanket-negative claim must not change any ledger disposition.
{
 const ledger:HuntCoverageLedger={
   sourceIndexed:91,sourceRead:91,leadsSelected:6,leadsAssessedByModel:0,
   leadsDeferred:0,leadsBlocked:0,experimentsSelected:56,experimentsExecuted:44,
   supportedNegative:31,observationOnly:13,fixtureFailed:12,unsupported:0,
   positiveObserved:0,verifiedFindings:0,unresolved:0,
   sourceCoverage:'complete',analysisCoverage:'partial',experimentCoverage:'partial'
 };
 const actual='The controller has observed behavior_not_observed status for all candidate functions.';
 const checked=reconcileHuntReason(actual,ledger);
 assert.deepEqual(checked.contradictions,['blanket_negative_contradicts_partial_experiment_ledger']);
 assert.match(checked.reason,/31 source-supported negative experiments/);
 assert.match(checked.reason,/13 observation-only/);
 assert.match(checked.reason,/12 failed\/incomplete fixtures/);
 assert.match(checked.reason,/Model analysis partial/i);
 assert.doesNotMatch(checked.reason,/negative status for all candidate functions/i);
 assert.equal(reconcileHuntReason('31 supported negatives and 25 unresolved or inconclusive executions.',ledger).contradictions.length,0);
}


// 1. Validate soliditySequenceSchema eth_balance and deploymentId extensions
{
  const valid = soliditySequenceSchema.safeParse({
    constructorArgs: [],
    preparation: {
      deployments: [{ id: "token", file: "contracts/mocks/ERC20Mock.sol", contract: "ERC20Mock", constructorArgs: [] }],
      operations: [],
      checks: [],
    },
    steps: [
      { operation: "eth_balance", account: "$contract" },
      { operation: "send", deploymentId: "token", function: "mint(address,uint256)", args: ["$contract", "1000"], sender: 0 },
      { operation: "observe", deploymentId: "token", function: "balanceOf(address)", args: ["$contract"], sender: 0 },
      { operation: "send", function: "rescue(address,address,uint256)", args: ["$deployment:token", "$account1", "1000"], sender: 1 },
      { operation: "eth_balance", account: "$account1" },
    ],
  });
  assert.ok(valid.success, "Valid eth_balance + deploymentId sequence should parse");
  const requiredSetup = soliditySequenceSchema.safeParse({
    constructorArgs: [],steps:[
      {operation:"send",function:"initialize()",args:[],sender:0,requiredSetup:true},
      {operation:"observe",function:"owner()",args:[]}
    ]
  });
  assert.ok(requiredSetup.success, "A required successful initializer must be accepted");
  const contradictorySetup = soliditySequenceSchema.safeParse({
    constructorArgs: [],steps:[
      {operation:"send",function:"initialize()",args:[],sender:0,requiredSetup:true,expectRevert:true},
      {operation:"observe",function:"owner()",args:[]}
    ]
  });
  assert.ok(!contradictorySetup.success, "Setup cannot require both success and revert");

  const invalidRef = soliditySequenceSchema.safeParse({
    constructorArgs: [],
    steps: [
      { operation: "send", function: "rescue(address)", args: ["$deployment:missing"], sender: 1 },
    ],
  });
  assert.ok(!invalidRef.success, "Undeclared $deployment: reference must be rejected");
}

// Regression: workspace source-1/... paths must become /repo-relative sources
// without making any neighboring repository or host path accessible.
{
  const tmp=await mkdtemp(join(tmpdir(),"lotus-fixture-path-"));
  try {
    const workspace=join(tmp,"workspace");
    const repository=join(workspace,"source-1");
    await mkdir(join(repository,"contracts"),{recursive:true});
    await writeFile(join(repository,"contracts","MockToken.sol"),"contract MockToken {}");
    await mkdir(join(workspace,"source-2"),{recursive:true});
    await writeFile(join(workspace,"source-2","Secret.sol"),"contract Secret {}");
    const sequence=soliditySequenceSchema.parse({
      constructorArgs:[],
      preparation:{deployments:[{
        id:"token",file:"source-1/contracts/MockToken.sol",
        contract:"MockToken",constructorArgs:[]
      }],operations:[],checks:[]},
      steps:[{operation:"send",function:"deposit()",args:[]},
        {operation:"observe",function:"owner()",args:[]}]
    });
    const normalized=await normalizeSolidityPreparationPaths(workspace,repository,sequence);
    assert.equal(normalized.preparation?.deployments[0].file,"contracts/MockToken.sol");
    assert.equal(sequence.preparation?.deployments[0].file,"source-1/contracts/MockToken.sol",
      "Preflight must not mutate the controller's original evidence");
    await assert.rejects(normalizeSolidityPreparationPaths(workspace,repository,{
      ...sequence,preparation:{...sequence.preparation!,
        deployments:[{...sequence.preparation!.deployments[0],file:"source-2/Secret.sol"}]}
    }),/outside selected Solidity repository/);
  } finally {await rm(tmp,{recursive:true,force:true});}
}

// 2. Test DeFi planner patterns & null commit compatibility
{
  const reinitSource = `pragma solidity 0.8.4;
contract VaultInit {
  address public owner;
  address public treasury;
  uint256 public fee;
  function initialize(address _owner, address _treasury, uint256 _fee) external {
    owner = _owner; treasury = _treasury; fee = _fee;
  }
}`;
  const mockSource = `pragma solidity 0.8.4;
contract ERC20Mock {
  mapping(address => uint256) public balanceOf;
  uint256 public totalSupply;
  function mint(address to, uint256 amt) public {
    totalSupply += amt; balanceOf[to] += amt;
  }
}`;
  const minterSource = `pragma solidity 0.8.4;
contract RealMinter {
  mapping(address => uint256) public balanceOf;
  uint256 public totalSupply;
  function mint(address to, uint256 amt) external {
    totalSupply += amt; balanceOf[to] += amt;
  }
  function deposit(uint256 amt) external {
    balanceOf[msg.sender] += amt;
  }
}`;
  const snap = [
    { path: "source-1/contracts/VaultInit.sol", content: reinitSource, sha256: sha(reinitSource) },
    { path: "source-1/contracts/mocks/ERC20Mock.sol", content: mockSource, sha256: sha(mockSource) },
    { path: "source-1/contracts/RealMinter.sol", content: minterSource, sha256: sha(minterSource) },
  ];
  const initOpts = controllerGroundedSolidityOptions(
    "source-1/contracts/VaultInit.sol",
    reinitSource,
    [
      { selector: "VaultInit.owner", operation: "call", inputs: [] },
      { selector: "VaultInit.initialize", operation: "send", inputs: ["address", "address", "uint256"] },
    ],
    snap,
    "a".repeat(40),
  );
  assert.ok(initOpts.some(o => o.selector === "VaultInit.initialize"), "Multi-arg initialize probe should be planned");
  assert.equal(
    controllerGroundedSolidityOptions("source-1/contracts/VaultInit.sol", reinitSource, [
      { selector: "VaultInit.owner", operation: "call", inputs: [] },
      { selector: "VaultInit.initialize", operation: "send", inputs: ["address", "address", "uint256"] },
    ], snap, null).length,
    0,
    "Null commit must disable new scenario construction"
  );

  const mockOpts = controllerGroundedSolidityOptions(
    "source-1/contracts/mocks/ERC20Mock.sol",
    mockSource,
    [{ selector: "ERC20Mock.mint", operation: "send", inputs: ["address", "uint256"] }],
    snap,
    "a".repeat(40),
  );
  assert.equal(mockOpts.length, 0, "Mock file unguarded minting must never be queued");

  const minterOpts = controllerGroundedSolidityOptions(
    "source-1/contracts/RealMinter.sol",
    minterSource,
    [
      { selector: "RealMinter.balanceOf", operation: "call", inputs: ["address"] },
      { selector: "RealMinter.totalSupply", operation: "call", inputs: [] },
      { selector: "RealMinter.mint", operation: "send", inputs: ["address", "uint256"] },
      { selector: "RealMinter.deposit", operation: "send", inputs: ["uint256"] },
    ],
    snap,
    "a".repeat(40),
  );
  assert.ok(minterOpts.some(o => o.selector === "RealMinter.mint"), "Non-mock unguarded mint must be queued");
  assert.ok(minterOpts.some(o => o.selector === "RealMinter.deposit"), "Core DeFi deposit entrypoint must be queued");
  const selectedDeposit = minterOpts.find(o => o.selector === "RealMinter.deposit")!;
  assert.match(selectedDeposit.probe.hypothesis, /Unauthorized caller/,
    "A source-backed unauthorized-mint hypothesis must outrank an exploratory fallback");

  // A plain entrypoint with no grounded security assertion must remain exploratory.
  const plainSource = `pragma solidity 0.8.4;
contract PlainVault {
  function deposit(uint256 amount) external {}
}`;
  const plainPath = "source-1/contracts/PlainVault.sol";
  const plainOpts = controllerGroundedSolidityOptions(
    plainPath,
    plainSource,
    [{ selector: "PlainVault.deposit", operation: "send", inputs: ["uint256"] }],
    [{ path: plainPath, content: plainSource, sha256: sha(plainSource) }],
    "a".repeat(40),
  );
  const exploratoryDeposit = plainOpts.find(o => o.selector === "PlainVault.deposit");
  assert.ok(exploratoryDeposit, "Plain deposit must be eligible for bounded exploration");
  assert.match(exploratoryDeposit.probe.hypothesis, /Exploratory core DeFi entrypoint/);
  assert.match(exploratoryDeposit.probe.hypothesis, /no verified accounting or authorization invariant/);
  assert.ok(exploratoryDeposit.probe.sequence.steps.some(step => step.operation === "send"),
    "Exploratory probe retains actual state-changing transaction execution");
}

// 3. Queue prioritization & Tier-4 setter cap (>16 items, max 3 Tier-4 per path)
{
  const items = [
    ...Array.from({ length: 16 }, (_, i) => ({
      id: `setter-${i}`,
      plan: { path: "source-1/contracts/Config.sol", query: `Config.set${i}`, hypothesis: `source-proven owner-gated state transition ${i}` },
    })),
    {
      id: "defi-deposit",
      plan: { path: "source-1/contracts/Vault.sol", query: "Vault.deposit", hypothesis: "core DeFi entrypoint state check" },
    },
    {
      id: "eth-extract",
      plan: { path: "source-1/contracts/Vault.sol", query: "Vault.sweep", hypothesis: "unauthorized ETH extraction guard" },
    },
  ];
  const leads = [{ path: "source-1/contracts/Vault.sol", line: 10, rule: "solidity-eth-transfer", message: "eth", severity: "WARNING" }];
  const prioritized = prioritizeSolidityStagedPlans(items, leads);
  assert.equal(prioritized.selected[0].id, "eth-extract", "Tier 1 extraction probe must be first");
  assert.equal(prioritized.selected[1].id, "defi-deposit", "Tier 2 core DeFi probe must precede setters");
  assert.equal(prioritized.droppedTier4Count, 13, "Tier-4 setters per file should be capped to 3 when >16 total");
  assert.equal(prioritized.selected.length, 5);
}

// 4. Protocol decodeAuditAction in ANALYZE stage
{
  const decoded = decodeAuditAction(
    JSON.stringify({
      action: "discover_experiment",
      file: "source-1/contracts/Vault.sol",
      function: "Vault.deposit",
      kind: "solidity_sequence",
      sequence: { constructorArgs: [], steps: [{ operation: "send", function: "deposit(uint256)", args: ["10"], sender: 1 }] },
    }),
    true,
    true,
  );
  assert.equal(decoded.path, "source-1/contracts/Vault.sol");
  assert.equal(decoded.query, "Vault.deposit");
  assert.equal(decoded.answer, "solidity_sequence");
  assert.throws(() => decodeAuditAction(JSON.stringify({ action: "discover_experiment", path: "", query: "", answer: "" }), true, false));
}

// 5. rankSolidityStaticTargets with limit 24
{
  const targets = rankSolidityStaticTargets([
    "source-1/contracts/mocks/Fake.sol",
    "source-1/vendor/Lib.sol",
    "source-1/contracts/DInterest.sol",
    "source-1/contracts/MPHMinter.sol",
  ], "source-1", 24);
  assert.deepEqual(targets, ["contracts/DInterest.sol", "contracts/MPHMinter.sol"]);
}

// 6. keep_alive in runEvidenceOnlyReview + End-to-End runLocalAudit ANALYZE -> EXPERIMENT -> REVIEW
{
  const tmp = await mkdtemp(join(tmpdir(), "autohack-analyze-review-"));
  const prevUrl = process.env.AUTOHACK_OLLAMA_URL;
  const prevKeepAlive = process.env.LOCAL_OLLAMA_KEEP_ALIVE;
  const seenKeepAlives: string[] = [];
  let sawAnalyzeActionPrompt = false;
  let sawMultiContractSummary = false;
  let reviewCalls = 0;

  const finalSchema = {
    type: "object",
    additionalProperties: false,
    properties: {
      findings: { type: "array", items: { type: "object" } },
      outcome: { type: "string" },
      reason: { type: "string" },
    },
    required: ["findings", "outcome", "reason"],
  };

  const server = createServer(async (req, res) => {
    let body = "";
    for await (const c of req) body += c.toString();
    const payload = JSON.parse(body);
    if (typeof payload.keep_alive === "string") seenKeepAlives.push(payload.keep_alive);
    res.setHeader("content-type", "application/json");
    const lastContent = String(payload.messages?.at(-1)?.content || "");
    const enumActions: string[] = payload.format?.properties?.action?.enum || [];

    // Evidence-only review check
    if (enumActions.length === 0 && payload.format?.properties?.verdict) {
      res.end(JSON.stringify({ message: { role: "assistant", content: JSON.stringify({ verdict: "approve", recommendation: "dont_submit" }) } }));
      return;
    }

    if (enumActions.includes("discover_experiment")) {
      sawAnalyzeActionPrompt = true;
      res.end(JSON.stringify({
        message: {
          role: "assistant",
          content: JSON.stringify({
            action: "discover_experiment",
            path: "source-1/contracts/VaultA.sol",
            query: "VaultA.customSwap",
            answer: "solidity_sequence",
            hypothesis: "Test custom model-proposed DeFi swap hypothesis.",
            sequence: {
              constructorArgs: [],
              steps: [
                { operation: "observe", function: "owner()", args: [] },
                { operation: "send", function: "customSwap(uint256)", args: ["10"], sender: 1 },
              ],
            },
          }),
        },
      }));
      return;
    }

    if (enumActions.length === 1 && enumActions[0] === "final") {
      reviewCalls++;
      if (payload.messages.some((m: any) => String(m.content || "").includes("Controller multi-contract experiment summary"))) {
        sawMultiContractSummary = true;
      }
      res.end(JSON.stringify({
        message: {
          role: "assistant",
          content: JSON.stringify({
            action: "final",
            path: "",
            query: "",
            answer: "",
            result: {
              findings: [],
              outcome: "no_testable_candidate",
              reason: "All executed probes were negative or observation_only across VaultA and VaultB.",
            },
          }),
        },
      }));
      return;
    }

    res.end(JSON.stringify({
      message: {
        role: "assistant",
        content: JSON.stringify({
          action: "finalize_analysis",
          path: "",
          query: "",
          answer: "",
        }),
      },
    }));
  });

  try {
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr !== "string");
    process.env.AUTOHACK_OLLAMA_URL = `http://127.0.0.1:${addr.port}/api/chat`;
    process.env.LOCAL_OLLAMA_KEEP_ALIVE = "45m";

    const reviewLog = join(tmp, "review.log");
    await writeFile(reviewLog, "");
    await runEvidenceOnlyReview({
      prompt: "Review",
      schema: { type: "object", properties: { verdict: { type: "string" } }, required: ["verdict"] },
      model: "mock",
      signal: new AbortController().signal,
      logFile: reviewLog,
      numCtx: 2048,
      numPredict: 128,
      validate: () => null,
    });
    assert.equal(seenKeepAlives[0], "45m", "runEvidenceOnlyReview must respect LOCAL_OLLAMA_KEEP_ALIVE");

    const repoDir = join(tmp, "source-1");
    await mkdir(join(repoDir, "contracts"), { recursive: true });
    await writeFile(
      join(repoDir, "contracts", "VaultA.sol"),
      "pragma solidity 0.8.4;\ncontract VaultA {\n  address public owner;\n  constructor(){ owner = msg.sender; }\n  function deposit(uint256 a) external {}\n  function withdraw(uint256 a) external {}\n  function customSwap(uint256 a) external {}\n}\n",
    );
    await writeFile(
      join(repoDir, "contracts", "VaultB.sol"),
      "pragma solidity 0.8.4;\ncontract VaultB {\n  address public owner;\n  constructor(){ owner = msg.sender; }\n  function stake(uint256 a) external {}\n}\n",
    );
    execFileSync("git", ["init", "-q", repoDir]);
    execFileSync("git", ["-C", repoDir, "config", "user.email", "ci@example.com"]);
    execFileSync("git", ["-C", repoDir, "config", "user.name", "CI"]);
    execFileSync("git", ["-C", repoDir, "add", "."]);
    execFileSync("git", ["-C", repoDir, "commit", "-q", "-m", "init"]);

    process.env.LOCAL_ANALYZE_MODEL_TURNS = "1";
    const auditLog = join(tmp, "audit.log");
    const answer = await runLocalAudit(
      "Audit DeFi contracts",
      auditLog,
      20000,
      tmp,
      "mock",
      "Offline audit",
      {
        maxTurns: 30,
        numCtx: 16384,
        numPredict: 512,
        numThreads: 4,
        productionWorkflow: true,
        controllerIndex: true,
        finalSchema,
        initialSourcePaths: ["source-1/contracts/VaultA.sol", "source-1/contracts/VaultB.sol"],
        staticLeads: [
          { path: "source-1/contracts/VaultA.sol", line: 4, rule: "solidity-eth-transfer", message: "Check", severity: "WARNING" },
        ],
        verifyPython: async (_path, fnName) =>
          JSON.stringify({
            status: "observation_only",
            behavior_observed: false,
            kind: "solidity_sequence",
            observations: { function: fnName, steps: [{ operation: "send", reverted: false, passed: true }] },
            limitation: "Observation only.",
          }),
        validateFinal: raw => {
          const parsed = JSON.parse(raw);
          return Array.isArray(parsed.findings) && parsed.findings.length === 0 ? null : "Expected findings=[]";
        },
      },
    );

    const parsedAnswer = JSON.parse(answer);
    assert.equal(parsedAnswer.findings.length, 0);
    assert.ok(sawAnalyzeActionPrompt, "Bounded ANALYZE window must invoke model with discover_experiment");
    assert.ok(reviewCalls >= 1 && sawMultiContractSummary, "REVIEW stage must receive multi-contract anti-bias summary");
    const transcript = await readFile(auditLog, "utf8");
    assert.match(transcript, /\[ANALYSIS_MODEL_WINDOW_STARTED\]/);
    assert.match(transcript, /\[ANALYSIS_MODEL_EXPERIMENT_ADDED\]/);
    assert.match(transcript, /\[MODEL_ANALYZE_SCENARIO_DISPATCHED\]/);
    assert.ok(seenKeepAlives.every(k => k === "45m"));
  } finally {
    server.close();
    if (prevUrl === undefined) delete process.env.AUTOHACK_OLLAMA_URL;
    else process.env.AUTOHACK_OLLAMA_URL = prevUrl;
    if (prevKeepAlive === undefined) delete process.env.LOCAL_OLLAMA_KEEP_ALIVE;
    else process.env.LOCAL_OLLAMA_KEEP_ALIVE = prevKeepAlive;
    delete process.env.LOCAL_ANALYZE_MODEL_TURNS;
    await rm(tmp, { recursive: true, force: true });
  }
}

console.log("DeFi probes, security classification, ANALYZE window & REVIEW anti-bias tests PASSED");
