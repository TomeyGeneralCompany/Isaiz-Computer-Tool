/** Real owned Git source + model actions + sandbox + report + evidence replay. */
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {execFileSync} from "node:child_process";
import {mkdtemp,writeFile,readFile,mkdir,rm,chmod} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";

// Exercise compatible candidate ranking during the existing workflow acceptance suite.
await import("./test-source-candidate-selection");

// Normalize formatting without allowing guessed targets to bypass validation.
const {decodeAuditAction}=await import("../packages/security-solver/src/local-audit-protocol");
const {javaProbeSelectorCompatible}=await import("../packages/security-solver/src/probe-target-validation");
const javaProbeFixtureDir=await mkdtemp(join(tmpdir(),"autohack-java-probe-intent-"));
try {
  const source=join(javaProbeFixtureDir,"ContractState.java");
  await writeFile(source,"public class ContractState { public long getTotalTronPowerWeight(){return 1L;} public static String normalize(String input){return input.trim();} }");
  assert.equal(await javaProbeSelectorCompatible(source,"ContractState.getTotalTronPowerWeight"),false,"unsupported getter must not reach verifier");
  assert.equal(await javaProbeSelectorCompatible(source,"ContractState.normalize"),true,"valid one-input text method should reach verifier");

  const extended=join(javaProbeFixtureDir,"Extended.java");
  await writeFile(extended,`public class Extended {
    public Extended() {}
    public static byte[] bytes(byte[] value) { return value; }
    public static CharSequence buffer(ByteBuffer value) { return value.toString(); }
    public StringBuilder format(StringBuilder value) { return value; }
    public Object path(Path value) { return value.toString(); }
    public URI uri(URI value) { return value; }
    public long noArg() { return 0; }
    public int number(String value) { return 1; }
    private String hidden(String value) { return value; }
  }`);
  for(const name of ["bytes","buffer","format","path","uri"])
    assert.equal(await javaProbeSelectorCompatible(extended,"Extended."+name),true,"supported verifier type: "+name);
  for(const name of ["noArg","number","hidden"])
    assert.equal(await javaProbeSelectorCompatible(extended,"Extended."+name),false,"unsupported verifier signature: "+name);
  const nonConstructible=join(javaProbeFixtureDir,"NonConstructible.java");
  await writeFile(nonConstructible,"public class NonConstructible { private NonConstructible(){} public String method(String value){return value;} public static String staticMethod(String value){return value;} }");
  assert.equal(await javaProbeSelectorCompatible(nonConstructible,"NonConstructible.method"),false);
  assert.equal(await javaProbeSelectorCompatible(nonConstructible,"NonConstructible.staticMethod"),true);

} finally { await rm(javaProbeFixtureDir,{recursive:true,force:true}); }

const corrected=decodeAuditAction(JSON.stringify({action:"plan_probe",file:"source-1/Fixture.java",method:"Fixture.normalize",kind:"html_reflection",hypothesis:"Check whether input is reflected and whether output is safely encoded."}),true);
assert.equal(corrected.path,"source-1/Fixture.java");
assert.equal(corrected.query,"Fixture.normalize");
assert.equal(corrected.answer,"html_reflection");
const incomplete=decodeAuditAction(JSON.stringify({action:"plan_probe",file:"source-1/Fixture.java",method:"Fixture.normalize",kind:"html_reflection"}),true);
assert.equal(incomplete.hypothesis,"","missing hypothesis must remain visible to workflow validation");
assert.throws(()=>decodeAuditAction(JSON.stringify({action:"plan_probe",file:"source-1/Fixture.java",method:"Fixture.normalize",kind:"html_reflection",shell:"unsafe"}),true));
const intent=decodeAuditAction(JSON.stringify({action:"probe_intent",file:"source-1/Fixture.java",kind:"html_reflection",hypothesis:"Check whether input remains unescaped in HTML output."}),true);
assert.equal(intent.action,"probe_intent");
assert.equal(intent.path,"source-1/Fixture.java");
assert.equal(intent.answer,"html_reflection");


const {fixtureArguments}=await import("../packages/security-solver/src/solidity-probe-inputs");
assert.deepEqual(fixtureArguments(["uint256","address","bool","string","bytes4"]),["7","$account1",true,"TOMEY_LOCAL_PROBE","0x41414141"]);
assert.deepEqual(fixtureArguments(["uint256[2]"]),[["7","7"]]);
assert.equal(fixtureArguments(["CustomContract"]),null);
const {soliditySequenceSchema}=await import("../packages/security-solver/src/solidity-sequence");
const observational=soliditySequenceSchema.parse({constructorArgs:[],steps:[
  {operation:"observe",function:"value()",args:[]},
  {operation:"send",function:"increment()",args:[]},
  {operation:"observe",function:"value()",args:[]}
]});
assert.equal(observational.steps.length,3);

const {SoliditySourceIndex}=await import("../packages/security-solver/src/solidity-source-index");
const solidityProbeDir=await mkdtemp(join(tmpdir(),"autohack-solidity-intent-"));
try {
  const contract=join(solidityProbeDir,"State.sol");
  await writeFile(contract,"pragma solidity ^0.8.20; contract State { uint256 private counter; function increment(uint256 value) public { counter += value; } function get() public view returns (uint256) { return counter; } }");
  const index=new SoliditySourceIndex(solidityProbeDir);
  const menu=await index.probeMenu(contract);
  assert.ok(menu.some(item=>item.selector==="State.increment" && item.operation==="send" && item.inputs[0]==="uint256"));
  assert.ok(menu.some(item=>item.selector==="State.get" && item.operation==="call" && item.inputs.length===0));
} finally { await rm(solidityProbeDir,{recursive:true,force:true}); }

// Shared controller choice menu must cover Python, JS, and Java source.
const {probeChoices}=await import("../packages/security-solver/src/probe-target-validation");
const choiceDir=await mkdtemp(join(tmpdir(),"autohack-probe-choice-"));
try {
  const py=join(choiceDir,"sample.py");
  await writeFile(py,"def format_text(value):\n    return '<p>'+value+'</p>'\n");
  const js=join(choiceDir,"sample.js");
  await writeFile(js,"export function formatText(value) { return value; }\n");
  const java=join(choiceDir,"Sample.java");
  await writeFile(java,"public class Sample { public static String formatText(String value) { return value; } }");
  assert.ok((await probeChoices(py,"html_reflection")).some(candidate=>candidate.selector==="format_text"));
  assert.ok((await probeChoices(js,"html_reflection")).some(candidate=>candidate.selector==="formatText"));
  assert.ok((await probeChoices(java,"html_reflection")).some(candidate=>candidate.selector==="Sample.formatText"));
  assert.deepEqual(await probeChoices(js,"solidity_sequence"),[]);
} finally { await rm(choiceDir,{recursive:true,force:true}); }
const revisedRunner=await readFile(new URL("../packages/security-solver/src/local-ollama-runner.ts",import.meta.url),"utf8");
assert.ok(revisedRunner.includes("[PROBE_INTENT_MENU]"));
assert.ok(revisedRunner.includes("Controller Solidity probe guidance:"));
assert.ok(revisedRunner.includes("[PROBE_INTENT_EXECUTE]"),"controller should perform accepted probe without a second model turn");

// Recovery regex regression: the source must use single-escaped regex tokens.
const recoveryRegexSource = await readFile(new URL("../packages/security-solver/src/local-ollama-runner.ts", import.meta.url), "utf8");
assert.ok(recoveryRegexSource.includes(String.raw`/\b([A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*)\b/`), "recovery must match real function selectors");
assert.ok(recoveryRegexSource.includes(String.raw`/\.(?:java|py|js|mjs|cjs|sol)$/`), "recovery must match supported file extensions");
assert.equal("ERC1155Upgradeable.sol".match(/\.(?:java|py|js|mjs|cjs|sol)$/)?.[0], ".sol");
assert.equal("Vault.deposit".match(/\b([A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*)\b/)?.[1], "Vault.deposit");


// Completed Solidity pagination must hand model exact indexed declarations rather
// than leave it inventing Contract.function targets or repeating final actions.
assert.ok(recoveryRegexSource.includes("page.nextOffset===null"),"guide only after last page");
assert.ok(recoveryRegexSource.includes("solidityIndex.outline(full,0,1200)"),"use real indexed declarations");
assert.ok(recoveryRegexSource.includes("[SOLIDITY_DECLARATIONS_GUIDED]"),"log successful handoff");
assert.ok(recoveryRegexSource.includes("Choose only a supported, declared probe target"),"retain probe eligibility gate");

// Solidity source-reading must lead to declaration discovery before repeated premature finals.
const workflowGuideText=await readFile(new URL("../packages/security-solver/src/investigation-workflow.ts",import.meta.url),"utf8");
assert.ok(workflowGuideText.includes("return {action:['outline_solidity'],path:[this.latestSolidityPath]}"),"paginate-to-outline guidance must be present");
assert.ok(workflowGuideText.includes("this.attemptedOutlines.add(this.latestSolidityPath)"),"parse failures must not trap outline retries");
const root=await mkdtemp(join(tmpdir(),"tomey-workflow-"));
const originalPath=process.env.PATH;
process.env.PROJECT_ROOT=root;
process.env.GITHUB_TOKEN="owned-fixture";
process.env.LOCAL_OLLAMA_MODEL="mock";
process.env.LOCAL_OLLAMA_TOOL_PROTOCOL="json";
// This scripted fixture expects to drive the first read itself; the separate
// seeded-source fixture exercises production's automatic first read.
process.env.AUTOHACK_AUTO_SOURCE_PREFETCH="false";
process.env.LOCAL_HUNT_NUM_PREDICT="4096";
const workflowText=await readFile(join(process.cwd(),"packages/security-solver/src/investigation-workflow.ts"),"utf8");
assert.ok(workflowText.includes("Invalid Solidity probe target"),"placeholder Solidity method targets must be rejected before verification");

const {InvestigationWorkflow}=await import("../packages/security-solver/src/investigation-workflow");
const outlineWorkflow=new InvestigationWorkflow();
outlineWorkflow.read("source-1/Fixture.sol");
for(let i=0;i<6;i++)outlineWorkflow.observe({action:"read_file",path:"source-1/Fixture.sol",query:"",answer:"",offset:i*10} as any,
  JSON.stringify({start:i*10,end:(i+1)*10,nextOffset:i===5?null:(i+1)*10}));
assert.deepEqual(await outlineWorkflow.constraints(),{action:["outline_solidity"],path:["source-1/Fixture.sol"]},
  "six Solidity source pages should request a declaration outline");
assert.notDeepEqual(await outlineWorkflow.constraints(),{action:["outline_solidity"],path:["source-1/Fixture.sol"]},
  "the same file must not force an endless outline loop");
const evidenceWorkflow=new InvestigationWorkflow();
for(let i=0;i<6;i++)evidenceWorkflow.observe({action:"read_file",path:"source-1/Example.java",query:"",answer:"",offset:i*10} as any,
  JSON.stringify({start:i*10,end:(i+1)*10,nextOffset:i===5?null:(i+1)*10}));
evidenceWorkflow.finalRejected("Read the tested source file and the claimed caller file before reporting.");
assert.ok((await evidenceWorkflow.constraints()).action.includes("read_file"),
  "missing caller evidence must reopen source reads after hypothesis stage");
const mixedWorkflow=new InvestigationWorkflow();
mixedWorkflow.read("source-1/Fixture.sol");
mixedWorkflow.observe({action:"read_file",path:"source-1/Fixture.sol",query:"",answer:"",offset:0} as any,
  JSON.stringify({start:0,end:10,nextOffset:null}));
mixedWorkflow.read("source-1/Other.java");
for(let i=0;i<5;i++)mixedWorkflow.observe({action:"read_file",path:"source-1/Other.java",query:"",answer:"",offset:i*10} as any,
  JSON.stringify({start:i*10,end:(i+1)*10,nextOffset:i===4?null:(i+1)*10}));
assert.notDeepEqual(await mixedWorkflow.constraints(),{action:["outline_solidity"],path:["source-1/Fixture.sol"]},
  "later Java reads must not trigger an obsolete Solidity outline");
const {declaredProbeTarget,sourceDeclarationHints}=await import("../packages/security-solver/src/probe-target-validation");
const probeFixtures=join(root,"probe-declarations");await mkdir(probeFixtures);
await writeFile(join(probeFixtures,"Target.java"),"public class Target { public static String actual(String input) { return input; } }");
await writeFile(join(probeFixtures,"target.py"),"def actual(value):\\n    return value\\n".replaceAll("\\\\n","\\n"));
await writeFile(join(probeFixtures,"target.js"),"exports.actual = function(value) { return value; };");
for(const [file,actual,missing] of [["Target.java","Target.actual","Target.function"],["target.py","actual","function"],["target.js","actual","function"]]) {
  assert.equal(await declaredProbeTarget(join(probeFixtures,file),actual),true,"declared probe name in "+file);
  assert.equal(await declaredProbeTarget(join(probeFixtures,file),missing),false,"invented probe name in "+file);
}
assert.deepEqual(await sourceDeclarationHints(join(probeFixtures,"Target.java")),["Target.actual"],"Java hints must use real class methods");
const {supportedJavaProbeHints}=await import("../packages/security-solver/src/probe-target-validation");
await writeFile(join(probeFixtures,"Signatures.java"),
  "public class Signatures { public long getTotalTronPowerWeight() { return 1L; } public static String normalize(String input) { return input.trim(); } }");
assert.deepEqual(await supportedJavaProbeHints(join(probeFixtures,"Signatures.java")),
  ["Signatures.normalize"],"Java probe handoff must exclude incompatible zero-argument methods");

assert.deepEqual(await sourceDeclarationHints(join(probeFixtures,"target.py")),["actual"],"Python hints must use declared functions");
assert.deepEqual(await sourceDeclarationHints(join(probeFixtures,"target.js")),[],"JS hint extraction must not invent methods for unsupported exports syntax");
await writeFile(join(probeFixtures,"modern.js"),"export function actual(value) { return value; }");
assert.deepEqual(await sourceDeclarationHints(join(probeFixtures,"modern.js")),["actual"],"JS exported function hints");
assert.ok(recoveryRegexSource.includes("sourceDeclarationHints(target)"),"rejected probes must expose grounded source declarations");
const controllerText=await readFile(join(process.cwd(),"packages/security-solver/src/local-ollama-runner.ts"),"utf8");
assert.ok(controllerText.includes("[CONTEXT_RECOVERY]"),"repeated completed source pages must recover rather than end a production hunt");
assert.ok(controllerText.includes("maxItems:0"),"without recorded case IDs, typed final schema must prohibit invented findings");
assert.ok(controllerText.includes("[PROBE_RECOVERY_REQUIRED]"),"an invented case with a declared compatible candidate must require probe planning");
assert.ok(controllerText.includes("[JAVA_PROBE_ELIGIBLE_HINTS]"),"invalid Java probes should yield compatible signature hints");
assert.ok(controllerText.includes("[REJECTED_FINAL_PROBE_HANDOFF]"),"required-test final rejections must guide a declared probe");
assert.ok(workflowText.includes("this.nextOffsets.values()].some(offset=>offset!==null)"),'hypothesis-stage source navigation must retain unfinished page access');

const incompleteWorkflow=new InvestigationWorkflow();
incompleteWorkflow.read('source-1/Incomplete.java');
incompleteWorkflow.observe({action:'read_file',path:'source-1/Incomplete.java',query:'',answer:'',offset:0} as any,
  JSON.stringify({start:0,end:4000,nextOffset:4000}));
for(let i=0;i<6;i++)incompleteWorkflow.observe({action:'list_files',path:'.',query:'',answer:'',offset:0} as any,
  JSON.stringify({files:[]}));
const incompleteConstraints=await incompleteWorkflow.constraints();
assert.ok(incompleteConstraints.action.includes('read_file'),
  'hypothesis stage must retain reading access to incomplete source');
assert.ok(incompleteConstraints.action.includes('plan_probe'),
  'hypothesis stage must preserve probe planning');
assert.ok(controllerText.includes("[INVALID_PROBE_PATH_RECOVERY]"),"nonexistent source paths in probe plans must be recovered without forced invalid reads");
assert.ok(controllerText.includes("if(exists)workflow!.requireSource(action.path)"),"only existing source paths may become required reads");
assert.ok(controllerText.includes("workflow!.snapshot().readPaths.slice(-8)"),"source-path recovery must suggest exactly inspected, grounded paths");
assert.ok(controllerText.includes("rejectedRequiredProbeFinals>=2"),"ordinary single premature final must not force a probe");
assert.ok(controllerText.includes(String.raw`/\btest\b.*\bbefore\b.*\bclassif/i`),"required-test matcher must use real word boundaries");
assert.ok(!controllerText.includes(String.raw`/\\btest\\b`),"double-escaped regex must not disable recovery");
const requiredTestWorkflow=new InvestigationWorkflow();
requiredTestWorkflow.read("owned/render.py");
assert.ok((await requiredTestWorkflow.constraints()).action.includes("final"),"ordinary final remains available");
requiredTestWorkflow.finalRejected("Test both inspected modules before classifying them.");
requiredTestWorkflow.requireProbePlanning("owned/render.py:render");
const kindLimitedWorkflow=new InvestigationWorkflow();
kindLimitedWorkflow.read("owned/render.py");
kindLimitedWorkflow.requireProbePlanning("owned/render.py:render","html_reflection");
assert.deepEqual(await kindLimitedWorkflow.constraints(),{action:["plan_probe"],answer:["html_reflection"]},
  "a fixture requiring HTML reflection must not permit path construction");
assert.equal(kindLimitedWorkflow.rejectedRequiredProbePlan(),false);
assert.equal(kindLimitedWorkflow.rejectedRequiredProbePlan(),true);
assert.ok((await kindLimitedWorkflow.constraints()).action.includes("final"),
  "invalid plans release the kind constraint without an infinite loop");
assert.deepEqual(await requiredTestWorkflow.constraints(),{action:["plan_probe"]},"explicit missing-test recovery must block another final");
const selectedProbe={action:"plan_probe",path:"owned/render.py",query:"render",answer:"html_reflection",
  hypothesis:"Markup might survive in the output; escaped markup would disprove it."} as any;
requiredTestWorkflow.plan(selectedProbe);
assert.deepEqual(await requiredTestWorkflow.constraints(),
  {action:["verify_source"],path:["owned/render.py"],query:["render"],answer:["html_reflection"]},
  "a selected probe must transition into verification");
requiredTestWorkflow.observe({...selectedProbe,action:"verify_source"},JSON.stringify({status:"behavior_not_observed",behavior_observed:false}));
assert.ok((await requiredTestWorkflow.constraints()).action.includes("final"),"verified probe must release final action");
const rejectedPlanningWorkflow=new InvestigationWorkflow();
rejectedPlanningWorkflow.read("owned/render.py");
rejectedPlanningWorkflow.requireProbePlanning("owned/render.py:render");
assert.equal(rejectedPlanningWorkflow.rejectedRequiredProbePlan(),false,"first invalid plan keeps bounded recovery active");
assert.deepEqual(await rejectedPlanningWorkflow.constraints(),{action:["plan_probe"]},"first invalid plan must still request a probe");
assert.equal(rejectedPlanningWorkflow.rejectedRequiredProbePlan(),true,"second invalid plan releases forced planning");
assert.ok((await rejectedPlanningWorkflow.constraints()).action.includes("final"),"repeated invalid plans must not deadlock the controller");
assert.ok(controllerText.includes("[REQUIRED_PROBE_PLAN_RELEASED]"),"controller must record escape from invalid probe planning");

assert.ok(controllerText.includes("snapshot.readPaths"),"recovery must rely on inspected source");
assert.ok(controllerText.includes("o.status==='behavior_observed'||o.status==='behavior_not_observed'"),
  "unsupported probe attempts must not consume the declared recovery candidate");
assert.ok(controllerText.includes("o.kind===limits.requiredProbeKind"),
  "wrong-kind observation cannot satisfy the required task probe kind");

assert.ok(workflowText.includes("if(this.recoveryProbe)return {action:['plan_probe']"),"probe recovery must constrain action to plan_probe");
assert.ok(workflowText.includes("return {action:['verify_source']"),"a planned probe must constrain follow-up execution to verify_source");
assert.ok(controllerText.includes("enum:recordedIds"),"with recorded cases, the model must select only verifier-issued case IDs");

const flowText=await readFile(join(process.cwd(),"packages/security-solver/src/local-program-flow.ts"),"utf8");
assert.ok(flowText.includes("sourceHints.filter(path=>!reads.has(path))"),"incomplete conclusions must advance through selected candidate batch");
assert.ok(flowText.includes("[PROBE_REQUIRED_FOR_FINDING]"),"fabricated findings must receive probe-directed controller feedback");
assert.ok(flowText.includes("prioritized candidate file(s) remain unread"),"coverage feedback must enumerate unfinished candidates");
assert.ok(flowText.includes("State only what the selected files"),"do not accept repository-wide negative claims");
assert.ok(controllerText.includes("requireInvestigationAfterEmpty=true;"),"coverage-driven final rejection must reopen tool actions");
assert.ok(controllerText.includes("requiredNextSource"),"coverage rejection must enforce a fresh eligible source read");
assert.ok(controllerText.includes("[EMPTY_FINAL_RECOVER]"),"repeated empty finals must reopen source investigation");
assert.ok(controllerText.includes("requireInvestigationAfterEmpty"),"recovery must require a tool action rather than another empty final");
assert.ok(!controllerText.includes("recentActions.clear();stalledActions=0"),"final rejection must preserve read history");
const server=createServer();
try {
  const fixture=join(root,"fixture");await mkdir(fixture);
  await writeFile(join(fixture,"Render.java"),'public class Render { public static String render(String x) { return "<p>"+x+"</p>"; }}');
  await writeFile(join(fixture,"Caller.java"),'Render.render(input);');
  await writeFile(join(fixture,"render.cjs"),'exports.render = x => "<p>"+x+"</p>";');
  await writeFile(join(fixture,"Render.sol"),'pragma solidity ^0.8.20; contract Render { function render(string memory x) public pure returns(string memory) { return string.concat("<p>",x,"</p>"); }}');
  await writeFile(join(fixture,"Store.sol"),'pragma solidity ^0.8.20; contract Store { uint256 public value; constructor(uint256 initial) {value=initial;} function set(uint256 x) external {value=x;} }');
  await writeFile(join(fixture,"StoreCaller.sol"),'store.set(input);');
  await writeFile(join(fixture,"caller.js"),'renderer.render(input);');
  await writeFile(join(fixture,"Caller.sol"),'renderer.render(input);');
  for(let i=0;i<35;i++)await writeFile(join(fixture,"incompatible_"+String(i).padStart(3,"0")+"_"+"x".repeat(100)+".sol"),"pragma solidity 0.6.0; contract Old {} ");
  execFileSync("git",["init","-q",fixture]);
  execFileSync("git",["-C",fixture,"add","."]);
  execFileSync("git",["-C",fixture,"-c","user.name=Fixture","-c","user.email=fixture@example.test","commit","-qm","Owned fixture"]);
  const realGit=execFileSync("which",["git"],{encoding:"utf8"}).trim();
  const bin=join(root,"bin");await mkdir(bin);
  await writeFile(join(bin,"git"),'#!/usr/bin/python3\nimport os,sys,shutil,subprocess\nargs=sys.argv[1:]\nif "clone" in args:\n    shutil.copytree('+JSON.stringify(fixture)+',args[-1])\nelif \"fetch\" in args:\n    subprocess.run(['+JSON.stringify(realGit)+',\"cat-file\",\"-e\",args[-1]+\"^{commit}\"],check=True)\nelse:\n    os.execv('+JSON.stringify(realGit)+',['+JSON.stringify(realGit)+']+args)\n');
  await chmod(join(bin,"git"),0o700);process.env.PATH=bin+":"+originalPath;
  let policyOffset=0,policyDone=false;
  let turn=0, caseId="", source="", caller="", selector="", stateful=false,reviewMode=false,reviewIndex=0,reviewOffset=0;
  let evidenceRepairReads:string[]=[];
  const reviewFiles=["source/Store.sol","evidence/report.txt","evidence/replay.json","evidence/policy.txt"];
  const sequence={constructorArgs:["5"],steps:[
    {operation:"call",function:"value()",args:[],expect:"5"},
    {operation:"send",function:"set(uint256)",args:["7"]},
    {operation:"call",function:"value()",args:[],expect:"8"},
  ]};
  server.on("request",async(req,res)=>{
    let raw="";for await(const chunk of req)raw+=chunk;
    const request=JSON.parse(raw);
    // Production progress is appended separately; inspect the last actual tool result.
    const latestTool=()=>[...request.messages].reverse().find((m:any)=>m.content?.startsWith("TOOL_RESULT "));
    const latestResult=()=>{try{return JSON.parse(latestTool()?.content.split("\n")[0].slice("TOOL_RESULT ".length) || "null");}catch{return null;}};
    assert.ok(JSON.stringify(request.messages).length+JSON.stringify(request.format).length <= (8192-request.options.num_predict-512)*3,'Every production request fits its declared budget');
    if(!reviewMode && !policyDone) {
      const last=latestTool();
      if(last) {const page=JSON.parse(JSON.parse(last.content.split('\n')[0].slice(12)).output);policyDone=page.nextOffset===null;policyOffset=page.nextOffset;}
      if(!policyDone) {res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify({action:'read_file',path:'audit-policy.txt',offset:policyOffset,query:'',answer:''})}}));return;}
    }
    if(!reviewMode && request.format.properties.action.enum.length===1 && request.format.properties.action.enum[0]==='verify_source') {
      const planned=[...request.messages].reverse().map((m:any)=>{try{return JSON.parse(m.content);}catch{return null;}}).find((a:any)=>a?.action==='plan_probe');
      assert.ok(planned);
      res.end(JSON.stringify({message:{role:'assistant',content:JSON.stringify({...planned,action:'verify_source'})}}));return;
    }
    // Finish the current read before advancing the scripted investigation stage.
    // Output-token reservations may change page size; evidence must stay complete.
    if(!reviewMode && turn>0) {
      const last=latestTool()?.content || request.messages.at(-1).content;
      if(last.startsWith("TOOL_RESULT ")) {
        const result=JSON.parse(last.split("\n")[0].slice(12));
        if(result.name==="read_file") {
          const page=JSON.parse(result.output);
          if(page.nextOffset!=null) {
            const previous=[...request.messages].reverse().map((m:any)=>{try{return JSON.parse(m.content);}catch{return null;}}).find((a:any)=>a?.action==='read_file');
            res.end(JSON.stringify({message:{role:"assistant",content:JSON.stringify({
              action:"read_file",path:previous.path,offset:page.nextOffset,query:"",answer:""})}}));
            return;
          }
        }
      }
    }
    // A rejected final may require fresh source and caller evidence. The
    // mock must follow the controller's feedback instead of parsing the
    // plain-text final_validation response as a verifier case.
    const lastResult=latestResult();
    if(!reviewMode && lastResult?.name==="final_validation" &&
       /Read the tested source file and the claimed caller file/.test(String(lastResult.output))) {
      evidenceRepairReads=["source-1/"+source,"source-1/"+caller];
    }
    if(!reviewMode && evidenceRepairReads.length) {
      if(lastResult?.name==="read_file") {
        try {if(JSON.parse(lastResult.output).nextOffset===null)evidenceRepairReads.shift();}catch{}
      }
      if(evidenceRepairReads.length) {
        res.end(JSON.stringify({message:{role:"assistant",content:JSON.stringify({
          action:"read_file",path:evidenceRepairReads[0],offset:0,query:"",answer:""
        })}}));return;
      }
    }
    turn++;
    if(reviewMode) {
      assert.ok(request.messages[1].content.length<7000,"Review prompt must not embed large policy/report");
      const last=latestTool()?.content || request.messages.at(-1).content;
      if(last.startsWith("TOOL_RESULT ")) {
        const page=JSON.parse(JSON.parse(last.split("\n")[0].slice(12)).output);
        if(page.nextOffset===null) {reviewIndex++;reviewOffset=0;}else reviewOffset=page.nextOffset;
      }
      const action=reviewIndex<reviewFiles.length
        ? {action:"read_file",path:reviewFiles[reviewIndex],offset:reviewOffset,query:"",answer:""}
        : {action:"final",path:"",query:"",answer:JSON.stringify({verdict:"reject",recommendation:"dont_submit",severity:"informational",confidence:0.9,
          ratingReason:"This synthetic fixture deliberately uses an incorrect expected value; it is not a vulnerability.",bet100:false,
          rubric:{exploitability:0,impactSeverity:0,evidenceQuality:3,novelty:0,scopeAlignment:3},issues:[],reasoning:"The supplied expectation is deliberately wrong; only report plumbing is under test."})};
      res.end(JSON.stringify({message:{role:"assistant",content:JSON.stringify(action)}}));return;
    }
    // The workflow may first require a Solidity declaration outline after
    // paginated reads. The scripted model must honor that constrained action
    // before returning to its probe plan; it must not bypass the controller.
    if(!reviewMode && request.format.properties.action.enum.length===1 &&
       request.format.properties.action.enum[0]==="outline_solidity") {
      const lastSolidityRead=[...request.messages].reverse().map((m:any)=>{
        try{return JSON.parse(m.content);}catch{return null;}
      }).find((a:any)=>a?.action==="read_file" && typeof a.path==="string" && a.path.endsWith(".sol"));
      // Older source action messages may have been compacted; the fixture's
      // source is the same owned path already selected by this test scenario.
      const outlinePath=lastSolidityRead?.path || (source.endsWith(".sol")?"source-1/"+source:null);
      assert.ok(outlinePath,"forced outline requires a fixture Solidity source");
      turn--;
      res.end(JSON.stringify({message:{role:"assistant",content:JSON.stringify({
        action:"outline_solidity",path:outlinePath,offset:0,query:"",answer:""
      })}}));
      return;
    }
    assert.ok(request.format.properties.action.enum.includes("plan_probe"));
    assert.ok(request.messages.some((m:any)=>m.content.includes("exported JavaScript")));
    const action=(name:string,path:string,query="",answer="")=>({action:name,path,query,answer});
    let next;
    if(turn===1)next=action("read_file","source-1/"+source);
    else if(turn===2 && stateful)next=action("final","","",JSON.stringify({findings:[]}));
    else if(turn===2)next=action("read_file","source-1/"+caller);
    else if(turn===3 && stateful) {assert.ok(JSON.stringify(request.messages).includes("No supported probe"));next={...action("verify_source","source-1/"+source,selector,"solidity_sequence"),sequence};}
    else if(turn===3)next=action("verify_source","source-1/"+source,source.endsWith(".java")?"Render.missing":"missing","html_reflection");
    else if(turn===4 && !stateful) {
      const latest=latestTool()?.content || "";
      // Declaration preflight rejects invented function names before the verifier.
      // The model receives the rejection through the controller; its exact prompt may be compacted.
      next=action("verify_source","source-1/"+source,selector,"html_reflection");
    } else if(!caseId && source.endsWith('.sol') && latestResult()?.name==='outline_solidity') {
      // An AST outline is navigation, not a reproduction observation. Resume
      // the declared probe and continue to require an actual verifier result.
      next={...action("plan_probe","source-1/"+source,selector,stateful?"solidity_sequence":"html_reflection"),
        ...(stateful?{sequence}:{}),
        hypothesis:"Check the stated fixture behavior; an assertion mismatch or escaped output disproves the hypothesis."};
    } else {
      if(!caseId) {
        const previous=latestResult();
        assert.equal(previous?.name,"verify_source","expected a verifier result before constructing a finding, source="+source+" turn="+turn+" recent="+JSON.stringify(request.messages.slice(-5)).slice(0,2500));
        caseId=JSON.parse(previous.output).caseId;
      }
      assert.ok(caseId);
      next=action("final","","",JSON.stringify({findings:[{
        caseId,severity:"medium",confidence:0.7,title:stateful?"Owned fixture assertion discrepancy":"Owned fixture reflection",
        ratingReason:"Owned fixture preserves input; this test checks report plumbing only.",
        impact:stateful?"Owned fixture returns 7 while the supplied test expects 8; no vulnerability claimed.":"Owned fixture returns raw markup to its caller.",
        callerFile:"source-1/"+(stateful?source:caller),callerLine:1,...(stateful?{reachability:"direct_transaction"}:{}),
        falsification:"No production exploitability is claimed; only owned fixture behavior was measured."
      }]}));
    }
    if(next.action==='verify_source')next={...next,action:'plan_probe',hypothesis:'Owned fixture behavior may violate the stated requirement; an escaped value or matching assertion would disprove it.'};
    res.setHeader("Content-Type","application/json");
    res.end(JSON.stringify({message:{role:"assistant",content:JSON.stringify(next)}}));
  });
  await new Promise<void>(r=>server.listen(0,"127.0.0.1",r));
  const address=server.address();assert.ok(address&&typeof address!=="string");
  process.env.AUTOHACK_OLLAMA_URL="http://127.0.0.1:"+address.port+"/api/chat";
  const {runLocalProgramHunt,independentReview}=await import("../packages/security-solver/src/local-program-flow");
  const {readSourceCase,replaySourceCase}=await import("../packages/security-solver/src/source-reproduction");
  const {referencesProbedFunction}=await import("../packages/security-solver/src/source-function-reference");
  assert.equal(referencesProbedFunction("renderer.render(input)","Render.render"),true);
  assert.equal(referencesProbedFunction("renderer.prerender(input)","Render.render"),false);
  assert.equal(referencesProbedFunction("// render is declared here","Render.render"),false);
  const program:any={id:"owned",provider:"immunefi",name:"Owned fixture",scopeSummary:JSON.stringify({policy:"Owned fixture policy; local tests only. ".repeat(300),scopes:[
    {assetType:"SOURCE_CODE",eligibleForBounty:true,assetIdentifier:"https://github.com/fixture/owned"}
  ]})};
  // Run a real isolated baseline -> send -> observation without fabricated
  // assertions; observations are evidence but not a reportable discrepancy.
  const {createProbeSession}=await import("../packages/security-solver/src/source-reproduction");
  const baselineSession=await createProbeSession(program,fixture,[{directory:fixture,url:"https://github.com/fixture/owned"}]);
  const baseline=JSON.parse(await baselineSession.probe("Store.sol","Store.set","solidity_sequence",{
    constructorArgs:["5"],steps:[
      {operation:"observe",function:"value()",args:[]},
      {operation:"send",function:"set(uint256)",args:["7"]},
      {operation:"observe",function:"value()",args:[]}
    ]
  }));
  assert.equal(baseline.status,"observation_only");
  assert.deepEqual(baseline.observations.steps.filter((step:any)=>step.operation==="observe").map((step:any)=>step.actual),["5","7"]);
  assert.equal(baseline.caseId,undefined);
  assert.equal(baselineSession.completedProbes,1);

  for(const language of ["javascript","java","solidity","stateful_solidity"]) {
    turn=0;policyOffset=0;policyDone=false;caseId="";evidenceRepairReads=[];stateful=language==="stateful_solidity";
    source=language==="javascript"?"render.cjs":language==="java"?"Render.java":"Render.sol";
    caller=language==="javascript"?"caller.js":language==="java"?"Caller.java":"Caller.sol";
    selector=language==="javascript"?"render":"Render.render";
    if(stateful) {source="Store.sol";caller="StoreCaller.sol";selector="Store.set";}
    const result=await runLocalProgramHunt(program);
    if(!result.success && result.auditRecord)console.error(await readFile(join(root,"data/logs",result.auditRecord),"utf8"));
    assert.equal(result.success,true,JSON.stringify(result));
    assert.equal(result.findings.length,1);
    if(!stateful)assert.ok(result.coverageDetail && !result.coverageDetail.includes("1 failed probes") && !result.coverageDetail.includes("1 unsupported probes"),"invented probe should be stopped at declaration preflight");
    else assert.equal(result.findings[0].vulnerabilityType,"State assertion discrepancy");
    const record=await readSourceCase(caseId,program);
    assert.equal((await replaySourceCase(record,fixture)).behavior_observed,true);
    if(stateful) {
      assert.deepEqual(record.spec.sequence,sequence);
      assert.match(result.findings[0].reportBody,/Reachability: direct_transaction/);
      reviewMode=true;reviewIndex=0;reviewOffset=0;
      const reviewProgram={...program,scopeSummary:JSON.stringify({...JSON.parse(program.scopeSummary),policy:"Long policy text. ".repeat(1600)})};
      const reviewed=await independentReview({...result.findings[0],id:"owned-review"} as any,reviewProgram,caseId,new AbortController().signal);
      assert.equal(reviewed.review.verdict,"reject");assert.equal(reviewIndex,reviewFiles.length);
      reviewMode=false;
      assert.ok(result.findings[0].reportBody.includes(JSON.stringify(sequence,null,2)));
    }
  }
  console.log("JavaScript/Java/Solidity model action -> failed probe recovery -> sandbox -> caller -> report -> persisted evidence -> replay PASSED");
} finally {
  process.env.PATH=originalPath;
  await new Promise<void>(r=>server.close(()=>r()));
  await rm(root,{recursive:true,force:true});
}

// Integration regression: compaction may discard model-visible pages but must not
// discard pagination cursors, and the 2,000-character source chunk cap remains.
assert.ok(controllerText.includes('sourceReadCounts'), 'repeated source reads must survive compaction');
assert.ok(controllerText.includes('never permit unlimited identical recovery reads'), 'evicted pages must preserve pagination');
assert.ok(controllerText.includes('[PROBE_RESULT]'), 'probe outcomes must be observable in hunt logs');
assert.ok(controllerText.includes('Math.min(2000'), 'CPU-friendly file chunking must remain active');
