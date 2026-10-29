/** Real configured Ollama -> real scoped hunt -> isolated source reproduction -> optional reviewer.
 * All source belongs to a fresh local test repository; no provider or production requests.
 */
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,chmod,rm,readdir,copyFile} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
const root=await mkdtemp(join(tmpdir(),'real-program-hunt-'));
const originalPath=process.env.PATH;
try {
  process.env.PROJECT_ROOT=root;
  process.env.GITHUB_TOKEN='offline-owned-fixture';
  process.env.LOCAL_OLLAMA_MODEL ||= 'qwen3:4b';
  process.env.LOCAL_OLLAMA_TOOL_PROTOCOL='json';
  process.env.AUTOHACK_AUTO_SOURCE_PREFETCH='true';
  process.env.AUTOHACK_GUIDED_SOURCE_PROBES='true';
  process.env.LOCAL_HUNT_DYNAMIC_ALLOWANCE='true';
  process.env.LOCAL_HUNT_MAX_TURNS='80';
  process.env.LOCAL_HUNT_NUM_PREDICT='2048';
  const fixture=join(root,'fixture');
  await mkdir(fixture);
  await writeFile(join(fixture,'render.py'),
    'def render(value):\n    return "<p>" + value + "</p>"\n');
  await writeFile(join(fixture,'caller.py'),
    'from http.server import BaseHTTPRequestHandler\n' +
    'from urllib.parse import parse_qs, urlsplit\n' +
    'from render import render\n' +
    'class OwnedHandler(BaseHTTPRequestHandler):\n' +
    '    def do_GET(self):\n' +
    '        value = parse_qs(urlsplit(self.path).query).get("q", [""])[0]\n' +
    '        body = render(value).encode("utf-8")\n' +
    '        self.send_response(200)\n' +
    '        self.send_header("Content-Type", "text/html; charset=utf-8")\n' +
    '        self.end_headers()\n' +
    '        self.wfile.write(body)\n');
  execFileSync('git',['init','-q',fixture]);
  execFileSync('git',['-C',fixture,'add','.']);
  execFileSync('git',['-C',fixture,'-c','user.name=Fixture','-c','user.email=fixture@example.test','commit','-qm','Owned fixture']);
  const realGit=execFileSync('which',['git'],{encoding:'utf8'}).trim();
  const bin=join(root,'bin');await mkdir(bin);
  await writeFile(join(bin,'git'),`#!/usr/bin/python3
import os,sys,shutil,subprocess
args=sys.argv[1:]
if "clone" in args:
    shutil.copytree(${JSON.stringify(fixture)},args[-1])
elif "fetch" in args:
    subprocess.run([${JSON.stringify(realGit)},"cat-file","-e",args[-1]+"^{commit}"],check=True)
else:
    os.execv(${JSON.stringify(realGit)},[${JSON.stringify(realGit)}]+args)
`);
  await chmod(join(bin,'git'),0o700);
  process.env.PATH=bin+':'+originalPath;
  const {runLocalProgramHunt,independentReview}=await import('../packages/security-solver/src/local-program-flow');
  const program:any={id:'owned-acceptance',provider:'immunefi',name:'Owned HTML rendering acceptance',
    scopeSummary:JSON.stringify({policy:'Authorized synthetic source only. User-supplied markup must be escaped before being rendered as HTML. No external requests or reports. ',
    scopes:[{assetType:'SOURCE_CODE',eligibleForBounty:true,assetIdentifier:'https://github.com/fixture/owned'}]})};
  const result=await runLocalProgramHunt(program);
  const report={success:result.success,coverage:result.coverage,coverageDetail:result.coverageDetail,
    findingCount:result.findings.length,auditRecord:result.auditRecord,error:result.error,
    findings:result.findings.map(f=>({title:f.title,reproductionCaseId:f.reproductionCaseId}))};
  const directory=join(process.cwd(),'data','production-workflow-tests');await mkdir(directory,{recursive:true});
  await writeFile(join(directory,'real-program-hunt.json'),JSON.stringify(report,null,2));
  if(!result.success || !result.findings.length) {
    if(result.auditRecord) {
      const log=await readFile(join(root,'data','logs',result.auditRecord),'utf8');
      await writeFile(join(directory,'real-program-hunt.log'),log);
    }
    throw new Error('Real-model scoped hunt did not generate a source-reproduced candidate: '+JSON.stringify(report));
  }
  assert.ok(result.findings.every(f=>f.reproductionCaseId&&f.reportBody));
  const evidence=result.findings[0];
  const reviewed=await independentReview({...evidence,id:'owned-acceptance-review'} as any,
    program,evidence.reproductionCaseId!,new AbortController().signal);
  assert.ok(['approve','reject'].includes(reviewed.review.verdict));
  await writeFile(join(directory,'real-program-review.json'),JSON.stringify({
    caseId:reviewed.caseId,verdict:reviewed.review.verdict,sourceSha256:reviewed.sourceSha256,replayedAt:reviewed.replayedAt
  },null,2));
  console.log('Actual Qwen3:4b scoped program hunt, source probe, report, replay and independent review PASSED');
} finally {
  process.env.PATH=originalPath;
  // Preserve reviewer turn/action logs before deleting the isolated fixture workspace.
  // Without this, a review timeout leaves only the generic 720-second CI error.
  try {
    const sourceLogs=join(root,'data','logs');
    const destination=join(process.cwd(),'data','production-workflow-tests','review-diagnostics');
    for(const name of await readdir(sourceLogs).catch(()=>[])) {
      if(!name.startsWith('local-review-') || !(name.endsWith('.log') || name.endsWith('.summary.json')))continue;
      await mkdir(destination,{recursive:true});
      await copyFile(join(sourceLogs,name),join(destination,name));
    }
  }catch(error) {console.error('Could not preserve reviewer diagnostics:',error);}
  await rm(root,{recursive:true,force:true});
}
