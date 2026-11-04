/** Trusted, source-backed facts passed between report drafting and review.
 * Narrative impact and severity remain model assessments, never inferred here.
 */
export interface ControllerReportPacket {
  caseId:string;
  repositoryUrl:string;
  commit:string;
  testedFile:string;
  testedFunction:string;
  probeKind:string;
  sourceSha256:string;
  callerFile:string;
  callerLine:number;
  callerCode:string;
  reachability:'caller'|'direct_transaction';
  observations:unknown;
  limitation:string;
}
export function buildControllerReportPacket(input:ControllerReportPacket):ControllerReportPacket {
  if(!/^[0-9a-f]{64}$/.test(input.caseId) || !/^[0-9a-f]{64}$/.test(input.sourceSha256))
    throw new Error('Controller report packet requires recorded SHA256 identifiers');
  if(!Number.isSafeInteger(input.callerLine) || input.callerLine<1 || !input.callerCode.trim())
    throw new Error('Controller report packet requires actual nonempty source caller line');
  return Object.freeze({...input});
}
export function controllerReportPacketText(packet:ControllerReportPacket):string {
  return [
    '## Controller-Verified Source Evidence',
    'Reproduction case: '+packet.caseId,
    'Repository: '+packet.repositoryUrl,
    'Commit: '+packet.commit,
    'Tested source: '+packet.testedFile,
    'Tested selector: '+packet.testedFunction,
    'Probe kind: '+packet.probeKind,
    'Source SHA256: '+packet.sourceSha256,
    'Caller: '+packet.callerFile+':'+packet.callerLine,
    'Reachability: '+packet.reachability,
    'Inspected caller source: '+JSON.stringify(packet.callerCode.trim()),
    'Recorded isolated observations:',
    JSON.stringify(packet.observations,null,2),
    'Reproduction limitations: '+packet.limitation,
    'The observation establishes tested behavior; actual security impact must be assessed against the caller, mitigations and application context.'
  ].join('\n');
}
