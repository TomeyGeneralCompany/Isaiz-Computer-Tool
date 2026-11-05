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
  entryProof?:{caseId:string;file:string;selector:string;sourceSha256:string;
    observations:unknown;limitation:string};
}
export function buildControllerReportPacket(input:ControllerReportPacket):ControllerReportPacket {
  if(!/^[0-9a-f]{64}$/.test(input.caseId) || !/^[0-9a-f]{64}$/.test(input.sourceSha256))
    throw new Error('Controller report packet requires recorded SHA256 identifiers');
  if(!Number.isSafeInteger(input.callerLine) || input.callerLine<1 || !input.callerCode.trim())
    throw new Error('Controller report packet requires actual nonempty source caller line');
  if(input.entryProof && (!/^[0-9a-f]{64}$/.test(input.entryProof.caseId) ||
      !/^[0-9a-f]{64}$/.test(input.entryProof.sourceSha256) ||
      !input.entryProof.file || !input.entryProof.selector))
    throw new Error('Controller entry proof requires a persisted reproduction case');
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
    ...(packet.entryProof ? [
      '## Controller-Executed Entry-to-Output Proof',
      'Entry reproduction case: '+packet.entryProof.caseId,
      'Entry source: '+packet.entryProof.file,
      'Entry selector: '+packet.entryProof.selector,
      'Entry source SHA256: '+packet.entryProof.sourceSha256,
      'Recorded entry execution observations:',
      JSON.stringify(packet.entryProof.observations,null,2),
      'Entry proof limitations: '+packet.entryProof.limitation,
      'Independent review must replay this entry reproduction and inspect actual output context.'
    ] : ['Entry execution not established by a separate sandbox reproduction.']),
    'The observation establishes tested behavior; actual security impact must be assessed against the caller, mitigations and application context.'
  ].join('\n');
}
