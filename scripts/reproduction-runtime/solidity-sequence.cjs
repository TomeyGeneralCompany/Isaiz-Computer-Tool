'use strict';
// Declarative local contract tests. No RPC URL, private key, script or arbitrary calldata input.
function validateSequence(s) {
  const object = (o, required, allowed=required) => {
    if (!o || typeof o !== 'object' || Array.isArray(o) || required.some(k=>!Object.hasOwn(o,k)) ||
        Object.keys(o).some(k=>!allowed.includes(k))) throw new Error('Invalid sequence fields');
  };
  const value = (v, depth=0) => {
    if (typeof v === 'boolean' || typeof v === 'string' && v.length<=2048) return;
    if (Array.isArray(v) && depth<2 && v.length<=32) {v.forEach(x=>value(x,depth+1));return;}
    throw new Error('ABI values must be strings, booleans or bounded arrays; encode integers as strings');
  };
  const args = a => {if(!Array.isArray(a)||a.length>32)throw new Error('Invalid ABI arguments');a.forEach(v=>value(v));};
  const wei = v => {if(v!==undefined && (typeof v!=='string'||!/^(0|[1-9][0-9]{0,29})$/.test(v)))throw new Error('Invalid wei amount');};
  object(s,['constructorArgs','steps'],['constructorArgs','constructorValueWei','steps','deployment','preparation']);
  if(s.deployment!==undefined) {
    object(s.deployment,['file','contract']);
    if(typeof s.deployment.file!=='string' || s.deployment.file.length>512 ||
       !/^[A-Za-z0-9_.\/-]+\.sol$/.test(s.deployment.file) ||
       s.deployment.file.startsWith('/') ||
       s.deployment.file.split('/').some(x=>x==='..'||x==='.') ||
       typeof s.deployment.contract!=='string' ||
       !/^[A-Za-z_]\w*$/.test(s.deployment.contract))
      throw new Error('Invalid repository-local derived deployment');
  }
  if(s.preparation!==undefined) {
    const p=s.preparation;
    object(p,['deployments','operations','checks']);
    if(!Array.isArray(p.deployments)||p.deployments.length>8 ||
       !Array.isArray(p.operations)||p.operations.length>24 ||
       !Array.isArray(p.checks)||p.checks.length>16)
      throw new Error('Invalid preparation bounds');
    const ids=new Set(),deployments=new Set();
    const id=v=>typeof v==='string'&&/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(v);
    const method=v=>typeof v==='string'&&/^[A-Za-z_]\w*(?:\([A-Za-z0-9_,()[\]]*\))?$/.test(v);
    for(const d of p.deployments) {
      object(d,['id','file','contract','constructorArgs'],['id','file','contract','constructorArgs','valueWei']);
      if(!id(d.id)||ids.has(d.id)||typeof d.file!=='string' ||
         !/^[A-Za-z0-9_.\\/-]+\\.sol$/.test(d.file) || d.file.startsWith('/') ||
         d.file.split('/').some(x=>x==='..'||x==='.') ||
         typeof d.contract!=='string'||!/^[A-Za-z_]\\w*$/.test(d.contract))
        throw new Error('Invalid preparation deployment');
      ids.add(d.id);deployments.add(d.id);args(d.constructorArgs);wei(d.valueWei);
    }
    for(const step of [...p.operations,...p.checks]) {
      const check=p.checks.includes(step);
      object(step,check?['id','deploymentId','function','args','sender','expect']:
        ['id','deploymentId','function','args','sender'],
        check?['id','deploymentId','function','args','sender','expect']:
        ['id','deploymentId','function','args','sender','valueWei','expectRevert']);
      if(!id(step.id)||ids.has(step.id)||!deployments.has(step.deploymentId) ||
         !method(step.function)||!Number.isInteger(step.sender)||
         step.sender<0||step.sender>2)
        throw new Error('Invalid preparation operation');
      ids.add(step.id);args(step.args);
      if(check)value(step.expect);
      else {wei(step.valueWei);if(step.expectRevert!==undefined&&typeof step.expectRevert!=='boolean')
        throw new Error('Invalid preparation revert expectation');}
    }
  }
  args(s.constructorArgs);wei(s.constructorValueWei);
  if(JSON.stringify(s).length>16000 || !Array.isArray(s.steps) || !s.steps.length || s.steps.length>16)throw new Error('Invalid sequence length');
  for(const step of s.steps) {
    if(step?.operation==='call')object(step,['operation','function','args','expect'],['operation','function','args','expect','sender']);
    else if(step?.operation==='observe')object(step,['operation','function','args'],['operation','function','args','sender']);
    else if(step?.operation==='send')object(step,['operation','function','args'],['operation','function','args','sender','valueWei','expectRevert']);
    else throw new Error('Unknown sequence operation');
    if(typeof step.function!=='string'||step.function.length>200||!/^[A-Za-z_][A-Za-z0-9_]*(?:\([A-Za-z0-9_,()[\]]*\))?$/.test(step.function))throw new Error('Invalid ABI function selector');
    args(step.args);
    if(step.sender!==undefined && (!Number.isInteger(step.sender)||step.sender<0||step.sender>2))throw new Error('Invalid local sender');
    if(step.operation==='call')value(step.expect);
    else {wei(step.valueWei);if(step.expectRevert!==undefined&&typeof step.expectRevert!=='boolean')throw new Error('Invalid revert expectation');}
  }
  if(!s.steps.some(step=>step.operation==='call'||step.operation==='observe'))throw new Error('Include a read observation');
  return s;
}
function normalize(v) {
  if(typeof v==='bigint')return v.toString();
  if(Array.isArray(v))return Array.from(v,normalize);
  if(typeof v==='string' && /^0x[0-9a-fA-F]{40}$/.test(v))return v.toLowerCase();
  if(typeof v==='string'||typeof v==='boolean')return v;
  throw new Error('Unsupported ABI result');
}
async function runSequence(artifact, sequence, transport, preparationArtifacts={}) {
  validateSequence(sequence);
  const {BrowserProvider, ContractFactory}=require('ethers');
  if(!artifact?.evm?.bytecode?.object || !/^[0-9a-fA-F]+$/.test(artifact.evm.bytecode.object))
    throw new Error('A deployable contract without unresolved library links is required');
  const provider=new BrowserProvider(transport,undefined,{cacheTimeout:-1,pollingInterval:10});
  try {
    const signers=await Promise.all([0,1,2].map(i=>provider.getSigner(i)));
    const accounts=await Promise.all(signers.map(s=>s.getAddress()));
    let address;
    const deployed=new Map();
    const setupSteps=[];
    const resolve = v => {
      if(Array.isArray(v))return v.map(resolve);
      if(typeof v==='string' && /^\$account[012]$/.test(v))return accounts[Number(v.at(-1))];
      if(typeof v==='string'&&/^\$deployment:[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(v)){
        const item=deployed.get(v.slice('$deployment:'.length));
        if(!item)throw new Error('Unresolved earlier deployment '+v);
        return item.address;
      }
      if(v==='$contract') {if(!address)throw new Error('$contract is unavailable in constructor arguments');return address;}
      if(typeof v==='string' && v.startsWith('$'))throw new Error('Unknown local address reference');
      return v;
    };
    // Preparation runs only in this isolated EVM. Each deployment and setup
    // operation is source-declared and evidence-checked before the main probe.
    const preparation=sequence.preparation;
    if(preparation) {
      for(const d of preparation.deployments) {
        const depArtifact=preparationArtifacts[d.file]?.[d.contract];
        if(!depArtifact?.evm?.bytecode?.object ||
           !/^[a-fA-F0-9]+$/.test(depArtifact.evm.bytecode.object))
          throw new Error('Missing or unlinked preparation contract '+d.file+':'+d.contract);
        const dep=await new ContractFactory(depArtifact.abi,depArtifact.evm.bytecode.object,signers[0])
          .deploy(...d.constructorArgs.map(resolve),{value:d.valueWei||'0',gasLimit:10000000});
        const receipt=await dep.deploymentTransaction().wait();
        if(receipt?.status!==1)throw new Error('Preparation deployment failed: '+d.id);
        const depAddress=await dep.getAddress();
        deployed.set(d.id,{contract:dep,address:depAddress,receipt});
        setupSteps.push({operation:'setup',function:'deploy:'+d.file+':'+d.contract,
          sender:0,passed:true,gasUsed:receipt.gasUsed.toString(),purpose:'prepare '+d.id});
      }
      for(const op of preparation.operations) {
        const item=deployed.get(op.deploymentId);
        const fn=item.contract.connect(signers[op.sender]).getFunction(op.function);
        const fragment=fn.fragment;
        if(!['payable','nonpayable'].includes(fragment.stateMutability))
          throw new Error('Preparation operation must change state: '+op.id);
        const values=op.args.map(resolve);
        item.contract.interface.encodeFunctionData(fragment,values);
        if(fragment.stateMutability!=='payable'&&BigInt(op.valueWei||'0')!==0n)
          throw new Error('Nonpayable preparation operation: '+op.id);
        let receipt;
        try {const tx=await fn.send(...values,{value:op.valueWei||'0',gasLimit:2000000});receipt=await tx.wait();}
        catch(error) {if(error.receipt?.status!==0)throw error;receipt=error.receipt;}
        if(!receipt||![0,1].includes(receipt.status))
          throw new Error('Preparation missing transaction receipt: '+op.id);
        const actualReverted=receipt.status===0;
        setupSteps.push({operation:'setup',function:fragment.format('sighash'),
          sender:op.sender,gasUsed:receipt.gasUsed.toString(),
          passed:actualReverted===!!op.expectRevert,purpose:'preparation operation '+op.id});
        if(actualReverted!==!!op.expectRevert)
          throw new Error('Preparation transaction expectation failed: '+op.id);
      }
      for(const check of preparation.checks) {
        const item=deployed.get(check.deploymentId);
        const fn=item.contract.connect(signers[check.sender]).getFunction(check.function);
        if(!['view','pure'].includes(fn.fragment.stateMutability))
          throw new Error('Preparation check must be read-only: '+check.id);
        const result=await fn.staticCallResult(...check.args.map(resolve),{gasLimit:1000000});
        const actual=normalize(fn.fragment.outputs.length===1?result[0]:result);
        const expected=normalize(resolve(check.expect));
        if(JSON.stringify(actual)!==JSON.stringify(expected))
          throw new Error('Preparation check failed: '+check.id);
      }
    }
    const contract=await new ContractFactory(artifact.abi,artifact.evm.bytecode.object,signers[0])
      .deploy(...sequence.constructorArgs.map(resolve),{value:sequence.constructorValueWei||'0',gasLimit:10000000});
    const deployment=await contract.deploymentTransaction().wait();
    if(!deployment || deployment.status!==1)throw new Error('Constructor deployment failed');
    address=await contract.getAddress();
    const steps=[...setupSteps];
    // Only the explicitly generated ERC1155 test harness gets automatic setup.
    // These are actual mined transactions, recorded separately from the probe.
    const harness = artifact.abi.some(x=>x.type==='function' && x.name==='tomeyMint') &&
      artifact.abi.some(x=>x.type==='function' && x.name==='tomeyMintBatch');
    const prepared = new Set();
    async function prepareTransfer(step) {
      if(!harness || step.operation!=='send' || step.expectRevert===true)return;
      const name=step.function.split('(')[0];
      if(!['safeTransferFrom','safeBatchTransferFrom'].includes(name))return;
      const values=step.args.map(resolve);
      const [from,to]=values;
      if(typeof from!=='string' || !accounts.some(a=>a.toLowerCase()===from.toLowerCase()) ||
         typeof to!=='string' || /^0x0{40}$/i.test(to))return;
      const ownerIndex=accounts.findIndex(a=>a.toLowerCase()===from.toLowerCase());
      const sender=step.sender??0;
      const idList=name==='safeTransferFrom'?[values[2]]:values[2];
      const amountList=name==='safeTransferFrom'?[values[3]]:values[3];
      if(!Array.isArray(idList)||!Array.isArray(amountList)||idList.length!==amountList.length||
         !idList.length||idList.length>32)return;
      const pairs=idList.map((id,i)=>[String(id),String(amountList[i])]);
      if(pairs.some(([id,amount])=>!/^(0|[1-9][0-9]{0,77})$/.test(id) ||
         !/^(0|[1-9][0-9]{0,77})$/.test(amount)))return;
      const key=JSON.stringify([from,pairs]);
      if(!prepared.has(key)){
        const mint=contract.getFunction('tomeyMintBatch(address,uint256[],uint256[])');
        const tx=await mint.send(from,pairs.map(p=>p[0]),pairs.map(p=>p[1]),{gasLimit:2000000});
        const receipt=await tx.wait();
        if(receipt?.status!==1)throw new Error('ERC1155 harness mint setup failed');
        steps.push({operation:'setup',function:'tomeyMintBatch(address,uint256[],uint256[])',
          sender:0,passed:true,gasUsed:receipt.gasUsed.toString(),purpose:'fund transfer prerequisites'});
        prepared.add(key);
      }
      if(ownerIndex!==sender){
        const approved=await contract.getFunction('isApprovedForAll(address,address)')
          .staticCall(from,accounts[sender]);
        if(!approved){
          const tx=await contract.connect(signers[ownerIndex])
            .getFunction('setApprovalForAll(address,bool)').send(accounts[sender],true,{gasLimit:2000000});
          const receipt=await tx.wait();
          if(receipt?.status!==1)throw new Error('ERC1155 harness approval setup failed');
          steps.push({operation:'setup',function:'setApprovalForAll(address,bool)',
            sender:ownerIndex,passed:true,gasUsed:receipt.gasUsed.toString(),purpose:'authorize transfer sender'});
        }
      }
    }
    for(const step of sequence.steps) {
      await prepareTransfer(step);
      const fn=contract.connect(signers[step.sender??0]).getFunction(step.function);
      const fragment=fn.fragment;
      const args=step.args.map(resolve);
      // Encode first: ABI/selector/setup failures must not count as expected reverts.
      contract.interface.encodeFunctionData(fragment,args);
      if(step.operation==='call' || step.operation==='observe') {
        if(!['view','pure'].includes(fragment.stateMutability))throw new Error('call requires a view/pure function');
        const result=await fn.staticCallResult(...args,{gasLimit:1000000});
        const actual=normalize(fragment.outputs.length===1?result[0]:result);
        if(step.operation==='call') {
          const expected=normalize(resolve(step.expect));
          steps.push({operation:'call',function:fragment.format('sighash'),sender:step.sender??0,
            actual,expected,passed:JSON.stringify(actual)===JSON.stringify(expected)});
        } else steps.push({operation:'observe',function:fragment.format('sighash'),sender:step.sender??0,actual});
      } else {
        if(!['nonpayable','payable'].includes(fragment.stateMutability))throw new Error('send requires a state-changing function');
        if(fragment.stateMutability!=='payable' && BigInt(step.valueWei||'0')!==0n)throw new Error('Nonpayable function cannot receive value');
        let receipt;
        try {const tx=await fn.send(...args,{value:step.valueWei||'0',gasLimit:2000000});receipt=await tx.wait();}
        catch(error) {
          // Only a mined EVM revert is a revert observation, not a transport/ABI error.
          if(error.receipt?.status!==0)throw error;
          receipt=error.receipt;
        }
        if(!receipt || ![0,1].includes(receipt.status))throw new Error('No transaction receipt');
        if(receipt.status===0 && receipt.gasUsed>=2000000n)throw new Error('Transaction exhausted its gas limit');
        const reverted=receipt.status===0;
        // A mined revert is evidence, even when the hypothesis expected success.\n        // Record the mismatch rather than aborting and losing the receipt and\n        // subsequent read observations. A revert never proves a vulnerability.
        steps.push({operation:'send',function:fragment.format('sighash'),sender:step.sender??0,
          valueWei:step.valueWei||'0',reverted,gasUsed:receipt.gasUsed.toString(),
          passed:reverted===!!step.expectRevert});
      }
    }
    const observations={contract:address.toLowerCase(),accounts:accounts.map(a=>a.toLowerCase()),
      deploymentGasUsed:deployment.gasUsed.toString(),steps};
    if(JSON.stringify(observations).length>64000)throw new Error('Sequence observations exceed 64KB');
    return observations;
  } finally {provider.destroy();}
}
module.exports={validateSequence,runSequence};
