/** Owned benchmark repositories. Answer keys stay outside the model's checkout. */
export type Language='solidity'|'python'|'javascript'|'java';
export const LANGUAGES:readonly Language[]=['solidity','python','javascript','java'];
export type Answer={language:Language;file:string;selector:string;caller:string;kind:string;defect:string};
export type Fixture={files:Record<string,string>;answer:Answer};
const labels=['Pricing','Settlement','Compliance','Route','Reserve','Oracle','Pool','Ledger','Adapter','Gateway'];
const title=(i:number)=>labels[i%labels.length]+'D'+String(i).padStart(3,'0');
const join=(...lines:string[])=>lines.join('\n')+'\n';
function solidity(n:number):Fixture {
 const files:Record<string,string>={
  'contracts/settlement/SettlementAuthority.sol':join('// SPDX-License-Identifier: MIT','pragma solidity ^0.8.20;',
   'contract SettlementAuthority {','address public administrator;','address public operator;',
   'constructor(){administrator=msg.sender;operator=msg.sender;}',
   'function rotateOperator(address next) external {require(next!=address(0),"zero");operator=next;}',
   'function changeAdministrator(address next) external {require(msg.sender==administrator,"only admin");administrator=next;}','}'),
  'contracts/settlement/SettlementVault.sol':join('// SPDX-License-Identifier: MIT','pragma solidity ^0.8.20;',
   'import "./SettlementAuthority.sol";','import "../../lib/utils/src/AmountMath.sol";',
   'contract SettlementVault is SettlementAuthority {',
   'using AmountMath for uint256;','mapping(address=>uint256) public credit;','uint256 public totalCredit;',
   'function fund(address recipient,uint256 amount) external {uint256 v=amount.bounded(type(uint128).max);credit[recipient]+=v;totalCredit+=v;}',
   'function settle(address recipient,uint256 amount) external {',
   ' require(msg.sender==operator,"operator only");require(amount>0&&amount<=totalCredit,"bad amount");',
   ' credit[recipient]+=amount;totalCredit-=amount;}','}'),
  'lib/utils/src/AmountMath.sol':join('// SPDX-License-Identifier: MIT','pragma solidity ^0.8.20;',
   'library AmountMath {function bounded(uint256 v,uint256 limit) internal pure returns(uint256){require(v<=limit,"limit");return v;}}'),
  'foundry.toml':'[profile.default]\nsrc = "contracts"\nlibs = ["lib"]\nsolc_version = "0.8.30"\n'
 };
 for(let i=0;i<n-3;i++){
  const cls=title(i);
  files['contracts/modules/'+cls+'.sol']=join('// SPDX-License-Identifier: MIT','pragma solidity ^0.8.20;',
   'contract '+cls+' {','address public administrator;','address public operator;',
   'constructor(){administrator=msg.sender;operator=msg.sender;}',
   'function rotateOperator(address next) external {require(msg.sender==administrator,"admin only");operator=next;}',
   'function settle(address recipient,uint256 amount) external view returns(uint256){',
   'require(msg.sender==operator,"operator only");return amount+uint256(uint160(recipient))%7;}','}');
 }
 return {files,answer:{language:'solidity',file:'contracts/settlement/SettlementAuthority.sol',
  selector:'rotateOperator',caller:'contracts/settlement/SettlementVault.sol',kind:'solidity_sequence',
  defect:'Unrestricted operator rotation enables unauthorized privileged settlement'}};
}
function python(n:number):Fixture {
 const files:Record<string,string>={
  'src/__init__.py':'',
  'src/renderer.py':join('from src.pipeline import wrap_fragment',
   'def render(value):','    return wrap_fragment(value)'),
  'src/pipeline.py':join('from src.codec import encode_fragment',
   'def wrap_fragment(value):','    return "<p>" + encode_fragment(value) + "</p>"'),
  'src/codec.py':join('def encode_fragment(value):','    return value'),
  'src/http_handler.py':join('from src.renderer import render','from urllib.parse import parse_qs, urlsplit',
   'def response_body(url):',
   '    user_text = parse_qs(urlsplit(url).query).get("message", [""])[0]',
   '    return render(user_text)')
 };
 for(let i=0;i<n-4;i++)files['src/modules/'+title(i).toLowerCase()+'.py']=join(
  'from html import escape',
  'def render(value):','    return "<p>" + escape(value, quote=True) + "</p>"',
  'def inspect(value):','    return render(str(value))');
 files['src/modules/__init__.py']='';
 return {files,answer:{language:'python',file:'src/renderer.py',selector:'render',
  caller:'src/http_handler.py',kind:'html_reflection',
  defect:'User-provided markup reaches the HTML response without escaping'}};
}
function javascript(n:number):Fixture {
 const files:Record<string,string>={
  'src/renderer.cjs':join('const {wrapFragment}=require("./pipeline.cjs");',
   'exports.render=function render(value){return wrapFragment(value);};'),
  'src/pipeline.cjs':join('const {encodeFragment}=require("./codec.cjs");',
   'exports.wrapFragment=function wrapFragment(value){return "<p>"+encodeFragment(value)+"</p>";};'),
  'src/codec.cjs':join('exports.encodeFragment=function encodeFragment(value){return value;};'),
  'src/http-handler.cjs':join('const {render}=require("./renderer.cjs");',
   'exports.responseBody=function responseBody(url){',
   'const userText=new URL(url,"http://localhost").searchParams.get("message")||"";',
   'return render(userText);};')
 };
 for(let i=0;i<n-4;i++)files['src/modules/'+title(i).toLowerCase()+'.cjs']=join(
  'exports.render=function render(value){',
  'return "<p>"+value.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")+"</p>";};',
  'exports.inspect=function inspect(value){return exports.render(String(value));};');
 return {files,answer:{language:'javascript',file:'src/renderer.cjs',selector:'render',
  caller:'src/http-handler.cjs',kind:'html_reflection',
  defect:'User-provided markup reaches the HTML response without escaping'}};
}
function java(n:number):Fixture {
 const files:Record<string,string>={
  'src/main/java/org/lotus/Renderer.java':join('package org.lotus;',
   'public class Renderer {','public static String render(String value){return Pipeline.wrapFragment(value);}','}'),
  'src/main/java/org/lotus/Pipeline.java':join('package org.lotus;',
   'public class Pipeline {',
   'public static String wrapFragment(String value){return "<p>"+Codec.encodeFragment(value)+"</p>";}','}'),
  'src/main/java/org/lotus/Codec.java':join('package org.lotus;',
   'public class Codec {','public static String encodeFragment(String value){return value;}','}'),
  'src/main/java/org/lotus/HttpHandler.java':join('package org.lotus;',
   'public class HttpHandler {','public String responseBody(String userInput){return Renderer.render(userInput);}','}')
 };
 for(let i=0;i<n-4;i++){
  const cls=title(i);
  files['src/main/java/org/lotus/modules/'+cls+'.java']=join('package org.lotus.modules;',
   'public class '+cls+' {',
   'public static String render(String value){',
   'return "<p>"+value.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")+"</p>";}',
   'public static String inspect(String value){return render(value);}','}');
 }
 return {files,answer:{language:'java',file:'src/main/java/org/lotus/Renderer.java',
  selector:'Renderer.render',caller:'src/main/java/org/lotus/HttpHandler.java',kind:'html_reflection',
  defect:'User-provided markup reaches the HTML response without escaping'}};
}
export function generate(language:Language,count:number):Fixture {
 if(!Number.isInteger(count)||count<8||count>200)throw Error('Invalid number of source files');
 switch(language){
  case 'solidity':return solidity(count);
  case 'python':return python(count);
  case 'javascript':return javascript(count);
  case 'java':return java(count);
 }
}
