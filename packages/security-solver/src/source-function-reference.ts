/** Remove comments and string contents while preserving offsets and line numbers. */
export function sourceCodeOnly(text:string):string {
  return text.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*|#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`/g,
    token=>token.replace(/[^\n]/g," "));
}
/** A real call expression is evidence to inspect, not proof of exploitability. */
export function referencesProbedFunction(line:string, selector:string):boolean {
  const name = selector.split(".").at(-1)!;
  const code=sourceCodeOnly(line);
  const pattern=new RegExp("(^|[^A-Za-z0-9_$])("+name+")\\s*\\(","g");
  for(const match of code.matchAll(pattern)) {
    const prefix=code.slice(0,match.index!+match[1].length);
    if(!/\b(?:function|def)\s*$/.test(prefix))return true;
  }
  return false;
}
export function callerLineReferences(text:string,line:number,selector:string):boolean {
  const lines=sourceCodeOnly(text).split("\n");
  if(line<1 || line>lines.length)return false;
  // Prefer the exact inspected line. This keeps evidence tied to a real source
  // location while tolerating whitespace and qualified call expressions.
  if(referencesProbedFunction(lines[line-1],selector))return true;
  // A receiver or function name may end a line before the opening parenthesis.
  // Only join a bounded continuation explicitly marked by '.' or a call name;
  // never borrow an unrelated call farther down the file.
  const name=selector.split(".").at(-1)!;
  const first=lines[line-1].trimEnd();
  if(!new RegExp("(?:\\.|\\b"+name+")\\s*$").test(first))return false;
  const continuation=lines.slice(line-1,Math.min(lines.length,line+2)).join("\n");
  return referencesProbedFunction(continuation,selector);
}
/** A fully qualified call is stronger caller evidence than a same-named
 * declaration or an unrelated unqualified invocation. Applicable across
 * Java, Python, JS, and Solidity when a selector has a receiver/type name.
 * This identifies syntax only; reachability and impact still need review.
 */
export function qualifiedCallerLineReferences(text:string,line:number,selector:string):boolean {
  const parts=selector.split(".");
  if(parts.length<2)return false;
  const receiver=parts.at(-2)!;
  const method=parts.at(-1)!;
  if(!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(receiver) ||
     !/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(method))return false;
  const lines=sourceCodeOnly(text).split("\n");
  if(line<1 || line>lines.length)return false;
  const code=lines[line-1];
  const pattern=new RegExp("(^|[^A-Za-z0-9_$])"+receiver+"\\s*\\.\\s*"+method+"\\s*\\(");
  return pattern.test(code);
}
/** The recorded mined send establishes ABI reachability; locate its declaration for review. */
export function transactionEntryLine(text:string,line:number,selector:string):boolean {
  const code=sourceCodeOnly(text), name=selector.split(".").at(-1)!;
  for(const match of code.matchAll(new RegExp("\\bfunction\\s+"+name+"\\s*\\(","g"))) {
    const start=code.slice(0,match.index).split("\n").length;
    const end=start+match[0].split("\n").length-1;
    if(line>=start && line<=end)return true;
  }
  return false;
}
