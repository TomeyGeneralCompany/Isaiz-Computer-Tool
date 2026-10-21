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
  return referencesProbedFunction(sourceCodeOnly(text).split("\n")[line-1] || "",selector);
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
