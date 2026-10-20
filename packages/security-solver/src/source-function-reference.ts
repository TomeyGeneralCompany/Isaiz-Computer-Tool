/** A caller reference is evidence to inspect, not proof of runtime reachability. */
export function referencesProbedFunction(line:string, selector:string):boolean {
  const name = selector.split(".").at(-1)!;
  // Selectors have already passed the identifier-only reproduction schema.
  return new RegExp("(^|[^A-Za-z0-9_$])"+name+"\\s*\\(").test(line);
}
