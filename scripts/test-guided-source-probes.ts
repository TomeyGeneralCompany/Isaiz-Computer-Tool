import assert from 'node:assert/strict';
import {guidedSourceProbe} from '../packages/security-solver/src/source-guided-probes';

const raw='def unrelated(value):\n    return value.upper()\n\ndef render_page(value):\n    return "<p>" + value + "</p>"\n';
const escaped='import html\n\ndef render_safe(value):\n    return "<p>" + html.escape(value) + "</p>"\n';
assert.equal(guidedSourceProbe('fixture.py',raw)?.functionName,'render_page');
assert.equal(guidedSourceProbe('safe.py',escaped)?.functionName,'render_safe');
assert.equal(guidedSourceProbe('other.py','def transform(value):\n    return value.upper()\n'),null);
assert.equal(guidedSourceProbe('../escape.py','def f(value):\n    return "<p>"+value+"</p>"\n')?.functionName,'f');
// Caller still enforces the real workspace boundary and isolated probe eligibility.
assert.equal(guidedSourceProbe('output.json',raw),null);
assert.equal(guidedSourceProbe('function.py','@decorator\ndef f(v,w):\n    return "<p>"+v+"</p>"\n'),null);
assert.equal(guidedSourceProbe('src/Render.java',
  'public class Render { public static String render(String value) { return "<p>" + value + "</p>"; }}')?.functionName,'Render.render');
assert.equal(guidedSourceProbe('src/Render.java',
  'public class Render { public String render(String value) { return "<p>" + value + "</p>"; }}')?.functionName,'Render.render');
assert.equal(guidedSourceProbe('src/Render.java',
  'public class Render { public static String render(String value) { return value; }}'),null);
assert.equal(guidedSourceProbe('src/render.cjs',
  'exports.render = x => "<p>"+x+"</p>";')?.functionName,'render');
assert.equal(guidedSourceProbe('src/renderer.mjs',
  'export const render = (value) => "<p>" + value + "</p>";')?.functionName,'render');
assert.equal(guidedSourceProbe('src/render.cjs',
  'exports.render = x => x.toUpperCase();'),null);
console.log('Bounded source-guided function selection PASSED');
