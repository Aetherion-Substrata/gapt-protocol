// tests/sprint06-fuzz.js -- 0.11.0 grammar fuzz for gapfn.
//
// Generates random gapfn declarations + calls, ensures the lexer, parser, and
// interpreter never throw an uncaught exception. errors[] is the legitimate
// drain for malformed input; anything else is a bug.
//
// Zero deps -- vanilla Math.random. ~10k cases, soft-capped at 10 seconds.

'use strict';

const { GaptLexer }       = require('../src/lexer');
const { GaptParser }      = require('../src/parser');
const { GaptInterpreter } = require('../src/interpreter');

const TARGET_CASES = 10000;
const SOFT_DEADLINE_MS = 10000;

function rand(n) { return Math.floor(Math.random() * n); }
function pick(a) { return a[rand(a.length)]; }
function maybe(p) { return Math.random() < p; }

const IDENTS = ['a','b','c','x','y','z','p','q','foo','bar','baz','sum','mul'];
const NUMBERS = ['0','1','2','5','42','100'];
const STRINGS = ['"k"','"secret"','"top-level"','"auth"','"x"'];

function gExpr(depth) {
  if (depth <= 0 || maybe(0.5)) {
    if (maybe(0.5)) return pick(IDENTS);
    if (maybe(0.5)) return pick(NUMBERS);
    return pick(STRINGS);
  }
  const ops = ['==','!=','<','>','<=','>=','&&','||'];
  return gExpr(depth - 1) + ' ' + pick(ops) + ' ' + gExpr(depth - 1);
}

function gParams() {
  const n = rand(4);
  const seen = new Set();
  const out = [];
  for (let i = 0; i < n; i++) {
    const id = pick(IDENTS);
    if (!seen.has(id)) { out.push(id); seen.add(id); }
  }
  return out.join(', ');
}

function gArgs(maxLen) {
  const n = rand(maxLen + 1);
  const out = [];
  for (let i = 0; i < n; i++) {
    if (maybe(0.5)) out.push(pick(NUMBERS));
    else            out.push(pick(STRINGS));
  }
  if (maybe(0.3)) out.push('as: ' + pick(STRINGS));
  return out.join(', ');
}

function gGapFn(name) {
  const params = gParams();
  const parts = ['gapfn ' + name + '(' + params + ') {'];
  if (maybe(0.5)) parts.push('  guard: ' + gExpr(2));
  if (maybe(0.5)) parts.push('  lock:  ' + gExpr(2));
  if (maybe(0.2)) parts.push('  persist: false');
  // Body is mandatory in our grammar.
  const bodyStmts = [];
  if (maybe(0.6)) bodyStmts.push('    let v = ' + pick(NUMBERS));
  bodyStmts.push('    return ' + (maybe(0.5) ? pick(NUMBERS) : pick(IDENTS)));
  parts.push('  body: {');
  parts.push(bodyStmts.join('\n'));
  parts.push('  }');
  parts.push('}');
  return parts.join('\n');
}

function gCall(name) {
  return name + '(' + gArgs(3) + ')';
}

function gProgram() {
  const lines = [];
  const fnCount = 1 + rand(3);
  const names = [];
  for (let i = 0; i < fnCount; i++) {
    const n = 'fn' + i;
    names.push(n);
    lines.push(gGapFn(n));
  }
  // Wrap calls inside a graph so they execute through send -> edge -> lock pipeline.
  lines.push('graph g {');
  lines.push('  node a {}');
  lines.push('  node b {}');
  lines.push('  edge a -> b {');
  if (maybe(0.7)) lines.push('    lock: ' + gCall(pick(names)));
  if (maybe(0.5)) lines.push('    guard: ' + gExpr(1));
  lines.push('  }');
  // A few sends.
  const sendCount = 1 + rand(3);
  for (let i = 0; i < sendCount; i++) {
    lines.push('  send a -> b { data: {} key: ' + pick(STRINGS) + ' }');
  }
  lines.push('}');
  return lines.join('\n');
}

console.log('\n  SPRINT 06 FUZZ -- gapfn grammar + interpreter');
console.log('  ' + new Array(49).join('='));

const t0 = Date.now();
let cases = 0;
let lexErrors = 0, parseErrors = 0, interpErrors = 0;
let crashes = 0;

while (cases < TARGET_CASES) {
  cases++;
  if ((Date.now() - t0) > SOFT_DEADLINE_MS) break;

  const src = gProgram();
  try {
    const tokens = new GaptLexer(src).tokenise();
    const lex = (tokens && tokens.length > 0);
    if (!lex) lexErrors++;

    const parser = new GaptParser(tokens || []);
    const ast = parser.parse();
    if (parser.errors.length) parseErrors++;

    const ip = new GaptInterpreter();
    ip.execute(ast);
    if (ip.errors.length) interpErrors++;
  } catch (e) {
    // Any uncaught throw is a crash -- this is what fuzzing exists to find.
    crashes++;
    if (crashes <= 3) {
      console.error('  [CRASH] case ' + cases + ': ' + (e && e.message ? e.message : e));
      console.error('  source:\n' + src);
    }
  }
}

const dur = Date.now() - t0;
console.log('  cases: ' + cases + '  duration: ' + dur + 'ms');
console.log('  lex-errors: ' + lexErrors + '  parse-errors: ' + parseErrors + '  interp-errors: ' + interpErrors);
console.log('  CRASHES: ' + crashes);
console.log('  ' + new Array(49).join('='));

if (crashes > 0) {
  console.error('  sprint06-fuzz: FAIL (uncaught exceptions)');
  process.exit(1);
}
console.log('  sprint06-fuzz: PASS (no uncaught exceptions across ' + cases + ' cases)');
console.log('');
