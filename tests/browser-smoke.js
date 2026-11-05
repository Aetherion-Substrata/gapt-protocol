// tests/browser-smoke.js
// Verifies dist/gapt.browser.js loads in a browser-like sandbox and exposes
// the documented API surface.
//
// Sandbox discipline: the VM context exposes ONLY browser-safe globals.
// fs / crypto / process / Buffer / require / __dirname / __filename are NOT
// available. If the bundle secretly depends on a Node-only API, this test
// crashes -- which is the point.

'use strict';

const fs   = require('fs');
const path = require('path');
const vm   = require('vm');

const bundlePath = path.join(__dirname, '..', 'dist', 'gapt.browser.js');
if (!fs.existsSync(bundlePath)) {
  console.error('  [smoke] dist/gapt.browser.js not found. Run: npm run build:browser');
  process.exit(1);
}
const bundleSrc = fs.readFileSync(bundlePath, 'utf8');

// Browser-safe globals only. process/Buffer/require deliberately omitted.
const fakeWindow = {};
const sandbox = {
  window:   fakeWindow,
  console:  console,
  Date, Math, JSON, Map, Set, WeakSet, WeakMap,
  Array, Object, String, Number, Boolean,
  Error, TypeError, RangeError, Symbol, BigInt, RegExp, Promise,
  Uint8Array, ArrayBuffer,
  setTimeout, clearTimeout, setInterval, clearInterval,
  parseInt, parseFloat, isNaN, isFinite,
};
sandbox.globalThis = sandbox;

const ctx = vm.createContext(sandbox);
try {
  vm.runInContext(bundleSrc, ctx, { filename: 'gapt.browser.js' });
} catch (e) {
  console.error('  [smoke] bundle threw on load: ' + e.message);
  console.error(e.stack);
  process.exit(1);
}

const Gapt = fakeWindow.Gapt;
if (!Gapt) {
  console.error('  [smoke] window.Gapt not defined after bundle load');
  process.exit(1);
}

let pass = 0, fail = 0;
function ok(cond, msg) {
  if (cond) { pass++; console.log('  [PASS] ' + msg); }
  else      { fail++; console.error('  [FAIL] ' + msg); }
}

console.log('');
console.log('  GAPT browser-smoke v' + Gapt.version);
console.log('  ' + new Array(49).join('='));

// ---------- 1. surface shape ----------
ok(typeof Gapt.GaptGraph === 'function',          'GaptGraph is a constructor');
ok(typeof Gapt.GaptEdge === 'function',           'GaptEdge is a constructor');
ok(typeof Gapt.GaptMemory === 'function',         'GaptMemory is a constructor');
ok(typeof Gapt.GaptFingerprint === 'function',    'GaptFingerprint is a constructor');
ok(typeof Gapt.GaptNetwork === 'function',        'GaptNetwork is a constructor');
ok(typeof Gapt.GaptLexer === 'function',          'GaptLexer is a constructor');
ok(typeof Gapt.GaptParser === 'function',         'GaptParser is a constructor');
ok(typeof Gapt.GaptInterpreter === 'function',    'GaptInterpreter is a constructor');
ok(typeof Gapt.getTrustTier === 'function',       'getTrustTier is callable');
ok(typeof Gapt.DEFAULT_TRUST_CONFIG === 'object', 'DEFAULT_TRUST_CONFIG is an object');
ok(typeof Gapt.TOKEN_TYPES === 'object',          'TOKEN_TYPES is an object');
ok(typeof Gapt.version === 'string',              'version is a string');

// ---------- 2. happy-path transmit ----------
const g = new Gapt.GaptGraph();
g.addNode('user',  {});
g.addNode('vault', {});
g.addEdge('user', 'vault', {
  bridgetype: 'vault-access',
  voidguard:  function (d) { return d && d.type === 'valid'; },
  edgelock:   'my-secret'
});
const r = g.send('user', 'vault', { type: 'valid' }, 'my-secret');
ok(r.passed === true,            'happy-path transmit passes');
ok(/^GAPT_CLEAR/.test(r.reason), 'reason is GAPT_CLEAR (got: ' + r.reason + ')');

// ---------- 3. lockdown after sustained fails ----------
const g2 = new Gapt.GaptGraph();
g2.addNode('a', {});
g2.addNode('b', {});
g2.addEdge('a', 'b', {
  bridgetype: 't',
  voidguard:  function () { return true; },
  edgelock:   'real-key'
});
for (let i = 0; i < 6; i++) g2.send('a', 'b', { type: 'x' }, 'wrong-' + i);
const stat = g2.gapStatus('a', 'b');
ok(stat.locked === true,    'edge locked after 6 wrong keys (locked=' + stat.locked + ')');
ok(stat.threatLevel === 3,  'threatLevel reached 3 (got: ' + stat.threatLevel + ')');

// ---------- 4. GaptNetwork wiring ----------
const net = new Gapt.GaptNetwork({ propagationRadius: 1 });
ok(typeof net.register === 'function', 'GaptNetwork has .register');
ok(typeof net.setPropagationRadius === 'function', 'GaptNetwork has .setPropagationRadius');

// ---------- 5. .gapt language pipeline ----------
const langSource = [
  'graph demo {',
  '  node a { role: "x" }',
  '  node b { role: "y" }',
  '  edge a -> b { guard: data.type == "ok"  lock: key == "k" }',
  '  send a -> b { data: { type: "ok" }  key: "k" }',
  '}'
].join('\n');

const lex = new Gapt.GaptLexer(langSource);
const toks = lex.tokenise();
ok(lex.errors.length === 0, 'lexer no errors (got ' + lex.errors.length + ')');
ok(toks.length > 0,         'tokens produced (' + toks.length + ')');

const par = new Gapt.GaptParser(toks);
const ast = par.parse();
ok(par.errors.length === 0, 'parser no errors (got ' + par.errors.length + ')');

const ip = new Gapt.GaptInterpreter();
const results = ip.execute(ast);
ok(Array.isArray(results),                           'interpreter returns array');
ok(results.length === 1,                             'one transmit result (got ' + results.length + ')');
ok(results[0] && results[0].passed === true,        'lang-driven send passed');

console.log('  ' + new Array(49).join('='));
console.log('  browser-smoke: ' + pass + ' PASS / ' + fail + ' FAIL');
console.log('');

if (fail > 0) process.exit(1);
