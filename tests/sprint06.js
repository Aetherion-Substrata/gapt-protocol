// tests/sprint06.js -- 0.11.0 lang-v3: holographic gapfn
//
// Each gapfn is a one-edge GaptGraph under the hood. Every call routes through
// GaptEdge.transmit(), so the same threat/trust/lockdown machinery that defends
// edges defends functions. The function IS a gap.
//
// 13 cases. Exits non-zero on first FAIL.

'use strict';

const fs   = require('fs');
const path = require('path');
const { GaptLexer }       = require('../src/lexer');
const { GaptParser }      = require('../src/parser');
const { GaptInterpreter } = require('../src/interpreter');

let pass = 0, fail = 0;
function ok(cond, msg) {
  if (cond) { pass++; console.log('  [PASS] ' + msg); }
  else      { fail++; console.error('  [FAIL] ' + msg); }
}

function run(source) {
  const tokens = new GaptLexer(source).tokenise();
  const ast    = new GaptParser(tokens).parse();
  const interp = new GaptInterpreter();
  interp.execute(ast);
  return interp;
}

console.log('\n  SPRINT 06 -- holographic gapfn (0.11.0)');
console.log('  ' + new Array(49).join('='));

// ---------- 1. declare + call returns body value ----------
{
  const ip = run([
    'gapfn add(a, b) { body: { return a } }',
  ].join('\n'));
  // Call via a synthetic graph that uses add() as a lock-expr trigger.
  const r = ip._callGapFn('add', [42, 1], 'tester');
  ok(r === 42, '1. simple gapfn returns body value (got ' + r + ')');
}

// ---------- 2. guard rejects bad args ----------
{
  const ip = run([
    'gapfn small(n) {',
    '  guard: n < 100',
    '  body:  { return n }',
    '}',
  ].join('\n'));
  const okR  = ip._callGapFn('small', [5],   'tester');
  const badR = ip._callGapFn('small', [500], 'tester');
  ok(okR === 5,      '2a. guard passes good arg (got ' + okR + ')');
  ok(badR === null,  '2b. guard rejects bad arg (got ' + badR + ')');
  const st = ip.fnStatus('small');
  ok(st.failCount === 1, '2c. failed call increments failCount (got ' + st.failCount + ')');
}

// ---------- 3. lock rejects wrong caller ----------
{
  const ip = run([
    'gapfn authOnly() {',
    '  lock: caller == "auth-flow"',
    '  body: { return 1 }',
    '}',
  ].join('\n'));
  const wrongR = ip._callGapFn('authOnly', [], 'attacker');
  const rightR = ip._callGapFn('authOnly', [], 'auth-flow');
  ok(wrongR === null, '3a. lock rejects wrong caller (got ' + wrongR + ')');
  ok(rightR === 1,    '3b. lock passes correct caller (got ' + rightR + ')');
}

// ---------- 4. 4-of-5 fails -> locked ----------
{
  const ip = run([
    'gapfn protected() {',
    '  lock: caller == "right"',
    '  body: { return 1 }',
    '}',
  ].join('\n'));
  for (let i = 0; i < 5; i++) ip._callGapFn('protected', [], 'wrong-' + i);
  const st = ip.fnStatus('protected');
  ok(st.locked === true,    '4a. gapfn locked after 5 wrong callers (locked=' + st.locked + ')');
  ok(st.threatLevel === 3,  '4b. threatLevel reached 3 (got ' + st.threatLevel + ')');
  const after = ip._callGapFn('protected', [], 'right');
  ok(after === null, '4c. even correct caller blocked while locked (got ' + after + ')');
}

// ---------- 5. trust climbs, tier reaches FAMILIAR ----------
{
  const ip = run([
    'gapfn quiet() { body: { return 1 } }',
  ].join('\n'));
  for (let i = 0; i < 12; i++) ip._callGapFn('quiet', [], 'tester');
  const st = ip.fnStatus('quiet');
  ok(st.trustScore >= 20,         '5a. trustScore climbed past 20 (got ' + st.trustScore + ')');
  ok(st.trustTier === 'FAMILIAR', '5b. tier reached FAMILIAR (got ' + st.trustTier + ')');
}

// ---------- 6. closure reads let-bound value ----------
{
  const ip = run([
    'let pin = "1234"',
    'gapfn checkPin(input) {',
    '  body: { return input == pin }',
    '}',
  ].join('\n'));
  const r = ip._callGapFn('checkPin', ['1234'], 'tester');
  ok(r === true, '6. fn body reads let-bound top-level value (got ' + r + ')');
}

// ---------- 7. local let stays local (does NOT leak to top-level scope) ----------
{
  const ip = run([
    'gapfn leakTest() {',
    '  let secret = "shh"',
    '  body: { return 1 }',
    '}',
  ].join('\n'));
  ip._callGapFn('leakTest', [], 'tester');
  ok(!('secret' in ip.scope), '7. local let inside fn body does NOT leak to top-level scope');
}

// ---------- 8. recursion safety net ----------
{
  const ip = run([
    'gapfn loop() { body: { return loop() } }',
  ].join('\n'));
  // Always-passing recursion would crash stack without the safety net.
  const r = ip._callGapFn('loop', [], 'tester');
  ok(r === null, '8a. infinite recursion returns null instead of stack overflow');
  const err = ip.errors.find(e => /call depth/.test(e));
  ok(!!err, '8b. errors[] records GAPT_CALL_DEPTH_LIMIT (got ' + (err ? 'yes' : 'no') + ')');
}

// ---------- 9. fnStatus shape ----------
{
  const ip = run([
    'gapfn target(x) { body: { return x } }',
  ].join('\n'));
  ip._callGapFn('target', [1], 'tester');
  const st = ip.fnStatus('target');
  ok(st.name === 'target',                '9a. fnStatus.name');
  ok(Array.isArray(st.params),            '9b. fnStatus.params is array');
  ok(typeof st.passCount === 'number',    '9c. fnStatus.passCount');
  ok(typeof st.trustScore === 'number',   '9d. fnStatus.trustScore');
  ok(typeof st.threatLevel === 'number',  '9e. fnStatus.threatLevel');
  ok(typeof st.locked === 'boolean',      '9f. fnStatus.locked');
  ok(ip.fnStatus('does-not-exist') === null, '9g. fnStatus returns null for unknown fn');
}

// ---------- 10. fnReset clears lock and rebases trust ----------
{
  const ip = run([
    'gapfn protected2() {',
    '  lock: caller == "right"',
    '  body: { return 1 }',
    '}',
  ].join('\n'));
  for (let i = 0; i < 5; i++) ip._callGapFn('protected2', [], 'wrong-' + i);
  ok(ip.fnStatus('protected2').locked === true, '10a. locked before reset');
  const okR = ip.fnReset('protected2', 'audit-team');
  ok(okR === true,                                '10b. fnReset returns true');
  ok(ip.fnStatus('protected2').locked === false, '10c. unlocked after reset');
  const after = ip._callGapFn('protected2', [], 'right');
  ok(after === 1, '10d. correct caller can call after reset (got ' + after + ')');
}

// ---------- 11. two gapfns track independently ----------
{
  const ip = run([
    'gapfn fnA() { lock: caller == "a-caller"  body: { return "a" } }',
    'gapfn fnB() { lock: caller == "b-caller"  body: { return "b" } }',
  ].join('\n'));
  // Attack fnA only.
  for (let i = 0; i < 5; i++) ip._callGapFn('fnA', [], 'wrong-' + i);
  const stA = ip.fnStatus('fnA');
  const stB = ip.fnStatus('fnB');
  ok(stA.locked === true,  '11a. fnA locked');
  ok(stB.locked === false, '11b. fnB unaffected by fnA attacks');
  // fnB still works.
  const r = ip._callGapFn('fnB', [], 'b-caller');
  ok(r === 'b', '11c. fnB still callable (got ' + r + ')');
}

// ---------- 12. gapfn used as edge lock: composition ----------
{
  const ip = run([
    'let secret = "k"',
    'gapfn isOk(k) { body: { return k == secret } }',
    'graph g {',
    '  node user {}',
    '  node vault {}',
    '  edge user -> vault {',
    '    lock: isOk(key)',
    '  }',
    '  send user -> vault { data: {} key: "k" }',
    '  send user -> vault { data: {} key: "wrong" }',
    '}',
  ].join('\n'));
  ok(ip.results.length === 2,             '12a. two sends executed (got ' + ip.results.length + ')');
  ok(ip.results[0].passed === true,       '12b. first send passes via gapfn lock');
  ok(ip.results[1].passed === false,      '12c. second send fails via gapfn lock');
  // The gapfn isOk should itself have stats recorded.
  const st = ip.fnStatus('isOk');
  ok(st.passCount + st.failCount === 2,   '12d. gapfn recorded both invocations (got ' + (st.passCount + st.failCount) + ')');
}

// ---------- 13. persist:true survives reload ----------
{
  const DATA_DIR = path.join(__dirname, '..', 'data');
  const FILE = path.join(DATA_DIR, 'gap___fn_persistedFn.json');
  // Clean slate before this case.
  if (fs.existsSync(FILE)) fs.unlinkSync(FILE);

  // First process: declare, call (passes), file should be written.
  const ip1 = run([
    'gapfn persistedFn() {',
    '  persist: true',
    '  body: { return 1 }',
    '}',
  ].join('\n'));
  ip1._callGapFn('persistedFn', [], 'tester');
  ok(fs.existsSync(FILE), '13a. persist:true wrote disk snapshot to ' + path.basename(FILE));

  // Second "process": fresh interpreter. autoRestore via GaptGraph should
  // restore the memory from the HMAC-signed envelope.
  const ip2 = run([
    'gapfn persistedFn() {',
    '  persist: true',
    '  body: { return 1 }',
    '}',
  ].join('\n'));
  const st = ip2.fnStatus('persistedFn');
  ok(st.passCount >= 1, '13b. restored passCount >= 1 in fresh interp (got ' + st.passCount + ')');

  // Cleanup.
  if (fs.existsSync(FILE)) fs.unlinkSync(FILE);
}

console.log('  ' + new Array(49).join('='));
console.log('  sprint06: ' + pass + ' PASS / ' + fail + ' FAIL');
console.log('');

if (fail > 0) process.exit(1);
