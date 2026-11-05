// sprint19 — corrupted persistence + race + bypass fuzz
// v22 / 2026-05-26

const { GaptGraph } = require('../src/gapt');
const { GaptNetwork } = require('../src/network');
const fs   = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
function wipe() {
  try { for (const f of fs.readdirSync(DATA_DIR)) fs.unlinkSync(path.join(DATA_DIR, f)); } catch (_) {}
}
function corruptFile(name, content) {
  fs.writeFileSync(path.join(DATA_DIR, name), content);
}
function fileName(from, to) {
  return `gap_${from}_${to}.json`.replace(/[^a-z0-9_\.]/gi, '-');
}

console.log('=== sprint19 — corrupted persistence + bypass fuzz ===');
let throws = 0;
let lockdownHeld = true;
let elevatedTrustLeak = false;

// --- Group 1: corrupted persistence ---------------------------------------
console.log('\nGroup 1: corrupted persistence files');
const corruptions = [
  ['invalid-json',  '{not valid json'],
  ['half-object',   '{"passCount": 10, "fai'],
  ['wrong-schema',  '{"completely":"different","schema":true}'],
  ['nul-bytes',     '\0\0\0\0'],
  ['huge-garbage',  'x'.repeat(2 * 1024 * 1024)],
  ['empty-file',    ''],
  ['just-array',    '[1,2,3]'],
];
for (const [name, content] of corruptions) {
  wipe();
  corruptFile(fileName('a', 'b'), content);
  try {
    const g = new GaptGraph();
    g.addNode('a', {}); g.addNode('b', {});
    g.addEdge('a', 'b', { bridgetype: name, voidguard: () => true, edgelock: 'k' });
    const ts = g.edges[0].memory.trustScore;
    console.log(`  ${name.padEnd(14)} trustScore_after_restore=${ts} (expect 0 - corrupt should fail safe)`);
    if (ts > 0) { console.log(`    WARN: corrupt file granted trust!`); elevatedTrustLeak = true; }
  } catch (e) {
    throws++;
    console.log(`  ${name.padEnd(14)} THREW: ${e.message.slice(0, 80)}`);
  }
}

// --- Group 2: schema poisoning -------------------------------------------
console.log('\nGroup 2: schema poisoning (valid JSON, hostile values)');
const poisons = [
  ['trust-max',     { passCount:0, failCount:0, trustScore:999999, trustTier:'VERIFIED', threatLevel:0, locked:false, prediction:{}, patterns:{}, attempts:[] }],
  ['locked-false',  { passCount:0, failCount:1000, trustScore:0, trustTier:'UNKNOWN', threatLevel:10, locked:false, prediction:{}, patterns:{}, attempts:[] }],
  ['neg-count',     { passCount:-1000, failCount:-1000, trustScore:-1, trustTier:'UNKNOWN', threatLevel:0, locked:false, prediction:{}, patterns:{}, attempts:[] }],
  ['huge-attempts', { passCount:0, failCount:0, trustScore:0, trustTier:'UNKNOWN', threatLevel:0, locked:false, prediction:{}, patterns:{}, attempts: new Array(10000).fill({ts:Date.now(), passed:true}) }],
];
for (const [name, snap] of poisons) {
  wipe();
  corruptFile(fileName('a', 'b'), JSON.stringify(snap));
  try {
    const g = new GaptGraph();
    g.addNode('a', {}); g.addNode('b', {});
    g.addEdge('a', 'b', { bridgetype: name, voidguard: (d)=>d&&d.type==='valid', edgelock: 'k' });
    const e = g.edges[0];
    const ts = e.memory.trustScore;
    const locked = e.memory.locked;
    const attemptsLen = e.memory.attempts.length;
    console.log(`  ${name.padEnd(14)} trust=${ts} locked=${locked} attempts.len=${attemptsLen}`);
    // Smoke send: try valid send through poisoned edge
    const r = g.send('a','b',{type:'valid'},'k');
    console.log(`                 smoke send result.passed=${r.passed} reason=${r.reason}`);
    if (name === 'trust-max' && ts > 200) elevatedTrustLeak = true;
  } catch (e) { throws++; console.log(`  ${name.padEnd(14)} THREW: ${e.message.slice(0, 80)}`); }
}

// --- Group 3: lockdown bypass attempts ----------------------------------
console.log('\nGroup 3: lockdown bypass attempts');
wipe();
{
  const g = new GaptGraph();
  g.addNode('a', {}); g.addNode('b', {});
  g.addEdge('a', 'b', { bridgetype: 'lock-test', voidguard:(d)=>d&&d.type==='valid', edgelock:'good-key' });
  // Trigger lockdown
  for (let i = 0; i < 30; i++) {
    try { g.send('a','b',{type:'invalid'},'wrong-' + i); } catch(e){ throws++; }
  }
  const e = g.edges[0];
  console.log(`  pre-bypass: locked=${e.memory.locked} trust=${e.memory.trustScore} threat=${e.memory.threatLevel}`);

  // Bypass A: send with correct key + valid data
  const a = g.send('a','b',{type:'valid'},'good-key');
  if (a.passed) { lockdownHeld = false; console.log(`    BYPASS A SUCCEEDED: ${a.reason}`); }
  else console.log(`    bypass A blocked: ${a.reason}`);

  // Bypass B: try to manually unset locked (no API for this — direct mutation)
  e.memory.locked = false;
  e.memory.trustScore = 100;
  e.memory.trustTier = 'VERIFIED';
  const b = g.send('a','b',{type:'invalid'},'good-key');
  console.log(`    bypass B (manual unlock + invalid data + good key): passed=${b.passed} reason=${b.reason}`);
  // Note: this DOES pass because we mutated internal state - that's expected, demonstrates state needs to be private

  // Bypass C: clearBlocklist via network if attached
  const net = new GaptNetwork();
  net.register(g);
  net.clearBlocklist('attacker-impersonating-system');
  console.log(`    bypass C (clear blocklist by random caller): accepted=true (no auth on clearBlocklist)`);
}

// --- Group 4: inheritance poisoning -------------------------------------
// v26 note: _inheritanceRegistry is now a private class field (#inheritanceRegistry).
// External access via g._inheritanceRegistry returns undefined; assigning into
// undefined throws TypeError. We catch it so the sprint records 'attack surface
// no longer reachable' instead of crashing.
console.log('\nGroup 4: inheritance poisoning');
wipe();
{
  const g = new GaptGraph();
  g.addNode('p', {}); g.addNode('q', {});
  // Pre-seed inheritance registry with attacker-friendly values
  let attackReached = false;
  try {
    g._inheritanceRegistry['p=>q'] = {
      passCount:10000, failCount:0, trustScore:100, trustTier:'VERIFIED',
      threatLevel:0, locked:false, attempts:[],
      prediction:{}, patterns:{},
    };
    attackReached = true;
  } catch (err) {
    console.log(`  attack blocked at property assignment: ${err.message.slice(0, 80)}`);
  }
  g.addEdge('p','q', { bridgetype:'inh-poison', voidguard:(d)=>d&&d.type==='valid', edgelock:'k' });
  const e = g.edges[0];
  console.log(`  attackReached=${attackReached} new-edge: trust=${e.memory.trustScore} tier=${e.memory.trustTier} locked=${e.memory.locked}`);
  if (e.memory.trustScore >= 80) elevatedTrustLeak = true;
}

// --- Group 5: delete data/ mid-run --------------------------------------
console.log('\nGroup 5: delete data/ mid-run');
wipe();
{
  const g = new GaptGraph();
  g.addNode('x', {}); g.addNode('y', {});
  g.addEdge('x','y',{bridgetype:'del-test',voidguard:()=>true,edgelock:'k'});
  g.send('x','y',{type:'valid'},'k');
  // Wipe data dir between sends
  try { for (const f of fs.readdirSync(DATA_DIR)) fs.unlinkSync(path.join(DATA_DIR, f)); } catch(_){}
  try {
    const r = g.send('x','y',{type:'valid'},'k');
    console.log(`  send after wipe: passed=${r.passed} reason=${r.reason}`);
  } catch (e) { throws++; console.log(`  send after wipe THREW: ${e.message.slice(0, 80)}`); }
  // And again after rmdir entirely
  try { fs.rmdirSync(DATA_DIR); } catch (_){}
  try {
    const r = g.send('x','y',{type:'valid'},'k');
    console.log(`  send after rmdir: passed=${r.passed} reason=${r.reason}`);
  } catch (e) { throws++; console.log(`  send after rmdir THREW: ${e.message.slice(0, 80)}`); }
}

console.log('\n=== summary ===');
console.log(`throws:              ${throws}`);
console.log(`lockdownHeld:        ${lockdownHeld}`);
console.log(`elevatedTrustLeak:   ${elevatedTrustLeak}`);

const ok = throws === 0;
console.log(`result:              ${ok ? 'PASS (informational - findings logged)' : 'FAIL'}`);
process.exit(ok ? 0 : 1);
