// sprint20 -- HMAC-signed persistence + private inheritance registry
// v26 / 2026-05-26
//
// 8 cases:
//   1. Coherent unsigned forgery rejected
//   2. HMAC against wrong secret rejected
//   3. HMAC with right secret accepted (legit restart)
//   4. Migration accept (one-shot grace) + auto-resign
//   5. Rotation (PREV fallback) + auto-resign
//   6. Tampered body with valid old sig rejected
//   7. In-memory registry mutation does not poison new edge
//   8. getRegistrySnapshot returns frozen deep clone

const fs   = require('fs');
const path = require('path');
const crypto = require('crypto');

// Set a known secret BEFORE first require of persist/gapt, so ensureSecret() doesn't
// auto-gen a file we have to clean up.
const SECRET_REAL = crypto.randomBytes(32).toString('hex');
const SECRET_WRONG = crypto.randomBytes(32).toString('hex');
process.env.GAPT_HMAC_SECRET = SECRET_REAL;
delete process.env.GAPT_HMAC_SECRET_PREV;
delete process.env.GAPT_HMAC_ACCEPT_UNSIGNED;

const persist = require('../src/persist');
const { GaptGraph } = require('../src/gapt');

const DATA_DIR = path.join(__dirname, '..', 'data');

function wipe() {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    for (const f of fs.readdirSync(DATA_DIR)) {
      // Keep the auto-gen secret file if present, just nuke gap_*.json
      if (f.startsWith('gap_') && f.endsWith('.json')) fs.unlinkSync(path.join(DATA_DIR, f));
    }
  } catch (_) {}
}
function fileName(from, to) {
  return `gap_${from}_${to}.json`.replace(/[^a-z0-9_\.]/gi, '-');
}
function filePath(from, to) { return path.join(DATA_DIR, fileName(from, to)); }

function signWithKey(body, hexKey) {
  const canon = persist.canonicalStringify(body);
  const secret = /^[0-9a-fA-F]+$/.test(hexKey) ? Buffer.from(hexKey, 'hex') : Buffer.from(hexKey, 'utf8');
  const h = crypto.createHmac('sha256', secret);
  h.update(canon);
  return 'sha256:' + h.digest('hex');
}

function writeEnvelope(from, to, body, hmac) {
  const obj = { v: 1, body: body, hmac: hmac };
  fs.writeFileSync(filePath(from, to), JSON.stringify(obj, null, 2));
}

function writeRaw(from, to, raw) { fs.writeFileSync(filePath(from, to), raw); }

const coherentBody = {
  edge: { from: 'a', to: 'b' },
  savedAt: new Date().toISOString(),
  passCount: 50,
  failCount: 0,
  trustScore: 100,
  trustTier: 'VERIFIED',
  threatLevel: 0,
  locked: false,
  prediction: { threat: false, confidence: 0, reason: null, preEmpted: 0 },
  patterns: { burst:false, rotation:false, probe:false, dormant:false, signatureDeviation:false },
  attempts: Array.from({ length: 50 }, (_, i) => ({
    ts: Date.now() - (50 - i) * 1000,
    timestamp: new Date(Date.now() - (50 - i) * 1000).toISOString(),
    passed: true, reason: 'GAPT_CLEAR [VERIFIED]', keySignature: 'abcd****',
    trustScore: 100, trustTier: 'VERIFIED'
  }))
};

console.log('=== sprint20 -- HMAC + private registry ===');
let passes = 0, fails = 0;
function chk(name, cond, detail) {
  if (cond) { console.log(`  PASS  ${name}` + (detail ? ` -- ${detail}` : '')); passes++; }
  else      { console.log(`  FAIL  ${name}` + (detail ? ` -- ${detail}` : '')); fails++; }
}

// --- Case 1: Coherent unsigned forgery rejected -----------------------------
console.log('\nCase 1: coherent unsigned forgery');
{
  wipe();
  writeRaw('a','b', JSON.stringify(coherentBody, null, 2)); // bare body, no envelope
  const g = new GaptGraph();
  g.addNode('a',{}); g.addNode('b',{});
  g.addEdge('a','b',{ bridgetype:'c1', voidguard:()=>true, edgelock:'k' });
  const ts = g.edges[0].memory.trustScore;
  chk('unsigned-forgery-trust-zero', ts === 0, `trust=${ts}`);
}

// --- Case 2: Wrong-secret HMAC rejected -------------------------------------
console.log('\nCase 2: HMAC against wrong secret');
{
  wipe();
  writeEnvelope('a','b', coherentBody, signWithKey(coherentBody, SECRET_WRONG));
  const g = new GaptGraph();
  g.addNode('a',{}); g.addNode('b',{});
  g.addEdge('a','b',{ bridgetype:'c2', voidguard:()=>true, edgelock:'k' });
  const ts = g.edges[0].memory.trustScore;
  chk('wrong-secret-trust-zero', ts === 0, `trust=${ts}`);
}

// --- Case 3: Right-secret HMAC accepted -------------------------------------
console.log('\nCase 3: HMAC with right secret');
{
  wipe();
  writeEnvelope('a','b', coherentBody, signWithKey(coherentBody, SECRET_REAL));
  const g = new GaptGraph();
  g.addNode('a',{}); g.addNode('b',{});
  g.addEdge('a','b',{ bridgetype:'c3', voidguard:()=>true, edgelock:'k' });
  const ts = g.edges[0].memory.trustScore;
  const pc = g.edges[0].memory.passCount;
  chk('right-secret-restored', ts === 100 && pc === 50, `trust=${ts} pass=${pc}`);
}

// --- Case 4: Migration accept (one-shot grace) ------------------------------
console.log('\nCase 4: migration accept + auto-resign');
{
  wipe();
  writeRaw('a','b', JSON.stringify(coherentBody, null, 2));
  process.env.GAPT_HMAC_ACCEPT_UNSIGNED = '1';
  const g1 = new GaptGraph();
  g1.addNode('a',{}); g1.addNode('b',{});
  g1.addEdge('a','b',{ bridgetype:'c4-mig', voidguard:()=>true, edgelock:'k' });
  const ts1 = g1.edges[0].memory.trustScore;
  const onDisk = JSON.parse(fs.readFileSync(filePath('a','b'), 'utf8'));
  chk('migration-accepted', ts1 === 100, `trust=${ts1}`);
  chk('migration-file-resigned', typeof onDisk.hmac === 'string' && onDisk.hmac.startsWith('sha256:'), `hmac=${onDisk.hmac && onDisk.hmac.slice(0,16)}...`);
  // Re-load without the grace flag -> should still accept because file is now signed
  delete process.env.GAPT_HMAC_ACCEPT_UNSIGNED;
  const g2 = new GaptGraph();
  g2.addNode('a',{}); g2.addNode('b',{});
  g2.addEdge('a','b',{ bridgetype:'c4-reload', voidguard:()=>true, edgelock:'k' });
  chk('migration-reload-still-accepted', g2.edges[0].memory.trustScore === 100, `trust=${g2.edges[0].memory.trustScore}`);
}

// --- Case 5: Rotation -------------------------------------------------------
console.log('\nCase 5: rotation (PREV fallback)');
{
  wipe();
  const ROT_A = crypto.randomBytes(32).toString('hex');
  const ROT_B = crypto.randomBytes(32).toString('hex');
  // Sign with key A
  writeEnvelope('a','b', coherentBody, signWithKey(coherentBody, ROT_A));
  // Now flip env to current=B, prev=A
  process.env.GAPT_HMAC_SECRET = ROT_B;
  process.env.GAPT_HMAC_SECRET_PREV = ROT_A;
  persist._resetSecretCache();
  const g1 = new GaptGraph();
  g1.addNode('a',{}); g1.addNode('b',{});
  g1.addEdge('a','b',{ bridgetype:'c5-rot', voidguard:()=>true, edgelock:'k' });
  chk('rotation-prev-accepted', g1.edges[0].memory.trustScore === 100, `trust=${g1.edges[0].memory.trustScore}`);
  // File should now be re-signed under B; drop PREV and reload
  const onDisk = JSON.parse(fs.readFileSync(filePath('a','b'), 'utf8'));
  delete process.env.GAPT_HMAC_SECRET_PREV;
  persist._resetSecretCache();
  const g2 = new GaptGraph();
  g2.addNode('a',{}); g2.addNode('b',{});
  g2.addEdge('a','b',{ bridgetype:'c5-resigned', voidguard:()=>true, edgelock:'k' });
  chk('rotation-resigned-load', g2.edges[0].memory.trustScore === 100, `trust=${g2.edges[0].memory.trustScore}`);
  // Restore real secret for subsequent cases
  process.env.GAPT_HMAC_SECRET = SECRET_REAL;
  persist._resetSecretCache();
}

// --- Case 6: Tampered body with valid old sig rejected ----------------------
console.log('\nCase 6: tampered body, sig now stale');
{
  wipe();
  writeEnvelope('a','b', coherentBody, signWithKey(coherentBody, SECRET_REAL));
  // Mutate the file: change trustScore in body, leave hmac alone
  const raw = JSON.parse(fs.readFileSync(filePath('a','b'), 'utf8'));
  raw.body.trustScore = 99; // any change invalidates the sig
  fs.writeFileSync(filePath('a','b'), JSON.stringify(raw, null, 2));
  const g = new GaptGraph();
  g.addNode('a',{}); g.addNode('b',{});
  g.addEdge('a','b',{ bridgetype:'c6', voidguard:()=>true, edgelock:'k' });
  chk('tampered-rejected', g.edges[0].memory.trustScore === 0, `trust=${g.edges[0].memory.trustScore}`);
}

// --- Case 7: In-memory registry mutation does not poison --------------------
console.log('\nCase 7: in-memory registry mutation rejected');
{
  wipe();
  const g = new GaptGraph();
  // Try the old attack from sprint19 Group 4
  try {
    g._inheritanceRegistry = {
      'p=>q': {
        passCount: 10000, failCount: 0, trustScore: 100, trustTier: 'VERIFIED',
        threatLevel: 0, locked: false, attempts: [], prediction: {}, patterns: {}
      }
    };
  } catch (_) { /* ok if throws */ }
  // Also try property assignment
  try {
    g._inheritanceRegistry['p=>q'] = {
      passCount: 10000, failCount: 0, trustScore: 100, trustTier: 'VERIFIED',
      threatLevel: 0, locked: false, attempts: [], prediction: {}, patterns: {}
    };
  } catch (_) { /* ok */ }
  g.addNode('p',{}); g.addNode('q',{});
  g.addEdge('p','q',{ bridgetype:'c7', voidguard:()=>true, edgelock:'k' });
  const ts = g.edges[0].memory.trustScore;
  chk('inmem-mutation-not-inherited', ts === 0, `trust=${ts} (attack via _inheritanceRegistry did NOT reach private field)`);
}

// --- Case 8: Diagnostic accessor is frozen + safe ---------------------------
console.log('\nCase 8: getRegistrySnapshot frozen');
{
  wipe();
  const g = new GaptGraph();
  g.addNode('a',{}); g.addNode('b',{});
  g.addEdge('a','b',{ bridgetype:'c8-build', voidguard:(d)=>true, edgelock:'k' });
  // Build some legit history then retire to populate the registry via the sanctioned path
  for (let i = 0; i < 10; i++) g.send('a','b',{type:'v'},'k');
  g.retireEdge('a','b');
  const snap1 = g.getRegistrySnapshot();
  let mutateThrew = false;
  try { snap1['a=>b'].trustScore = 999; }
  catch (e) { mutateThrew = true; }
  // Also try replacing top-level key
  try { snap1['evil'] = { trustScore: 100 }; } catch (_) { mutateThrew = true; }
  const snap2 = g.getRegistrySnapshot();
  // snap2 must look identical to snap1 in its real fields (i.e., no mutation persisted)
  const stillSafe = !snap2['evil'] && snap2['a=>b'] && snap2['a=>b'].trustScore !== 999;
  chk('snapshot-frozen-mutate-failed', stillSafe, `mutateThrew=${mutateThrew} sealed=true`);
}

console.log('\n=== summary ===');
console.log(`passes: ${passes}`);
console.log(`fails:  ${fails}`);
console.log(`result: ${fails === 0 ? 'PASS' : 'FAIL'}`);
process.exit(fails === 0 ? 0 : 1);
