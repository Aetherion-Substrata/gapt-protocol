
// v06 patch: defensive safe-stringify for snapshots
function _gaptSafeStringifyP(v, indent) {
  const seen = new WeakSet();
  try {
    return JSON.stringify(v, function (k, val) {
      if (typeof val === 'bigint') return val.toString() + 'n';
      if (typeof val === 'symbol') return val.toString();
      if (typeof val === 'function') return '[Function]';
      if (val instanceof Map) return { __map__: Array.from(val.entries()) };
      if (val instanceof Set) return { __set__: Array.from(val.values()) };
      if (typeof val === 'object' && val !== null) {
        if (seen.has(val)) return '[Circular]';
        seen.add(val);
      }
      return val;
    }, indent);
  } catch (e) {
    return '"[Unserializable: ' + (e && e.message ? e.message : String(e)) + ']"';
  }
}

// ============================================
// GAPT - Persistence Layer v0.2 (v26: HMAC-signed)
// Gap memory survives restarts; snapshots are tamper-evident.
// ============================================

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

// GAPT_DATA_DIR env var lets serverless/read-only environments redirect
// persist writes to a writable path (e.g. /tmp on Vercel lambdas).
const DATA_DIR = process.env.GAPT_DATA_DIR || path.join(__dirname, '../data');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// ---------- HMAC helpers (v26) ----------

const SECRET_FILE = path.join(DATA_DIR, '.gapt-hmac-secret');
let _secretCache = null;
let _secretPrevCache = null;

// v34: multi-replica HMAC handshake state. One-shot per process so we don't
// re-stat the handshake file on every persist call.
const HANDSHAKE_FILE = path.join(DATA_DIR, '.gapt-handshake.json');
let _handshakeChecked = false;
let _handshakeResult  = null;


function ensureSecret() {
  // Allow tests to invalidate the cache by setting _gapt_hmac_secret_reset on the module.
  // Otherwise we read env once per process.
  if (_secretCache !== null) return _secretCache;

  const envHex = process.env.GAPT_HMAC_SECRET;
  if (envHex && envHex.length >= 32) {
    _secretCache = Buffer.from(envHex, /^[0-9a-fA-F]+$/.test(envHex) ? 'hex' : 'utf8');
    return _secretCache;
  }

  // Auto-gen fallback to data/.gapt-hmac-secret
  try {
    if (fs.existsSync(SECRET_FILE)) {
      const raw = fs.readFileSync(SECRET_FILE);
      if (raw && raw.length >= 16) {
        _secretCache = raw;
        return _secretCache;
      }
    }
    const gen = crypto.randomBytes(32);
    fs.writeFileSync(SECRET_FILE, gen, { mode: 0o600 });
    console.warn('\n*** GAPT SECURITY WARNING *****************************************************');
    console.warn(' HMAC secret auto-generated at:');
    console.warn('   ' + SECRET_FILE);
    console.warn(' This is OK for development. In production, set GAPT_HMAC_SECRET in the');
    console.warn(' environment instead -- env-var is the documented audit boundary. Anyone');
    console.warn(' with read access to the file above can forge signatures.');
    console.warn(' To generate a key for the env var:');
    console.warn('   node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    console.warn('*******************************************************************************\n');
    _secretCache = gen;
    return _secretCache;
  } catch (err) {
    throw new Error('GAPT_HMAC_SECRET unavailable: ' + err.message);
  }
}

function getPrevSecret() {
  if (_secretPrevCache !== null) return _secretPrevCache;
  const envHex = process.env.GAPT_HMAC_SECRET_PREV;
  if (envHex && envHex.length >= 32) {
    _secretPrevCache = Buffer.from(envHex, /^[0-9a-fA-F]+$/.test(envHex) ? 'hex' : 'utf8');
    return _secretPrevCache;
  }
  _secretPrevCache = false; // sentinel: checked, none set
  return _secretPrevCache;
}

// Test/iteration helper: forget cached secrets so a new env can take effect.
function _resetSecretCache() {
  _secretCache = null;
  _secretPrevCache = null;
}

function canonicalStringify(obj) {
  // Deterministic JSON: keys sorted recursively, no whitespace, same circular guards as _gaptSafeStringifyP.
  const seen = new WeakSet();
  function walk(v) {
    if (v === null || typeof v !== 'object') return v;
    if (seen.has(v)) return '[Circular]';
    seen.add(v);
    if (Array.isArray(v)) return v.map(walk);
    if (v instanceof Map) return { __map__: Array.from(v.entries()).map(([k, val]) => [k, walk(val)]) };
    if (v instanceof Set) return { __set__: Array.from(v.values()).map(walk) };
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = walk(v[k]);
    return out;
  }
  return JSON.stringify(walk(obj));
}

function _computeHmac(body, secret) {
  const h = crypto.createHmac('sha256', secret);
  h.update(canonicalStringify(body));
  return h.digest('hex');
}

function signSnapshot(body) {
  const secret = ensureSecret();
  return { v: 1, body: body, hmac: 'sha256:' + _computeHmac(body, secret) };
}

function verifySnapshot(obj, opts) {
  opts = opts || {};
  if (!obj || typeof obj !== 'object') return { ok: false, body: null, reason: 'NO_HMAC' };
  // Unsigned: no hmac field, no v field, but a recognizable body shape (top-level passCount/trustScore etc.)
  // We detect "wrapped" form vs "legacy bare" by presence of obj.hmac.
  const isWrapped = (typeof obj.hmac === 'string' && obj.body && typeof obj.body === 'object');
  if (!isWrapped) {
    // Legacy unsigned snapshot. Accept only under grace flag; caller is responsible for re-signing.
    if (process.env.GAPT_HMAC_ACCEPT_UNSIGNED === '1') {
      return { ok: true, body: obj, reason: 'MIGRATION' };
    }
    return { ok: false, body: null, reason: 'NO_HMAC' };
  }
  const expected = obj.hmac.replace(/^sha256:/, '');
  const secret = ensureSecret();
  const got = _computeHmac(obj.body, secret);
  if (timingSafeEqHex(expected, got)) {
    return { ok: true, body: obj.body, reason: 'OK' };
  }
  const prev = getPrevSecret();
  if (prev) {
    const gotPrev = _computeHmac(obj.body, prev);
    if (timingSafeEqHex(expected, gotPrev)) {
      return { ok: true, body: obj.body, reason: 'ROTATED' };
    }
  }
  return { ok: false, body: null, reason: 'BAD_HMAC' };
}

function timingSafeEqHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex')); }
  catch { return false; }
}

// ---------- file ops ----------

function edgeKey(fromId, toId) {
  return `gap_${fromId}_${toId}.json`.replace(/[^a-z0-9_\.]/gi, '-');
}

function edgePath(fromId, toId) {
  return path.join(DATA_DIR, edgeKey(fromId, toId));
}

function saveGapMemory(fromId, toId, memory) {
  ensureHandshake();
  const filepath = edgePath(fromId, toId);
  const body = {
    edge: { from: fromId, to: toId },
    savedAt: new Date().toISOString(),
    passCount: memory.passCount,
    failCount: memory.failCount,
    locked: memory.locked,
    trustScore: memory.trustScore,
    trustTier: memory.trustTier,
    threatLevel: memory.threatLevel,
    prediction: memory.prediction,
    patterns: memory.patterns,
    attempts: (memory.attempts || []).slice(-100)
  };
  try {
    const envelope = signSnapshot(body);
    fs.writeFileSync(filepath, _gaptSafeStringifyP(envelope, 2));
    return true;
  } catch (err) {
    console.error(`  Failed to save gap memory [${fromId}->${toId}]: ${err.message}`);
    return false;
  }
}

function loadGapMemory(fromId, toId) {
  ensureHandshake();
  const filepath = edgePath(fromId, toId);
  if (!fs.existsSync(filepath)) return null;
  let parsed;
  try {
    const raw = fs.readFileSync(filepath, 'utf8');
    parsed = JSON.parse(raw);
  } catch (err) {
    return null; // corrupt JSON; caller treats null = clean-slate
  }
  const result = verifySnapshot(parsed);
  if (!result.ok) {
    if (result.reason === 'BAD_HMAC') {
      console.warn(`  [TAMPERED] Gap [${fromId}->${toId}] rejected: HMAC mismatch`);
    } else if (result.reason === 'NO_HMAC') {
      console.warn(`  [UNSIGNED] Gap [${fromId}->${toId}] rejected (set GAPT_HMAC_ACCEPT_UNSIGNED=1 for one-time migration)`);
    }
    return null;
  }
  // Auto-resign on migration or rotation
  if (result.reason === 'MIGRATION') {
    try {
      const envelope = signSnapshot(result.body);
      fs.writeFileSync(filepath, _gaptSafeStringifyP(envelope, 2));
      console.log(`  [MIGRATION] resigned ${path.basename(filepath)}`);
    } catch (_) {}
  } else if (result.reason === 'ROTATED') {
    try {
      const envelope = signSnapshot(result.body);
      fs.writeFileSync(filepath, _gaptSafeStringifyP(envelope, 2));
      console.log(`  [ROTATE] re-signed ${path.basename(filepath)} with current key`);
    } catch (_) {}
  }
  const snapshot = result.body;
  console.log(`  Gap [${fromId}->${toId}] restored -- passes:${snapshot.passCount} fails:${snapshot.failCount}`);
  return snapshot;
}

function listPersistedGaps() {
  try {
    const files = fs.readdirSync(DATA_DIR).filter(f => f.startsWith('gap_') && f.endsWith('.json'));
    return files.map(f => {
      const raw  = fs.readFileSync(path.join(DATA_DIR, f), 'utf8');
      let parsed; try { parsed = JSON.parse(raw); } catch { return { file: f, error: 'BAD_JSON' }; }
      const r = verifySnapshot(parsed);
      if (!r.ok) return { file: f, error: r.reason };
      const snap = r.body;
      return { file: f, edge: snap.edge, savedAt: snap.savedAt,
               passCount: snap.passCount, failCount: snap.failCount,
               locked: snap.locked, trustScore: snap.trustScore, threatLevel: snap.threatLevel };
    });
  } catch { return []; }
}

function deleteGapMemory(fromId, toId) {
  const filepath = edgePath(fromId, toId);
  if (fs.existsSync(filepath)) {
    fs.unlinkSync(filepath);
    console.log(`  Gap memory deleted [${fromId}->${toId}]`);
    return true;
  }
  return false;
}

// ---------- v34: multi-replica handshake ----------

function _keyFingerprint(secret) {
  // Public-safe fingerprint of the secret. Uses a domain-separated hash so this
  // value can be written to disk without leaking the secret itself. First 16 hex
  // chars (64 bits) is more than enough entropy to detect misconfig.
  const h = crypto.createHash('sha256');
  h.update('gapt-handshake-v1:');
  h.update(secret);
  return 'sha256:' + h.digest('hex').slice(0, 16);
}

function _hostFingerprint() {
  try {
    const os = require('os');
    return os.hostname() + ':pid-' + process.pid + ':' + new Date().toISOString();
  } catch (_) { return 'unknown:pid-' + process.pid; }
}

function ensureHandshake(opts) {
  opts = opts || {};
  if (_handshakeChecked && !opts.force) return _handshakeResult;

  // Resolve effective strict mode: explicit opt overrides env.
  let strict;
  if (typeof opts.strict === 'boolean') strict = opts.strict;
  else strict = (process.env.GAPT_HANDSHAKE_STRICT === '1');

  let secret;
  try { secret = ensureSecret(); }
  catch (e) {
    _handshakeResult = { ok: false, reason: 'NO_SECRET', error: e && e.message };
    _handshakeChecked = true;
    if (strict) throw new Error('GAPT_HANDSHAKE_MISMATCH: secret unavailable -- ' + (e && e.message));
    return _handshakeResult;
  }

  const expected = _keyFingerprint(secret);

  if (fs.existsSync(HANDSHAKE_FILE)) {
    let parsed = null;
    try {
      const raw = fs.readFileSync(HANDSHAKE_FILE, 'utf8');
      parsed = JSON.parse(raw);
    } catch (_) {
      console.warn('\n*** GAPT HANDSHAKE WARNING ****************************************************');
      console.warn(' .gapt-handshake.json is corrupt or unreadable. Refusing to silently');
      console.warn(' regenerate it -- that would mask a real config drift. Delete the file');
      console.warn(' manually after confirming the secret is correct on every replica.');
      console.warn('   path: ' + HANDSHAKE_FILE);
      console.warn('*******************************************************************************\n');
      _handshakeResult = { ok: false, reason: 'CORRUPT', fingerprint: expected };
      _handshakeChecked = true;
      if (strict) throw new Error('GAPT_HANDSHAKE_CORRUPT: see warning above');
      return _handshakeResult;
    }
    if (!parsed || parsed.v !== 1 || typeof parsed.keyFingerprint !== 'string') {
      _handshakeResult = { ok: false, reason: 'CORRUPT', fingerprint: expected };
      _handshakeChecked = true;
      if (strict) throw new Error('GAPT_HANDSHAKE_CORRUPT: malformed envelope');
      return _handshakeResult;
    }
    if (parsed.keyFingerprint !== expected) {
      console.warn('\n*** GAPT HANDSHAKE MISMATCH ***************************************************');
      console.warn(' This data dir was first written by a process whose HMAC secret has a');
      console.warn(' different fingerprint than the one this process is using. That means');
      console.warn(' you have two replicas with DIFFERENT GAPT_HMAC_SECRET values, or this');
      console.warn(' process was misconfigured after the secret was rotated.');
      console.warn(' Snapshots written by one will be rejected as [TAMPERED] by the other.');
      console.warn('   on-disk fingerprint:   ' + parsed.keyFingerprint);
      console.warn('   this-process expected: ' + expected);
      console.warn(' Fix: align GAPT_HMAC_SECRET across replicas, OR run gapt-resign with');
      console.warn(' GAPT_HMAC_SECRET_PREV set to the old key, then restart.');
      console.warn('*******************************************************************************\n');
      _handshakeResult = { ok: false, reason: 'MISMATCH', fingerprint: expected, onDisk: parsed.keyFingerprint };
      _handshakeChecked = true;
      if (strict) throw new Error('GAPT_HANDSHAKE_MISMATCH: see warning above');
      return _handshakeResult;
    }
    _handshakeResult = { ok: true, reason: 'OK', fingerprint: expected };
    _handshakeChecked = true;
    console.log('  [HANDSHAKE OK] data dir secret fingerprint matches (' + expected + ')');
    return _handshakeResult;
  }

  // No handshake file yet -- this is the first writer. Initialise.
  try {
    const body = {
      v: 1,
      firstSeen: new Date().toISOString(),
      keyFingerprint: expected,
      hostFingerprint: _hostFingerprint(),
    };
    const sigInput = 'gapt-handshake-sig-v1:' + canonicalStringify(body);
    const hmac = crypto.createHmac('sha256', secret); hmac.update(sigInput);
    body.signedAs = 'sha256:' + hmac.digest('hex');
    fs.writeFileSync(HANDSHAKE_FILE, JSON.stringify(body, null, 2));
    _handshakeResult = { ok: true, reason: 'INITIALISED', fingerprint: expected };
    _handshakeChecked = true;
    console.log('  [HANDSHAKE INIT] wrote ' + HANDSHAKE_FILE + ' fingerprint=' + expected);
    return _handshakeResult;
  } catch (e) {
    _handshakeResult = { ok: false, reason: 'WRITE_FAILED', error: e && e.message, fingerprint: expected };
    _handshakeChecked = true;
    if (strict) throw new Error('GAPT_HANDSHAKE_WRITE_FAILED: ' + (e && e.message));
    return _handshakeResult;
  }
}

function _resetHandshakeCache() {
  _handshakeChecked = false;
  _handshakeResult  = null;
}

module.exports = {
  saveGapMemory, loadGapMemory, listPersistedGaps, deleteGapMemory,
  // v26 new exports
  ensureSecret, canonicalStringify, signSnapshot, verifySnapshot, _resetSecretCache,
  // v34 new exports
  ensureHandshake, _resetHandshakeCache
};
