// GAPT - Persistence Layer (browser shim, v0.10.0)
// In-memory, sync, API-compatible with persist.js but without fs/crypto.
//
// What's the same: every exported function name + signature matches the Node
// persist.js, so the rest of the gapt codebase compiles unchanged against this
// module via the build/build-browser.js bundler.
//
// What's different (and you should know):
//   - Storage is a process-local Map. Refreshing the page wipes it.
//   - No HMAC. signSnapshot wraps with a sentinel hmac:'browser-noop' so the
//     envelope shape survives JSON round-trips. verifySnapshot accepts both
//     wrapped and bare bodies and never rejects.
//   - ensureHandshake is a no-op that always reports {ok:true}. There are no
//     replicas in a browser tab.
//
// If you want real persistence in the browser, the v0.11.x roadmap is the
// async backend (localStorage / IndexedDB + WebCrypto HMAC). This file is
// deliberately small and sync so the v0.10.0 bundle stays drop-in.

const _store = new Map(); // edgeKey -> body (deep-cloned on get)

function _clone(v) {
  // Structured deep clone via JSON. Matches what fs round-trip would do.
  if (v === null || v === undefined) return v;
  return JSON.parse(JSON.stringify(v));
}

function edgeKey(fromId, toId) {
  return ('gap_' + fromId + '_' + toId + '.json').replace(/[^a-z0-9_\.]/gi, '-');
}

function canonicalStringify(obj) {
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

function ensureSecret() {
  // Sentinel value. Anything that compares ensureSecret() === ensureSecret()
  // still works (same reference). Anything that asks for raw bytes gets an
  // empty Uint8Array.
  return ensureSecret._sentinel || (ensureSecret._sentinel = new Uint8Array(0));
}

function _resetSecretCache() { ensureSecret._sentinel = null; }

function signSnapshot(body) {
  return { v: 1, body: body, hmac: 'browser-noop' };
}

function verifySnapshot(obj) {
  if (!obj || typeof obj !== 'object') return { ok: false, body: null, reason: 'NO_BODY' };
  const isWrapped = (typeof obj.hmac === 'string' && obj.body && typeof obj.body === 'object');
  if (isWrapped) return { ok: true, body: obj.body, reason: 'BROWSER_NOOP' };
  return { ok: true, body: obj, reason: 'BROWSER_BARE' };
}

function saveGapMemory(fromId, toId, memory) {
  ensureHandshake();
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
    const envelope = signSnapshot(_clone(body));
    _store.set(edgeKey(fromId, toId), envelope);
    return true;
  } catch (err) {
    if (typeof console !== 'undefined' && console.error) {
      console.error('  Failed to save gap memory [' + fromId + '->' + toId + ']: ' + err.message);
    }
    return false;
  }
}

function loadGapMemory(fromId, toId) {
  ensureHandshake();
  const envelope = _store.get(edgeKey(fromId, toId));
  if (!envelope) return null;
  const r = verifySnapshot(envelope);
  if (!r.ok) return null;
  const snapshot = _clone(r.body);
  if (typeof console !== 'undefined' && console.log) {
    console.log('  Gap [' + fromId + '->' + toId + '] restored -- passes:' + snapshot.passCount + ' fails:' + snapshot.failCount);
  }
  return snapshot;
}

function listPersistedGaps() {
  const out = [];
  for (const [file, envelope] of _store.entries()) {
    const r = verifySnapshot(envelope);
    if (!r.ok) { out.push({ file: file, error: r.reason }); continue; }
    const snap = r.body;
    out.push({
      file: file, edge: snap.edge, savedAt: snap.savedAt,
      passCount: snap.passCount, failCount: snap.failCount,
      locked: snap.locked, trustScore: snap.trustScore, threatLevel: snap.threatLevel
    });
  }
  return out;
}

function deleteGapMemory(fromId, toId) {
  const k = edgeKey(fromId, toId);
  if (_store.has(k)) {
    _store.delete(k);
    if (typeof console !== 'undefined' && console.log) {
      console.log('  Gap memory deleted [' + fromId + '->' + toId + ']');
    }
    return true;
  }
  return false;
}

let _handshakeChecked = false;
let _handshakeResult = null;

function ensureHandshake(opts) {
  opts = opts || {};
  if (_handshakeChecked && !opts.force) return _handshakeResult;
  _handshakeResult = { ok: true, reason: 'BROWSER_INMEMORY', fingerprint: 'browser:no-secret' };
  _handshakeChecked = true;
  return _handshakeResult;
}

function _resetHandshakeCache() {
  _handshakeChecked = false;
  _handshakeResult = null;
}

module.exports = {
  saveGapMemory, loadGapMemory, listPersistedGaps, deleteGapMemory,
  ensureSecret, canonicalStringify, signSnapshot, verifySnapshot, _resetSecretCache,
  ensureHandshake, _resetHandshakeCache
};
