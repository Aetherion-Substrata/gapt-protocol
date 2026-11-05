// send-throughput.js -- gapt baseline send/s benchmark.
// Measures the cost of edge.transmit() on a single edge with HMAC-signed
// persistence enabled. Compares to the GATE-v19 baseline (~1000-1200/s).
//
// Usage: GAPT_HMAC_SECRET=<32+byte hex> node bench/send-throughput.js [iterations]
// Default: 5000 iterations.

'use strict';

const path = require('path');
const fs   = require('fs');
const crypto = require('crypto');

if (!process.env.GAPT_HMAC_SECRET) {
  process.env.GAPT_HMAC_SECRET = crypto.randomBytes(32).toString('hex');
  console.log('[bench] auto-generated GAPT_HMAC_SECRET for this run');
}

const { GaptGraph } = require('../src/gapt');

const N = parseInt(process.argv[2], 10) || 5000;

// Clean a dedicated bench data dir so we don't fight other runs.
const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
for (const f of fs.readdirSync(DATA_DIR)) {
  if (f.startsWith('gap_') && f.endsWith('.json')) fs.unlinkSync(path.join(DATA_DIR, f));
}

const g = new GaptGraph({ autoRestore: false });
g.addNode('a', {}); g.addNode('b', {});
g.addEdge('a', 'b', {
  bridgetype: 'bench',
  voidguard: (d) => d && d.type === 'valid',
  edgelock: 'k',
  predictive: false   // turn off prediction so we measure the raw send + persist hot path
});

const payload = { type: 'valid', n: 0 };

// Warmup -- let V8 JIT settle.
for (let i = 0; i < 200; i++) {
  payload.n = i;
  g.send('a', 'b', payload, 'k');
}

// Measure.
const startMs = Date.now();
const startHr = process.hrtime.bigint();
for (let i = 0; i < N; i++) {
  payload.n = i;
  const r = g.send('a', 'b', payload, 'k');
  if (!r.passed) {
    console.error('[bench] FAIL at i=' + i + ' -- ' + r.reason);
    process.exit(2);
  }
}
const endHr = process.hrtime.bigint();
const endMs = Date.now();

const ns = Number(endHr - startHr);
const secs = ns / 1e9;
const opsPerSec = N / secs;

console.log('[bench] iterations:        ' + N);
console.log('[bench] wall ms:           ' + (endMs - startMs));
console.log('[bench] hr secs:           ' + secs.toFixed(4));
console.log('[bench] ops/sec:           ' + Math.round(opsPerSec));
console.log('[bench] avg us/op:         ' + (ns / N / 1000).toFixed(2));
console.log('[bench] v19 baseline ref:  1000-1200 ops/sec');
const ratio = opsPerSec / 1100;
console.log('[bench] vs v19 baseline:   ' + (ratio * 100).toFixed(1) + '%');
if (ratio < 0.95) {
  console.log('[bench] WARNING: more than 5% slower than baseline. Investigate persist hot path.');
} else {
  console.log('[bench] PASS within +/-5% gate.');
}

// Cleanup
for (const f of fs.readdirSync(DATA_DIR)) {
  if (f.startsWith('gap_') && f.endsWith('.json')) fs.unlinkSync(path.join(DATA_DIR, f));
}
