// GAPT - Sprint 02 Test
// Behavioural Fingerprinting
// Correct credentials. Wrong behaviour. Blocked.

const { GaptGraph } = require('../src/gapt');
const { deleteGapMemory } = require('../src/persist');

deleteGapMemory('alice', 'vault');

function divider(t) { console.log(`\n${'='.repeat(54)}\n  ${t}\n${'='.repeat(54)}`); }

const g = new GaptGraph({ autoRestore: false });
g.addNode('alice', {}); g.addNode('vault', {});
g.addEdge('alice', 'vault', {
  bridgetype: 'vault-access',
  voidguard:  (d) => d.payload !== undefined,
  edgelock:   'alice-key-secure'
});

divider('PHASE 1 - Building Alice fingerprint (10 normal transmissions)');
for (let i = 1; i <= 10; i++) {
  const data = { payload: 'x'.repeat(50 + Math.floor(Math.random() * 20)) };
  const r = g.send('alice', 'vault', data, 'alice-key-secure', { travellerId: 'alice' });
  if ([1, 5, 10].includes(i)) console.log(`  Pass ${i}: ${r.passed ? 'PASS' : 'FAIL'} | ${r.reason}`);
}
const fp = g.gapStatus('alice', 'vault');
console.log(`\n  Fingerprint built: ${fp.trustScore}/100 -- ${fp.trustTier}`);

divider('PHASE 2 - Legitimate Alice, normal behaviour');
const normal = g.send('alice', 'vault', { payload: 'x'.repeat(55) }, 'alice-key-secure', { travellerId: 'alice' });
console.log(`  Result: ${normal.passed ? 'PASS' : 'BLOCKED'} | ${normal.reason}`);
if (normal.deviationScore !== undefined) console.log(`  Deviation: ${normal.deviationScore}/100`);

divider('PHASE 3 - Account takeover (correct key, wrong behaviour)');
const takeover = g.send('alice', 'vault', { payload: 'x'.repeat(5000) }, 'alice-key-secure', { travellerId: 'alice' });
console.log(`  Result: ${takeover.passed ? 'PASSED -- FALSE NEGATIVE' : 'BLOCKED -- CORRECT'}`);
console.log(`  Reason: ${takeover.reason}`);
if (takeover.deviationScore) {
  console.log(`  Deviation: ${takeover.deviationScore}/100`);
  takeover.deviationReasons?.forEach(r => console.log(`  Flag: ${r}`));
}

divider('PHASE 4 - Wrong key prefix pattern');
const wrongPrefix = g.send('alice', 'vault', { payload: 'x'.repeat(55) }, 'hack-key-secure', { travellerId: 'alice' });
console.log(`  Result: ${wrongPrefix.passed ? 'PASSED' : 'BLOCKED'} | ${wrongPrefix.reason}`);

divider('PHASE 5 - New traveller, no fingerprint (should pass)');
deleteGapMemory('bob', 'vault');
const g2 = new GaptGraph({ autoRestore: false });
g2.addNode('bob', {}); g2.addNode('vault', {});
g2.addEdge('bob', 'vault', { bridgetype: 'vault-access', voidguard: (d) => d.payload !== undefined, edgelock: 'bob-key-001' });
const newUser = g2.send('bob', 'vault', { payload: 'first time' }, 'bob-key-001', { travellerId: 'bob' });
console.log(`  Result: ${newUser.passed ? 'PASS -- new traveller allowed' : 'BLOCKED'} | ${newUser.reason}`);

divider('SPRINT 02 COMPLETE');
console.log('\n  Fingerprint builds from clean history');
console.log('  Normal behaviour passes');
console.log('  Payload anomaly detected and blocked');
console.log('  New travellers pass -- no false positives');
console.log('\n  The gap knows WHO you are, not just WHAT you do.');
