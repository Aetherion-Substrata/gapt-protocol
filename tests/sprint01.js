// GAPT - Sprint 01 Test
// Weighted Trust Scoring

const { GaptGraph } = require('../src/gapt');
const { deleteGapMemory } = require('../src/persist');

deleteGapMemory('user', 'vault');

function divider(t) { console.log(`\n${'='.repeat(52)}\n  ${t}\n${'='.repeat(52)}`); }

function trustBar(score) {
  const filled = Math.round(score / 5);
  const bar = '#'.repeat(filled) + '.'.repeat(20 - filled);
  return `[${bar}] ${score}/100`;
}

function status(g) {
  const s = g.gapStatus('user', 'vault');
  console.log(`\n  Trust  : ${trustBar(s.trustScore)}`);
  console.log(`  Tier   : ${s.trustTier}`);
  console.log(`  Passes : ${s.passCount} | Fails: ${s.failCount}`);
}

const g = new GaptGraph({ autoRestore: false });
g.addNode('user', {}); g.addNode('vault', {});
g.addEdge('user', 'vault', {
  bridgetype: 'vault-access',
  voidguard:  (d) => d.type === 'valid',
  edgelock:   'correct-key'
});

divider('SCENARIO 1 - Trust climbing through tiers');
const milestones = [20, 50, 80]; let milestone = 0;
for (let i = 1; i <= 50; i++) {
  g.send('user', 'vault', { type: 'valid' }, 'correct-key');
  const s = g.gapStatus('user', 'vault');
  if (s.trustScore >= milestones[milestone]) {
    console.log(`\n  Pass ${i}: Score hit ${s.trustScore} -> Tier: ${s.trustTier}`);
    console.log(`  ${trustBar(s.trustScore)}`);
    milestone++;
    if (milestone >= milestones.length) break;
  }
}
status(g);

divider('SCENARIO 2 - Voidguard bypass at TRUSTED tier');
const s2 = g.gapStatus('user', 'vault');
console.log(`\n  Current tier: ${s2.trustTier} (${s2.trustScore}/100)`);
const bypass = g.send('user', 'vault', { type: 'INVALID_DATA' }, 'correct-key');
console.log(`  Invalid data with TRUSTED tier: ${bypass.passed ? 'PASSED' : 'BLOCKED'}`);
console.log(`  Voidguard bypassed: ${bypass.voidguardBypassed ? 'YES' : 'NO'}`);
console.log(`  Reason: ${bypass.reason}`);

divider('SCENARIO 3 - Failures tank the trust score');
console.log(`\n  Score before attacks: ${g.gapStatus('user', 'vault').trustScore}`);
for (let i = 1; i <= 3; i++) {
  g.send('user', 'vault', { type: 'valid' }, 'wrong-key');
  const s = g.gapStatus('user', 'vault');
  console.log(`  Fail ${i}: Score -> ${s.trustScore} (${s.trustTier})`);
}
status(g);

divider('SCENARIO 4 - Custom trust config');
deleteGapMemory('admin', 'vault');
const g2 = new GaptGraph({ autoRestore: false });
g2.addNode('admin', {}); g2.addNode('vault', {});
g2.addEdge('admin', 'vault', {
  bridgetype: 'admin-access',
  voidguard:  (d) => d.clearance === 'high',
  edgelock:   'admin-key',
  trustConfig: {
    earnPerPass:5, losePerFail:20, losePerPattern:40, losePerLockdown:80,
    tiers:{
      unknown: {min:0,  max:19,  label:'UNKNOWN',  bypass:null},
      familiar:{min:20, max:49,  label:'FAMILIAR', bypass:'voidguard-low-risk'},
      trusted: {min:50, max:79,  label:'TRUSTED',  bypass:'voidguard'},
      verified:{min:80, max:100, label:'VERIFIED', bypass:'edgelock-pattern'},
    }
  }
});
console.log('\n  Custom config: +5 per pass, -20 per fail');
for (let i = 1; i <= 12; i++) {
  g2.send('admin', 'vault', { clearance: 'high' }, 'admin-key');
  const s = g2.gapStatus('admin', 'vault');
  if ([1,5,10,12].includes(i)) console.log(`  Pass ${i}: ${trustBar(s.trustScore)} -- ${s.trustTier}`);
}
g2.send('admin', 'vault', { clearance: 'high' }, 'wrong-key');
const s4 = g2.gapStatus('admin', 'vault');
console.log(`  After 1 fail: ${trustBar(s4.trustScore)} -- ${s4.trustTier}`);

divider('SPRINT 01 COMPLETE - Trust Score Summary');
const final = g.gapStatus('user', 'vault');
console.log(`\n  Trust : ${trustBar(final.trustScore)}`);
console.log(`  Tier  : ${final.trustTier}`);
console.log(`  Passes: ${final.passCount} | Fails: ${final.failCount}`);
console.log(`\n  Trust is now a score, not a switch.`);
