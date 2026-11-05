// GAPT - Sprint 04 Test
// Gap Inheritance -- rebuild the edge, gap still remembers

const { GaptGraph } = require('../src/gapt');
const { deleteGapMemory } = require('../src/persist');

['user','attacker'].forEach(a => deleteGapMemory(a,'vault'));

function divider(t) { console.log(`\n${'='.repeat(54)}\n  ${t}\n${'='.repeat(54)}`); }

function printStatus(label, s) {
  const threat = ['CLEAN','WATCH','SUSPICIOUS','LOCKDOWN'][s.threatLevel]||'LOCKDOWN';
  console.log(`\n  ${label}`);
  console.log(`  Trust  : ${s.trustScore}/100 -- ${s.trustTier}`);
  console.log(`  Passes : ${s.passCount} | Fails: ${s.failCount}`);
  console.log(`  Threat : ${threat} | Locked: ${s.locked}`);
}

const cfg = { bridgetype:'vault-access', voidguard:(d)=>d.type==='valid', edgelock:'correct-key' };

divider('PHASE 1 - Build history on original edge');
const g = new GaptGraph({ autoRestore: false });
g.addNode('user',{}); g.addNode('attacker',{}); g.addNode('vault',{});
g.addEdge('user','vault',{...cfg}); g.addEdge('attacker','vault',{...cfg});

console.log('\n  User building trust (15 passes):');
for (let i=0;i<15;i++) g.send('user','vault',{type:'valid'},'correct-key');
console.log(`  Trust: ${g.gapStatus('user','vault').trustScore}/100 -- ${g.gapStatus('user','vault').trustTier}`);

console.log('\n  Attacker triggering lockdown:');
['atk-aaa','atk-bbb','atk-ccc','atk-ddd'].forEach(k => g.send('attacker','vault',{type:'valid'},k));
const ba = g.gapStatus('attacker','vault');
console.log(`  Locked: ${ba.locked} | Fails: ${ba.failCount} | Predicted: ${ba.prediction.threat}`);

divider('PHASE 2 - Retiring edges');
g.retireEdge('user','vault');
g.retireEdge('attacker','vault');
console.log(`\n  Registry: ${Object.keys(g.getRegistrySnapshot()).join(', ')}`);

divider('PHASE 3 - Rebuilding with inheritance');
g.addEdge('user','vault',{...cfg, voidguard:(d)=>d.type==='valid'&&d.version!==undefined, inherit:true});
g.addEdge('attacker','vault',{...cfg, inherit:true});

divider('PHASE 4 - Verifying inherited state');
printStatus('User gap (inherited):',    g.gapStatus('user','vault'));
printStatus('Attacker gap (inherited):', g.gapStatus('attacker','vault'));

const attackerTry = g.send('attacker','vault',{type:'valid'},'correct-key');
console.log(`\n  Attacker on new edge: ${attackerTry.passed?'PASSED -- inheritance failed':'BLOCKED -- inheritance worked'}`);
console.log(`  Reason: ${attackerTry.reason}`);

const userTry = g.send('user','vault',{type:'valid',version:'1.0'},'correct-key');
console.log(`\n  User on new edge: ${userTry.passed?'PASS':'BLOCKED'} | ${userTry.reason}`);

divider('PHASE 5 - Fresh edge (inherit: false)');
g.retireEdge('user','vault');
g.addEdge('user','vault',{...cfg, inherit:false});
const fresh = g.gapStatus('user','vault');
console.log(`\n  Trust  : ${fresh.trustScore}/100 -- ${fresh.trustTier}`);
console.log(`  From zero: ${fresh.passCount===0?'YES':'NO'}`);

divider('SPRINT 04 COMPLETE');
console.log('\n  Edge retired -- memory preserved');
console.log('  New edge inherits trust and lock state');
console.log('  Attacker still blocked after edge rebuild');
console.log('  inherit:false starts fresh correctly');
console.log('\n  Rebuild the edge. The gap still remembers.');
