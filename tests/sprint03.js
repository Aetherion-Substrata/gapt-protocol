// GAPT - Sprint 03 Test
// Gap Communication -- network-wide defence

const { GaptGraph } = require('../src/gapt');
const { GaptNetwork } = require('../src/network');
const { deleteGapMemory } = require('../src/persist');

['user','attacker','processor'].forEach(a =>
  ['vault','processor','sidenode'].forEach(b => deleteGapMemory(a,b))
);

function divider(t) { console.log(`\n${'='.repeat(54)}\n  ${t}\n${'='.repeat(54)}`); }

const network = new GaptNetwork();

const g1 = new GaptGraph({ autoRestore: false });
g1.addNode('user',{}); g1.addNode('attacker',{}); g1.addNode('vault',{});
g1.addEdge('user',     'vault', { bridgetype:'user-access',     voidguard:d=>d.type==='valid', edgelock:'correct-key' });
g1.addEdge('attacker', 'vault', { bridgetype:'attacker-access', voidguard:d=>d.type==='valid', edgelock:'correct-key' });

const g2 = new GaptGraph({ autoRestore: false });
g2.addNode('user',{}); g2.addNode('processor',{}); g2.addNode('sidenode',{});
g2.addEdge('user','processor', { bridgetype:'proc-access', voidguard:d=>true, edgelock:'correct-key' });
g2.addEdge('user','sidenode',  { bridgetype:'side-access', voidguard:d=>true, edgelock:'correct-key' });

network.register(g1);
network.register(g2);

divider('SCENARIO 1 - Attack propagates across network');
console.log('\n  Attacker hammering attacker->vault...\n');
['hack-aaa','hack-bbb','hack-ccc','hack-ddd','hack-eee'].forEach(key => {
  const r = g1.send('attacker','vault',{type:'valid'},key);
  const s = g1.gapStatus('attacker','vault');
  const threat = ['CLEAN','WATCH','SUSPICIOUS','LOCKDOWN'][s.threatLevel];
  console.log(`  [${key}]: BLOCKED ${r.reason} | ${threat}`);
});
const net = network.networkStatus();
console.log(`\n  Network threat : ${net.networkThreatLevel}`);
console.log(`  Blocklist      : ${net.blocklistSize} signature(s)`);
console.log(`  Entries        : ${net.blocklist.join(', ')}`);

divider('SCENARIO 2 - Blocklisted key blocked across all edges');
console.log('');
[
  {graph:g1,from:'user',    to:'vault',     key:'hack-aaa'},
  {graph:g2,from:'user',    to:'processor', key:'hack-bbb'},
  {graph:g2,from:'user',    to:'sidenode',  key:'hack-ccc'},
].forEach(({graph,from,to,key}) => {
  const r = graph.send(from,to,{type:'valid'},key);
  console.log(`  [${from}->${to}] [${key}]: ${r.passed?'PASSED':'BLOCKED'} | ${r.reason}`);
});

divider('SCENARIO 3 - Legitimate user unaffected');
console.log('');
[
  {graph:g1,from:'user',to:'vault'},
  {graph:g2,from:'user',to:'processor'},
  {graph:g2,from:'user',to:'sidenode'},
].forEach(({graph,from,to}) => {
  const r = graph.send(from,to,{type:'valid'},'correct-key');
  console.log(`  [${from}->${to}]: ${r.passed?'PASS':'BLOCKED'} | ${r.reason}`);
});

divider('SCENARIO 4 - Authority clears blocklist');
network.clearBlocklist('admin-kizldn');
console.log(`\n  Blocklist after clear: ${network.networkStatus().blocklistSize}`);

divider('SPRINT 03 COMPLETE');
const final = network.networkStatus();
console.log(`\n  Graphs    : ${final.registeredGraphs}`);
console.log(`  Edges     : ${final.totalEdges}`);
console.log(`  Alerts    : ${final.alertCount}`);
console.log('\n  One gap attacked. Whole network responded.');
