// GAPT Core v0.5 -- Gapt Protocol
// Weighted trust, fingerprinting, network comms, inheritance
// Aetherion Substrata Ltd -- github.com/Aetherion-Substrata/gapt-protocol

const { saveGapMemory, loadGapMemory } = require('./persist');
const { GaptNetwork } = require('./network');

// v19 patch: cap live attempts array to bound RAM
const GAPT_ATTEMPTS_MAX = 256;

// ── Bridge Classes (v0.12) ─────────────────────────────────────────────────────
// A bridgeclass gives an edge typed, functional semantics — not just a label.
// It changes what the gap enforces during transmission.
//
//   relay     — explicit pass-through. Data moves unchanged. No surprises.
//   guard     — voidguard is mandatory and cannot be bypassed by trust tier.
//   signal    — one-directional. Data is stripped from the result (receipt only).
//   boundary  — domain edge. Every crossing is logged regardless of trust tier.
//   transform — flags that data changes in transit. Logged explicitly.
//   trust     — identity lane. edgelock is mandatory and cannot be bypassed.
//
// bridgeclass is optional and backward-compatible.
// If omitted, the edge behaves exactly as it did before v0.12.
const BRIDGE_CLASSES = Object.freeze({
  relay:     'relay',
  guard:     'guard',
  signal:    'signal',
  boundary:  'boundary',
  transform: 'transform',
  trust:     'trust',
});

// v06 patch: circular-ref safe stringify
function _gaptSafeStringify(v, indent) {
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


const DEFAULT_TRUST_CONFIG = {
  earnPerPass:2, losePerFail:10, losePerPattern:25, losePerLockdown:50,
  tiers:{
    unknown: {min:0,  max:19,  label:'UNKNOWN',  bypass:null},
    familiar:{min:20, max:49,  label:'FAMILIAR', bypass:'voidguard-low-risk'},
    trusted: {min:50, max:79,  label:'TRUSTED',  bypass:'voidguard'},
    verified:{min:80, max:100, label:'VERIFIED', bypass:null},
  }
};

function getTrustTier(score,config=DEFAULT_TRUST_CONFIG){
  const t=config.tiers;
  if(score>=t.verified.min)return t.verified;
  if(score>=t.trusted.min)return t.trusted;
  if(score>=t.familiar.min)return t.familiar;
  return t.unknown;
}

class GaptMemory {
  constructor(trustConfig=DEFAULT_TRUST_CONFIG) {
    this.attempts=[]; this.failCount=0; this.passCount=0; this.lastAttempt=null;
    this.locked=false; this.threatLevel=0; this.trustScore=0; this.trustTier='UNKNOWN';
    this.trustConfig=trustConfig;
    this.patterns={burst:false,rotation:false,probe:false,dormant:false,signatureDeviation:false};
    this.fingerprints={};
    this.prediction={threat:false,confidence:0,reason:null,preEmpted:0};
  }

  applyTrustEarn(){
    this.trustScore=Math.min(100,this.trustScore+this.trustConfig.earnPerPass);
    this._updateTrustTier();
  }

  applyTrustLoss(reason){
    const losses={fail:this.trustConfig.losePerFail,pattern:this.trustConfig.losePerPattern,lockdown:this.trustConfig.losePerLockdown};
    this.trustScore=Math.max(0,this.trustScore-(losses[reason]||this.trustConfig.losePerFail));
    this._updateTrustTier();
  }

  _updateTrustTier(){ this.trustTier=getTrustTier(this.trustScore,this.trustConfig).label; }
  getTierPrivilege(){ return getTrustTier(this.trustScore,this.trustConfig).bypass; }

  record(result,key,meta={}) {
    const entry={
      ts:Date.now(),timestamp:new Date().toISOString(),
      passed:result.passed,reason:result.reason,
      keySignature:key?key.toString().slice(0,4)+'****':'none',
      rawKey:key,trustScore:this.trustScore,trustTier:this.trustTier,
      predicted:result.predicted||false
    };
    this.attempts.push(entry); if (this.attempts.length > GAPT_ATTEMPTS_MAX) this.attempts.splice(0, this.attempts.length - GAPT_ATTEMPTS_MAX);
    this.lastAttempt=entry.timestamp;
    if(result.passed){this.passCount++;this.applyTrustEarn();}
    else{this.failCount++;this.applyTrustLoss('fail');}
    this.updateThreatLevel();
    this.analysePatterns();
    if(result.passed&&meta.travellerId&&key){
      if(!this.fingerprints[meta.travellerId]) this.fingerprints[meta.travellerId]=new GaptFingerprint(meta.travellerId);
      this.fingerprints[meta.travellerId].record({
        hour:new Date().getHours(),dataSize:meta.dataSize||0,
        keyLen:key.length,keyPrefix:key.slice(0,4),passed:result.passed
      });
    }
    return entry;
  }

  checkFingerprint(travellerId,key,dataSize){
    if(!travellerId||!this.fingerprints[travellerId]) return {score:0,ready:false,reasons:[]};
    return this.fingerprints[travellerId].compare({
      hour:new Date().getHours(),dataSize:dataSize||0,
      keyLen:key?key.length:0,keyPrefix:key?key.slice(0,4):'',
    });
  }

  analysePatterns(){
    const h=this.attempts,now=Date.now(),recent=h.slice(-10),prevThreat=this.prediction.threat;
    this.patterns.burst=h.filter(a=>(now-a.ts)<500&&!a.passed).length>=5;
    this.patterns.rotation=new Set(h.filter(a=>!a.passed&&a.rawKey).map(a=>a.rawKey)).size>=4;
    if(recent.length>=6){
      let alt=true;
      for(let i=1;i<6;i++){if(recent[recent.length-i].passed===recent[recent.length-i-1].passed){alt=false;break;}}
      this.patterns.probe=alt;
    }
    if(h.length>=8){
      const older=h.slice(-10,-5),newer=h.slice(-5);
      if(older.length>0){
        const g=newer[0].ts-older[older.length-1].ts,b=newer[newer.length-1].ts-newer[0].ts;
        this.patterns.dormant=g>2000&&b<200;
      }
    }
    let c=0;
    if(this.patterns.burst)c+=70;if(this.patterns.rotation)c+=60;
    if(this.patterns.probe)c+=40;if(this.patterns.dormant)c+=50;
    c=Math.min(c,100);
    if(!prevThreat&&c>=60)this.applyTrustLoss('pattern');
    this.prediction.confidence=c;this.prediction.threat=c>=60;
    const r=[];
    if(this.patterns.burst)r.push('BURST');if(this.patterns.rotation)r.push('KEY_ROT');
    if(this.patterns.probe)r.push('PROBE');if(this.patterns.dormant)r.push('DORMANT');
    this.prediction.reason=r.join('+')||null;
  }

  updateThreatLevel(){
    const recent=this.attempts.slice(-5),fails=recent.filter(a=>!a.passed).length;
    const prevLocked=this.locked;
    if(this.locked)this.threatLevel=3;
    else if(fails>=4){this.threatLevel=3;this.locked=true;}
    else if(fails>=3)this.threatLevel=2;
    else if(fails>=2)this.threatLevel=1;
    else this.threatLevel=0;
    if(!prevLocked&&this.locked)this.applyTrustLoss('lockdown');
  }

  reset(authority='system'){
    this.locked=false;this.threatLevel=0;
    this.prediction.threat=false;this.prediction.confidence=0;
    const ratio=this.passCount/Math.max(1,this.passCount+this.failCount);
    this.trustScore=Math.round(ratio*40);this._updateTrustTier();
    this.attempts.push({ts:Date.now(),timestamp:new Date().toISOString(),passed:null,
      reason:`GAP_RESET -- authorised by [${authority}]`,keySignature:'AUTHORITY',rawKey:null,
      trustScore:this.trustScore,trustTier:this.trustTier}); if (this.attempts.length > GAPT_ATTEMPTS_MAX) this.attempts.splice(0, this.attempts.length - GAPT_ATTEMPTS_MAX);
    console.log(`  Reset by [${authority}] | Trust: ${this.trustScore}/100 -- ${this.trustTier}`);
  }

  restoreFrom(snapshot){
    // v23 patch: validate / clamp every field. Hostile persistence files cannot grant trust.
    if (!snapshot || typeof snapshot !== 'object') return;
    const VALID_TIERS = new Set(['UNKNOWN','FAMILIAR','TRUSTED','VERIFIED']);
    const num = (v, lo, hi, def) => {
      if (typeof v !== 'number' || !Number.isFinite(v)) return def;
      return Math.max(lo, Math.min(hi, Math.floor(v)));
    };
    this.passCount   = num(snapshot.passCount,   0, 1e9, 0);
    this.failCount   = num(snapshot.failCount,   0, 1e9, 0);
    this.trustScore  = num(snapshot.trustScore,  0, 100, 0);
    this.threatLevel = num(snapshot.threatLevel, 0, 10,  0);
    this.locked      = (snapshot.locked === true);
    // v24 patch: history-check. Trust must be earned, not declared.
    // If snapshot claims high trust but has no pass history, reject the claim.
    // Threshold: trust >= 50 (TRUSTED tier) requires passCount >= 5.
    if (this.trustScore >= 50 && this.passCount < 5) {
      this.trustScore = 0;
      this.threatLevel = Math.max(this.threatLevel, 1);
      this.locked = false;
    }
    // Cross-check: high threatLevel forces locked even if snapshot said false.
    if (this.threatLevel >= 3) this.locked = true;
    // Tier must match enum AND be consistent with trustScore.
    const tierIn = (typeof snapshot.trustTier === 'string' && VALID_TIERS.has(snapshot.trustTier)) ? snapshot.trustTier : 'UNKNOWN';
    this.trustTier = tierIn;
    this._updateTrustTier(); // recompute from trustScore - overrides any tier inflation
    const attemptsIn = Array.isArray(snapshot.attempts) ? snapshot.attempts : [];
    this.attempts = attemptsIn.length > GAPT_ATTEMPTS_MAX ? attemptsIn.slice(-GAPT_ATTEMPTS_MAX) : attemptsIn;
    this.lastAttempt = this.attempts.slice(-1)[0]?.timestamp || null;
    if (snapshot.prediction && typeof snapshot.prediction === 'object') {
      Object.assign(this.prediction, snapshot.prediction);
    }
  }

  getStatus(){
    return{
      passCount:this.passCount,failCount:this.failCount,threatLevel:this.threatLevel,
      locked:this.locked,trustScore:this.trustScore,trustTier:this.trustTier,
      lastAttempt:this.lastAttempt,prediction:this.prediction,
      patterns:this.patterns,recentHistory:this.attempts.slice(-8)
    };
  }
}

class GaptEdge {
  constructor(from,to,{voidguard,bridgetype,bridgeclass,edgelock,predictive=true,trustConfig}){
    this.from=from;this.to=to;this.voidguard=voidguard;this.bridgetype=bridgetype;
    // v0.12: bridgeclass validation
    if(bridgeclass&&!BRIDGE_CLASSES[bridgeclass]){
      throw new Error(`GAPT: unknown bridgeclass "${bridgeclass}". Valid: ${Object.keys(BRIDGE_CLASSES).join(', ')}`);
    }
    if(bridgeclass==='guard'&&!voidguard){
      throw new Error('GAPT: bridgeclass "guard" requires a voidguard function.');
    }
    if(bridgeclass==='trust'&&!edgelock){
      throw new Error('GAPT: bridgeclass "trust" requires an edgelock.');
    }
    this.bridgeclass=bridgeclass||null;
    this.edgelock=edgelock;this.predictive=predictive;
    this.memory=new GaptMemory(trustConfig||DEFAULT_TRUST_CONFIG);
    this._network=null;this._networkAlertLevel=0;this._networkBlocklist=new Set();
  }

  _receiveAlert(alert,blocklist){
    this._networkBlocklist=blocklist;
    if(alert.type==='LOCKDOWN_TRIGGERED')this._networkAlertLevel=3;
    else if(alert.type==='THREAT_ELEVATED')this._networkAlertLevel=Math.max(this._networkAlertLevel,alert.threatLevel||1);
  }

  _broadcastIfNeeded(key){
    if(!this._network)return;
    const m=this.memory,edgeId=`${this.from}=>${this.to}`,keySignature=key?key.slice(0,4)+'****':null;
    if(m.locked&&this._networkAlertLevel<3){
      this._networkAlertLevel=3;
      this._network.broadcast({type:'LOCKDOWN_TRIGGERED',sourceEdge:edgeId,attackerSignature:keySignature,threatLevel:3,message:`Edge locked. Sig: ${keySignature}`});
    } else if(m.threatLevel>=2&&this._networkAlertLevel<2){
      this._networkAlertLevel=2;
      this._network.broadcast({type:'THREAT_ELEVATED',sourceEdge:edgeId,attackerSignature:keySignature,threatLevel:m.threatLevel,message:`Threat ${m.threatLevel}`});
    } else if(m.prediction.threat&&this._networkAlertLevel<1){
      this._networkAlertLevel=1;
      this._network.broadcast({type:'ATTACKER_SIGNATURE',sourceEdge:edgeId,attackerSignature:keySignature,threatLevel:1,message:`Pattern: ${m.prediction.reason}`});
    }
  }

  restore(){const s=loadGapMemory(this.from,this.to);if(s){this.memory.restoreFrom(s);return true;}return false;}

  persist(){
    const m=this.memory;
    saveGapMemory(this.from,this.to,{
      passCount:m.passCount,failCount:m.failCount,locked:m.locked,
      trustScore:m.trustScore,trustTier:m.trustTier,threatLevel:m.threatLevel,
      prediction:m.prediction,patterns:m.patterns,
      attempts:m.attempts.slice(-100).map(a=>({
        timestamp:a.timestamp,passed:a.passed,reason:a.reason,
        keySignature:a.keySignature,trustScore:a.trustScore,trustTier:a.trustTier
      }))
    });
  }

  transmit(data,accessKey,options={}){
    // v08 patch: coerce accessKey to string before any string op.
    if (typeof accessKey !== 'string') {
      try { accessKey = (accessKey === null || accessKey === undefined) ? '' : String(accessKey); }
      catch (e) { accessKey = ''; }
    }
    // v09 patch: global try/catch wrap. Any caller-input crash (proxy traps, getter throws,
    // weird payload types, etc.) returns a structured GAP_EXCEPTION log instead of propagating.
    try { return this._transmitCore(data, accessKey, options); }
    catch (e) {
      const log = { from:this.from, to:this.to, bridgetype:this.bridgetype,
        timestamp:new Date().toISOString(), passed:false,
        reason:'GAP_EXCEPTION', error:String(e && e.message ? e.message : e) };
      try { this.memory.record(log, accessKey, {}); this.persist(); } catch (_) {}
      return log;
    }
  }

  _transmitCore(data,accessKey,options={}){
    const travellerId=options.travellerId||null,dataSize=(_gaptSafeStringify(data)||'').length;
    const log={from:this.from,to:this.to,bridgetype:this.bridgetype,
      bridgeclass:this.bridgeclass||undefined,
      timestamp:new Date().toISOString(),passed:false,reason:null,predicted:false,
      trustScore:this.memory.trustScore,trustTier:this.memory.trustTier,travellerId};

    if(this._networkBlocklist&&accessKey){
      const sig=accessKey.slice(0,4)+'****';
      if(this._networkBlocklist.has(sig)){
        log.reason=`NETWORK_BLOCKED -- sig flagged [${sig}]`;log.networkBlock=true;
        this.memory.record(log,accessKey,{});this.persist();return log;
      }
    }

    if(this.memory.locked){
      log.reason='GAP_LOCKED';this._broadcastIfNeeded(accessKey);
      this.memory.record(log,accessKey,{});this.persist();return log;
    }

    if(this.predictive&&this.memory.prediction.threat){
      log.reason=`GAP_PREDICTED_THREAT [${this.memory.prediction.reason}] ${this.memory.prediction.confidence}%`;
      log.predicted=true;this.memory.prediction.preEmpted++;
      this.memory.record(log,accessKey,{});this.persist();return log;
    }

    const privilege=this.memory.getTierPrivilege();

    // v0.12: trust class — edgelock mandatory, no tier bypass
    if(this.edgelock&&(privilege!=='edgelock-pattern'||this.bridgeclass==='trust')){
      const ok=typeof this.edgelock==='function'?this.edgelock(accessKey,data):accessKey===this.edgelock;
      if(!ok){
        log.reason='EDGELOCK_FAILED';this.memory.record(log,accessKey,{});
        this._broadcastIfNeeded(accessKey);this.persist();return log;
      }
    } else if(privilege==='edgelock-pattern'&&this.bridgeclass!=='trust'){log.edgelockBypassed=true;}

    // v0.12: guard class — voidguard mandatory, no tier bypass
    const skipVoid=(this.bridgeclass!=='guard')&&(privilege==='voidguard'||privilege==='edgelock-pattern');
    if(!skipVoid&&this.voidguard&&!this.voidguard(data)){
      log.reason='VOIDGUARD_REJECTED';this.memory.record(log,accessKey,{});this.persist();return log;
    }
    if(skipVoid)log.voidguardBypassed=true;

    if(travellerId){
      const fp=this.memory.checkFingerprint(travellerId,accessKey,dataSize);
      if(fp.ready&&fp.score>=60){
        log.passed=false;log.reason=`FINGERPRINT_DEVIATION [score:${fp.score}]`;
        log.deviationScore=fp.score;log.deviationReasons=fp.reasons;
        this.memory.record(log,accessKey,{travellerId,dataSize});this.persist();return log;
      }
      if(fp.ready)log.deviationScore=fp.score;
    }

    log.passed=true;log.reason=`GAPT_CLEAR [${this.memory.trustTier}]`;log.data=data;
    // v0.12: class-specific result shaping
    if(this.bridgeclass==='signal'){delete log.data;log.signalReceived=true;}
    if(this.bridgeclass==='boundary')log.boundaryCrossing=true;
    if(this.bridgeclass==='transform')log.transformExpected=true;
    this.memory.record(log,accessKey,{travellerId,dataSize});this.persist();
    return log;
  }

  status(){return{edge:`${this.from} -> ${this.to}`,bridgetype:this.bridgetype,bridgeclass:this.bridgeclass||null,...this.memory.getStatus()};}
}

class GaptGraph {
  // v26: private inheritance registry. External writes like
  //   g._inheritanceRegistry[k] = {...}
  // hit a public-property shadow that the class never reads.
  #inheritanceRegistry = {};

  constructor(options={}){
    this.nodes={};this.edges=[];
    this.autoRestore=options.autoRestore!==false;
    this._network=null;
  }

  addNode(id,data){this.nodes[id]={id,data,edges:[]};return this;}

  // v26: diagnostic read-only accessor. Returns a frozen deep clone so
  // external code cannot mutate the live registry through this handle.
  getRegistrySnapshot(){
    const clone = JSON.parse(JSON.stringify(this.#inheritanceRegistry));
    function freezeDeep(o){
      if (o && typeof o === 'object') {
        Object.freeze(o);
        for (const k of Object.keys(o)) freezeDeep(o[k]);
      }
      return o;
    }
    return freezeDeep(clone);
  }

  retireEdge(fromId,toId){
    const edge=this.edges.find(e=>e.from===fromId&&e.to===toId);
    if(!edge)return false;
    const key=`${fromId}=>${toId}`;
    this.#inheritanceRegistry[key]={
      retiredAt:new Date().toISOString(),
      passCount:edge.memory.passCount,failCount:edge.memory.failCount,
      trustScore:edge.memory.trustScore,trustTier:edge.memory.trustTier,
      threatLevel:edge.memory.threatLevel,locked:edge.memory.locked,
      prediction:{...edge.memory.prediction},patterns:{...edge.memory.patterns},
      attempts:edge.memory.attempts.slice(-20)
    };
    this.edges=this.edges.filter(e=>!(e.from===fromId&&e.to===toId));
    if(this.nodes[fromId]) this.nodes[fromId].edges=this.nodes[fromId].edges.filter(e=>!(e.from===fromId&&e.to===toId));
    console.log(`  Edge [${key}] retired`);
    return true;
  }

  addEdge(fromId,toId,gapConfig){
    const edge=new GaptEdge(fromId,toId,gapConfig);
    if(this.autoRestore)edge.restore();
    const key=`${fromId}=>${toId}`,shouldInherit=gapConfig.inherit!==false,retired=this.#inheritanceRegistry[key];
    if(shouldInherit&&retired&&!edge.memory.passCount){
      // v23 patch: validate inheritance same way as restoreFrom. Hostile registry cannot poison.
      edge.memory.restoreFrom(retired);
      // (restoreFrom clamps all fields. The remaining work below is just bookkeeping.)
      if(retired.patterns)Object.assign(edge.memory.patterns,retired.patterns);
      console.log(`  Edge [${key}] inherited | Trust:${edge.memory.trustScore} Locked:${edge.memory.locked}`);
    }
    if(this._network)edge._network=this._network;
    this.edges.push(edge);this.nodes[fromId]?.edges.push(edge);
    return this;
  }

  _setNetwork(network){
    this._network=network;
    for(const edge of this.edges)edge._network=network;
  }

  send(fromId,toId,data,accessKey=null,options={}){
    const edge=this.edges.find(e=>e.from===fromId&&e.to===toId);
    if(!edge)return{passed:false,reason:'NO_EDGE_EXISTS'};
    return edge.transmit(data,accessKey,options);
  }

  gapStatus(fromId,toId){const edge=this.edges.find(e=>e.from===fromId&&e.to===toId);return edge?edge.status():null;}

  resetGap(fromId,toId,authority='system'){
    const edge=this.edges.find(e=>e.from===fromId&&e.to===toId);
    if(edge){edge.memory.reset(authority);edge.persist();}
  }
}

// ============================================
// GaptFingerprint -- Behavioural signature
// ============================================

class GaptFingerprint {
  constructor(travellerId){
    this.travellerId=travellerId;this.samples=[];this.signature=null;this.minSamples=5;
  }

  record(sample){
    this.samples.push(sample);
    if(this.samples.length>=this.minSamples)this._computeSignature();
  }

  _computeSignature(){
    const s=this.samples;
    const avg=arr=>arr.reduce((a,b)=>a+b,0)/arr.length;
    const std=arr=>{const m=avg(arr);return Math.sqrt(avg(arr.map(x=>Math.pow(x-m,2))));};
    this.signature={
      avgHour:avg(s.map(x=>x.hour)),stdHour:std(s.map(x=>x.hour)),
      avgSize:avg(s.map(x=>x.dataSize)),stdSize:std(s.map(x=>x.dataSize)),
      avgKeyLen:avg(s.map(x=>x.keyLen)),stdKeyLen:std(s.map(x=>x.keyLen)),
      commonKeyPfx:this._mode(s.map(x=>x.keyPrefix)),sampleCount:s.length,
    };
  }

  _mode(arr){const f={};arr.forEach(v=>f[v]=(f[v]||0)+1);return Object.keys(f).sort((a,b)=>f[b]-f[a])[0];}

  compare(sample){
    if(!this.signature||this.samples.length<this.minSamples)return{score:0,ready:false,reasons:[]};
    const sig=this.signature,reasons=[];let deviations=0;
    const hourDiff=Math.abs(sample.hour-sig.avgHour);
    if(hourDiff>Math.max(3,sig.stdHour*2)){deviations+=30;reasons.push(`UNUSUAL_HOUR (~${Math.round(sig.avgHour)}h got ${sample.hour}h)`);}
    const sizeDiff=Math.abs(sample.dataSize-sig.avgSize);
    if(sizeDiff>Math.max(50,sig.stdSize*2.5)){
      const mul=sample.dataSize/Math.max(1,sig.avgSize);
      const sc=mul>=50?60:mul>=10?40:25;
      deviations+=sc;reasons.push(`UNUSUAL_SIZE (~${Math.round(sig.avgSize)}b got ${sample.dataSize}b ${Math.round(mul)}x)`);
    }
    if(Math.abs(sample.keyLen-sig.avgKeyLen)>Math.max(2,sig.stdKeyLen*2)){
      deviations+=25;reasons.push(`UNUSUAL_KEY_LEN (~${Math.round(sig.avgKeyLen)} got ${sample.keyLen})`);
    }
    if(sig.commonKeyPfx&&sample.keyPrefix!==sig.commonKeyPfx){
      deviations+=20;reasons.push(`UNUSUAL_KEY_PFX ("${sig.commonKeyPfx}" got "${sample.keyPrefix}")`);
    }
    return{score:Math.min(100,deviations),ready:true,reasons,signature:sig};
  }

  toJSON(){return{travellerId:this.travellerId,signature:this.signature,sampleCount:this.samples.length};}
}

module.exports={GaptGraph,GaptEdge,GaptMemory,GaptFingerprint,GaptNetwork,getTrustTier,DEFAULT_TRUST_CONFIG,BRIDGE_CLASSES};
