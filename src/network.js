// ============================================
// GAPT - Sprint 03 — Gap Communication
// GaptNetwork layer — gaps signal each other
// One gap attacked — all gaps notified
// ============================================

class GaptNetwork {
  constructor(opts) {
    this.graphs      = [];
    this.alertLog    = [];
    this.blocklist   = new Set();
    this.networkThreatLevel = 0;
    // v33: bounded blast-radius propagation. Infinity = legacy behaviour
    // (every registered edge sees every alert). Set to a finite k to
    // restrict alert delivery to edges within k hops of the source edge,
    // measured by edge-adjacency BFS (two edges are adjacent when they
    // share at least one endpoint node).
    const radius = (opts && typeof opts === 'object' && 'propagationRadius' in opts)
      ? opts.propagationRadius : Infinity;
    this._propagationRadius = GaptNetwork._normaliseRadius(radius);
  }

  static _normaliseRadius(k) {
    if (k === Infinity) return Infinity;
    if (typeof k !== 'number' || !Number.isFinite(k) || k < 0) return Infinity;
    return Math.floor(k);
  }

  setPropagationRadius(k) {
    this._propagationRadius = GaptNetwork._normaliseRadius(k);
    return this;
  }

  getPropagationRadius() {
    return this._propagationRadius;
  }

  _edgesWithinRadius(sourceEdgeId, k) {
    // Returns a Set of edgeIds reachable in <= k hops via edge-adjacency,
    // EXCLUDING the source itself. k=0 => empty Set. k=Infinity => every
    // other registered edge (legacy behaviour).
    if (k === 0) return new Set();
    if (k === Infinity) {
      const all = new Set();
      for (const g of this.graphs) for (const e of g.edges) {
        const id = e.from + '=>' + e.to;
        if (id !== sourceEdgeId) all.add(id);
      }
      return all;
    }
    // Build node -> edge incidence on demand.
    const nodeToEdges = new Map();
    const allEdges = [];
    for (const g of this.graphs) for (const e of g.edges) {
      const id = e.from + '=>' + e.to;
      allEdges.push({ id, from: e.from, to: e.to });
      if (!nodeToEdges.has(e.from)) nodeToEdges.set(e.from, new Set());
      if (!nodeToEdges.has(e.to))   nodeToEdges.set(e.to,   new Set());
      nodeToEdges.get(e.from).add(id);
      nodeToEdges.get(e.to).add(id);
    }
    const idx = sourceEdgeId.indexOf('=>');
    if (idx < 0) return new Set(); // malformed source id
    const visited = new Set([sourceEdgeId]);
    let frontier = new Set([sourceEdgeId]);
    for (let depth = 1; depth <= k; depth++) {
      const next = new Set();
      for (const eid of frontier) {
        const i = eid.indexOf('=>');
        if (i < 0) continue;
        const from = eid.slice(0, i);
        const to   = eid.slice(i + 2);
        const a = nodeToEdges.get(from);
        const b = nodeToEdges.get(to);
        if (a) for (const nid of a) if (!visited.has(nid)) { visited.add(nid); next.add(nid); }
        if (b) for (const nid of b) if (!visited.has(nid)) { visited.add(nid); next.add(nid); }
      }
      if (next.size === 0) break;
      frontier = next;
    }
    visited.delete(sourceEdgeId);
    return visited;
  }

  register(graph) {
    // v20 patch: defensive guard - silently no-op on null/non-graph inputs
    if (!graph || typeof graph._setNetwork !== 'function') return this;
    graph._setNetwork(this);
    this.graphs.push(graph);
    return this;
  }

  broadcast(alert) {
    // v20 patch: validate alert shape; reject junk and proto-pollution attempts
    if (!alert || typeof alert !== 'object' || Array.isArray(alert)) return;
    if (typeof alert.type !== 'string' || alert.type === '__proto__' || alert.type === 'constructor') return;
    // attackerSignature is the only field that mutates global blocklist - must be a sane string
    if ('attackerSignature' in alert) {
      const sig = alert.attackerSignature;
      if (typeof sig !== 'string' || sig.length === 0 || sig.length > 256) {
        delete alert.attackerSignature;
      }
    }
    try {
    alert.networkTs = new Date().toISOString();
    this.alertLog.push(alert);

    if (alert.type === 'LOCKDOWN_TRIGGERED') {
      this.networkThreatLevel = Math.max(this.networkThreatLevel, 3);
    } else if (alert.type === 'THREAT_ELEVATED') {
      this.networkThreatLevel = Math.max(this.networkThreatLevel, alert.threatLevel || 1);
    }

    if (alert.attackerSignature) {
      this.blocklist.add(alert.attackerSignature);
    }

    // v33: bounded blast-radius -- only edges within k hops get the alert.
    // alert.sourceEdge identifies the origin; legacy callers without one fall back
    // to legacy "every edge" delivery via the Infinity branch in _edgesWithinRadius.
    const reachable = this._edgesWithinRadius(alert.sourceEdge || '', this._propagationRadius);
    for (const graph of this.graphs) {
      for (const edge of graph.edges) {
        const edgeId = `${edge.from}=>${edge.to}`;
        if (reachable.has(edgeId)) {
          edge._receiveAlert(alert, this.blocklist);
        }
      }
    }

    const icon = { THREAT_ELEVATED:'yellow', LOCKDOWN_TRIGGERED:'red', ATTACKER_SIGNATURE:'blue' }[alert.type] || 'white';
    console.log(`  [NET] [${alert.type}] from [${alert.sourceEdge}] -- ${alert.message}`);
    if (this.blocklist.size > 0) {
      console.log(`     Blocklist: ${this.blocklist.size} signature(s) active`);
    }
    } catch (_e) { /* v20: never let broadcast take down the host */ }
  }

  networkStatus() {
    return {
      registeredGraphs: this.graphs.length,
      totalEdges: this.graphs.reduce((n, g) => n + g.edges.length, 0),
      networkThreatLevel: this.networkThreatLevel,
      propagationRadius: this._propagationRadius,
      blocklistSize: this.blocklist.size,
      blocklist: [...this.blocklist],
      alertCount: this.alertLog.length,
      recentAlerts: this.alertLog.slice(-10),
    };
  }

  cooldown() {
    if (this.networkThreatLevel > 0) {
      this.networkThreatLevel = Math.max(0, this.networkThreatLevel - 1);
    }
  }

  clearBlocklist(authority = 'system', token = null) {
    // v23 patch: require a token when network has set an admin secret.
    // If no _adminToken was configured, fall back to legacy behaviour but log loud.
    if (this._adminToken && token !== this._adminToken) {
      console.warn(`  [NET] clearBlocklist DENIED for [${authority}] - bad/missing token`);
      return false;
    }
    const count = this.blocklist.size;
    this.blocklist.clear();
    this.networkThreatLevel = 0;
    if (!this._adminToken) {
      console.warn('\n*** SECURITY WARNING ***********************************************************');
      console.warn(' clearBlocklist() called by [' + authority + '] WITHOUT an admin token.');
      console.warn(' Anyone with a reference to this network object can clear the blocklist.');
      console.warn(' Fix: call network.setAdminToken("<random-string-8+chars>") at startup,');
      console.warn('      then pass the token as the second arg to clearBlocklist().');
      console.warn('*******************************************************************************\n');
    }
    console.log(`  [NET] Blocklist cleared by [${authority}] -- ${count} signatures removed`);
    return true;
  }

  setAdminToken(token) {
    if (typeof token === 'string' && token.length >= 8) {
      this._adminToken = token;
      return true;
    }
    return false;
  }
}

module.exports = { GaptNetwork };
