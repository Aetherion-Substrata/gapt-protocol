// Type definitions for @gapt/protocol/src/network

import { GaptGraph } from './gapt';

export interface NetworkOptions {
  /**
   * Bounded blast radius (v0.7.0+).
   * - `Infinity` (default): every registered edge sees every alert (legacy).
   * - `0`: alerts log but do not propagate.
   * - `k`: alerts reach edges within k hops of the source edge (edge-adjacency BFS).
   */
  propagationRadius?: number;
}

export type GaptAlertType =
  | 'THREAT_ELEVATED'
  | 'LOCKDOWN_TRIGGERED'
  | 'ATTACKER_SIGNATURE'
  | string;

export interface GaptAlert {
  type: GaptAlertType;
  sourceEdge?: string;
  message?: string;
  threatLevel?: number;
  attackerSignature?: string;
  networkTs?: string;
  [extra: string]: unknown;
}

export interface NetworkStatus {
  registeredGraphs: number;
  totalEdges: number;
  networkThreatLevel: number;
  propagationRadius: number;
  blocklistSize: number;
  blocklist: string[];
  alertCount: number;
  recentAlerts: GaptAlert[];
}

/** Network-wide gap communication: alerts, blocklist, threat propagation. */
export class GaptNetwork {
  constructor(opts?: NetworkOptions);
  register(graph: GaptGraph): this;
  broadcast(alert: GaptAlert): void;
  networkStatus(): NetworkStatus;
  cooldown(): void;
  clearBlocklist(authority?: string, token?: string | null): boolean;
  setAdminToken(token: string): boolean;
  /** Sets the propagation radius. Garbage values normalise to Infinity. */
  setPropagationRadius(k: number): this;
  /** Current effective propagation radius. */
  getPropagationRadius(): number;
}
