// Type definitions for @gapt/protocol
// Project: https://github.com/FizzNetwork/gapt
//
// Covers the main entry (src/gapt.js). For deep imports, see:
//   src/network.d.ts    - GaptNetwork (re-exported below)
//   src/persist.d.ts    - persistence + handshake helpers
//   src/lexer.d.ts      - GaptLexer + Token
//   src/parser.d.ts     - GaptParser
//   src/interpreter.d.ts - GaptInterpreter

/** Trust tier earned by an edge through repeated clean sends. */
export type TrustTier = 'UNKNOWN' | 'FAMILIAR' | 'TRUSTED' | 'VERIFIED';

/** Trust-score thresholds + per-event deltas. */
export interface TrustConfig {
  passDelta: number;
  failDelta: number;
  tiers: { tier: TrustTier; threshold: number; bypass: 'none' | 'voidguard' }[];
}

export const DEFAULT_TRUST_CONFIG: TrustConfig;

export function getTrustTier(score: number, config?: TrustConfig): { tier: TrustTier; bypass: string };

/** Per-edge stored memory: passes, fails, threat level, attempt log. */
export class GaptMemory {
  constructor(trustConfig?: TrustConfig);
  passCount: number;
  failCount: number;
  trustScore: number;
  trustTier: TrustTier;
  threatLevel: number;
  locked: boolean;
  prediction: Record<string, unknown>;
  patterns: Record<string, unknown>;
  attempts: unknown[];
  reset(authority?: string): void;
  restoreFrom(snapshot: Partial<GaptMemory>): void;
  getTierPrivilege(): string;
}

/** Per-traveller behavioural fingerprint. */
export class GaptFingerprint {
  constructor(travellerId: string);
  travellerId: string;
}

/** Result of GaptGraph.send / edge.transmit. */
export interface SendResult {
  passed: boolean;
  reason: string;
  trustScore?: number;
  threatLevel?: number;
  predicted?: boolean;
  [extra: string]: unknown;
}

/** Typed behaviour class for an edge (v0.12). Optional — omit for default behaviour. */
export type BridgeClass = 'relay' | 'guard' | 'signal' | 'boundary' | 'transform' | 'trust';

export const BRIDGE_CLASSES: Readonly<Record<BridgeClass, BridgeClass>>;

/** Gap-config used when wiring an edge. */
export interface GapConfig {
  /** Inspector that examines the data before transmission. Truthy result = allowed. */
  voidguard?: (data: unknown) => boolean;
  /** Free-form label naming the relationship between the two nodes. */
  bridgetype?: string;
  /** Typed behaviour class for this edge. Changes what the gap enforces. */
  bridgeclass?: BridgeClass;
  /**
   * Lock check. Either a string (compared by exact match against accessKey)
   * or a function (key, data) => boolean.
   */
  edgelock?: string | ((key: unknown, data: unknown) => boolean);
  /** Whether predictive lockdown is enabled on this edge (default: true). */
  predictive?: boolean;
  /** Override trust thresholds for this edge only. */
  trustConfig?: TrustConfig;
  /** Whether the edge should inherit retired-edge memory (default: true). */
  inherit?: boolean;
}

/** Options for a single transmission. */
export interface SendOptions {
  /** Stable id used to track behavioural fingerprint across sends. */
  travellerId?: string;
  [extra: string]: unknown;
}

/** Snapshot returned by getRegistrySnapshot(). Frozen + read-only. */
export interface InheritanceRegistrySnapshot {
  readonly [edgeKey: string]: Readonly<{
    retiredAt: string;
    passCount: number;
    failCount: number;
    trustScore: number;
    trustTier: TrustTier;
    threatLevel: number;
    locked: boolean;
    prediction: Readonly<Record<string, unknown>>;
    patterns: Readonly<Record<string, unknown>>;
    attempts: ReadonlyArray<unknown>;
  }>;
}

/** Single edge in the graph. The gap between two nodes is a first-class citizen. */
export class GaptEdge {
  constructor(from: string, to: string, config: GapConfig);
  readonly from: string;
  readonly to: string;
  memory: GaptMemory;
  transmit(data: unknown, accessKey?: unknown, options?: SendOptions): SendResult;
  status(): Record<string, unknown>;
  restore(): void;
  persist(): boolean;
}

/** The graph. */
export class GaptGraph {
  constructor(options?: { autoRestore?: boolean });
  readonly nodes: Record<string, { id: string; data: Record<string, unknown>; edges: GaptEdge[] }>;
  readonly edges: GaptEdge[];
  addNode(id: string, data?: Record<string, unknown>): this;
  addEdge(from: string, to: string, config: GapConfig): this;
  retireEdge(from: string, to: string): boolean;
  send(from: string, to: string, data: unknown, accessKey?: unknown, options?: SendOptions): SendResult;
  gapStatus(from: string, to: string): Record<string, unknown> | null;
  resetGap(from: string, to: string, authority?: string): void;
  /** Frozen, deep-cloned snapshot of the private inheritance registry. */
  getRegistrySnapshot(): InheritanceRegistrySnapshot;
}

// Re-exports from sibling modules so consumers can do `import { GaptNetwork } from '@gapt/protocol'`.
export { GaptNetwork } from './network';
