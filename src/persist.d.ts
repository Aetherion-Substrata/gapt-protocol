// Type definitions for @gapt/protocol/src/persist

import { GaptMemory } from './gapt';

export interface PersistedGap {
  edge: { from: string; to: string };
  savedAt: string;
  passCount: number;
  failCount: number;
  trustScore: number;
  trustTier: string;
  threatLevel: number;
  locked: boolean;
  prediction: Record<string, unknown>;
  patterns: Record<string, unknown>;
  attempts: unknown[];
}

export interface SnapshotEnvelope {
  v: 1;
  body: PersistedGap;
  hmac: string;
}

export interface VerifyResult {
  ok: boolean;
  body: PersistedGap | null;
  reason: 'OK' | 'ROTATED' | 'MIGRATION' | 'BAD_HMAC' | 'NO_HMAC';
}

export interface HandshakeResult {
  ok: boolean;
  reason: 'OK' | 'INITIALISED' | 'MISMATCH' | 'CORRUPT' | 'NO_SECRET' | 'WRITE_FAILED';
  fingerprint?: string;
  onDisk?: string;
  error?: string;
}

export interface HandshakeOptions {
  /**
   * If true, throw `GAPT_HANDSHAKE_MISMATCH` (or similar) instead of returning `{ok:false}`.
   * Defaults to the value of env var `GAPT_HANDSHAKE_STRICT === '1'`.
   */
  strict?: boolean;
  /** Bypass the once-per-process cache. */
  force?: boolean;
}

export function saveGapMemory(fromId: string, toId: string, memory: GaptMemory): boolean;
export function loadGapMemory(fromId: string, toId: string): PersistedGap | null;
export function listPersistedGaps(): Array<Partial<PersistedGap> & { file: string; error?: string }>;
export function deleteGapMemory(fromId: string, toId: string): boolean;

/** Returns the raw secret bytes. In Node this is a `Buffer`, which is a subclass of `Uint8Array`. */
export function ensureSecret(): Uint8Array;
export function canonicalStringify(obj: unknown): string;
export function signSnapshot(body: PersistedGap): SnapshotEnvelope;
export function verifySnapshot(env: SnapshotEnvelope | PersistedGap): VerifyResult;

/** Multi-replica HMAC handshake (v0.7.0+). */
export function ensureHandshake(opts?: HandshakeOptions): HandshakeResult;
