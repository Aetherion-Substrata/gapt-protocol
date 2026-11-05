// Type definitions for @gapt/protocol/src/interpreter

import { AstNode } from './parser';
import { GaptGraph, SendResult } from './gapt';
import { GaptNetwork } from './network';

export class GaptInterpreter {
  constructor();
  readonly graphs: Record<string, GaptGraph>;
  readonly results: Array<SendResult & { _from: string; _to: string }>;
  readonly errors: string[];
  readonly log: string[];
  /** Top-level scope for `let` bindings (v0.8.0+). */
  readonly scope: Record<string, unknown>;
  network: GaptNetwork | null;
  execute(ast: AstNode): SendResult[];

  // 0.11.0 lang-v3: holographic gapfn surface.
  /** Registry of declared gapfns. Each entry wraps a one-edge internal GaptGraph. */
  readonly fns: Record<string, {
    name: string;
    params: string[];
    persist: boolean;
    graph: GaptGraph;
    edge: GaptGraph['edges'][number];
  }>;
  /** Same shape as gapStatus(from,to) -- pass/fail counts, trust, threat, lockdown. */
  fnStatus(name: string): (Record<string, unknown> & {
    name: string; params: string[]; persist: boolean;
    passCount: number; failCount: number;
    trustScore: number; trustTier: string;
    threatLevel: number; locked: boolean;
  }) | null;
  /** Clears the lockdown and rebases trust to 40 * (passes/total). */
  fnReset(name: string, authority?: string): boolean;
}
