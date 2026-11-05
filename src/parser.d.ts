// Type definitions for @gapt/protocol/src/parser

import { Token } from './lexer';

export type AstNode =
  | { type: 'Program'; body: AstNode[] }
  | { type: 'Literal'; value: unknown; kind: 'string' | 'number' | 'boolean' | 'null' }
  | { type: 'Identifier'; name: string }
  | { type: 'MemberExpr'; object: AstNode; property: string }
  | { type: 'CallExpr'; callee: AstNode; args: AstNode[]; callerOverride?: AstNode | null }
  | { type: 'BinaryExpr'; op: string; left: AstNode; right: AstNode }
  | { type: 'NodeDecl'; id: string; props: Record<string, unknown> }
  | { type: 'EdgeDecl'; from: string; to: string; config: { guard: AstNode | null; label: AstNode | null; lock: AstNode | null; inherit: boolean } }
  | { type: 'SendStmt'; from: string; to: string; send: { data: Record<string, unknown>; key: unknown; travellerId: unknown } }
  | { type: 'GraphDecl'; name: string; body: AstNode[] }
  | { type: 'NetworkDecl'; graphs: string[] }
  | { type: 'VarDecl'; name: string; value: AstNode }
  | { type: 'IfStmt'; test: AstNode; consequent: AstNode[]; alternate: AstNode[] | null }
  | { type: 'GapFnDecl'; name: string; params: string[]; guard: AstNode | null; lock: AstNode | null; body: AstNode[]; persist: boolean }
  | { type: 'ReturnStmt'; value: AstNode };

export class GaptParser {
  constructor(tokens: Token[]);
  readonly tokens: Token[];
  readonly errors: string[];
  parse(): Extract<AstNode, { type: 'Program' }>;
}
