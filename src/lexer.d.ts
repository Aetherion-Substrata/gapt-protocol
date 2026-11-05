// Type definitions for @gapt/protocol/src/lexer

export type GaptTokenType =
  | 'NODE' | 'EDGE' | 'SEND' | 'GUARD' | 'LABEL' | 'LOCK'
  | 'GRAPH' | 'NETWORK' | 'INHERIT' | 'TRUE' | 'FALSE'
  | 'LET' | 'IF' | 'ELSE' | 'ASSIGN'
  | 'GAPFN' | 'BODY' | 'RETURN' | 'AS' | 'PERSIST'
  | 'ARROW' | 'LBRACE' | 'RBRACE' | 'COLON' | 'DOT'
  | 'LPAREN' | 'RPAREN' | 'COMMA'
  | 'EQUALS' | 'NEQUALS' | 'AND' | 'OR'
  | 'GT' | 'LT' | 'GTE' | 'LTE'
  | 'IDENTIFIER' | 'STRING' | 'NUMBER'
  | 'COMMENT' | 'NEWLINE' | 'EOF';

export const TOKEN_TYPES: Readonly<Record<GaptTokenType, GaptTokenType>>;

export class Token {
  constructor(type: GaptTokenType, value: unknown, line: number);
  readonly type: GaptTokenType;
  readonly value: unknown;
  readonly line: number;
  toString(): string;
}

export class GaptLexer {
  constructor(source: string);
  readonly source: string;
  readonly tokens: Token[];
  readonly errors: string[];
  tokenise(): Token[];
}
