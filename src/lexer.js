// GAPT Lexer -- tokenises .gapt source files
// Sprint 05 -- Language Foundation

const TOKEN_TYPES = {
  NODE:'NODE', EDGE:'EDGE', SEND:'SEND', GUARD:'GUARD', LABEL:'LABEL',
  LOCK:'LOCK', GRAPH:'GRAPH', NETWORK:'NETWORK', INHERIT:'INHERIT',
  TRUE:'TRUE', FALSE:'FALSE',
  // v31 -- language v2: let bindings + if/else conditionals
  LET:'LET', IF:'IF', ELSE:'ELSE', ASSIGN:'ASSIGN',
  // 0.11.0 -- language v3: holographic gapfn (functions as gaps)
  GAPFN:'GAPFN', BODY:'BODY', RETURN:'RETURN', AS:'AS', PERSIST:'PERSIST',
  ARROW:'ARROW', LBRACE:'LBRACE', RBRACE:'RBRACE', COLON:'COLON',
  DOT:'DOT', LPAREN:'LPAREN', RPAREN:'RPAREN', COMMA:'COMMA',
  EQUALS:'EQUALS', NEQUALS:'NEQUALS', AND:'AND', OR:'OR',
  GT:'GT', LT:'LT', GTE:'GTE', LTE:'LTE',
  IDENTIFIER:'IDENTIFIER', STRING:'STRING', NUMBER:'NUMBER',
  COMMENT:'COMMENT', NEWLINE:'NEWLINE', EOF:'EOF',
};

const KEYWORDS = new Set([
  'node','edge','send','guard','label','lock','graph','network','inherit','true','false',
  // v31
  'let','if','else',
  // 0.11.0 -- gapfn keywords
  'gapfn','body','return','as','persist'
]);

class Token {
  constructor(type, value, line) {
    this.type = type; this.value = value; this.line = line;
  }
  toString() { return `Token(${this.type}, ${JSON.stringify(this.value)}, line:${this.line})`; }
}

class GaptLexer {
  constructor(source) {
    this.source = source; this.pos = 0; this.line = 1;
    this.tokens = []; this.errors = [];
  }

  peek(offset=0) { return this.source[this.pos+offset] || ''; }

  advance() {
    const ch = this.source[this.pos++];
    if (ch === '\n') this.line++;
    return ch;
  }

  skipWhitespace() {
    while (this.pos < this.source.length) {
      const ch = this.peek();
      if (ch===' '||ch==='\t'||ch==='\r') { this.advance(); }
      else if (ch==='/'&&this.peek(1)==='/') {
        while (this.pos<this.source.length&&this.peek()!=='\n') this.advance();
      } else break;
    }
  }

  readString() {
    this.advance(); let str='';
    while (this.pos<this.source.length&&this.peek()!=='"') str+=this.advance();
    this.advance(); return str;
  }

  readNumber() {
    let num='';
    while (this.pos<this.source.length&&/[0-9.]/.test(this.peek())) num+=this.advance();
    return parseFloat(num);
  }

  readIdentifier() {
    let id='';
    while (this.pos<this.source.length&&/[a-zA-Z0-9_\-]/.test(this.peek())) id+=this.advance();
    return id;
  }

  tokenise() {
    while (this.pos < this.source.length) {
      this.skipWhitespace();
      if (this.pos >= this.source.length) break;
      const ch = this.peek(); const line = this.line;

      if (ch==='\n') { this.advance(); continue; }
      if (ch==='"') { this.tokens.push(new Token(TOKEN_TYPES.STRING, this.readString(), line)); continue; }
      if (/[0-9]/.test(ch)) { this.tokens.push(new Token(TOKEN_TYPES.NUMBER, this.readNumber(), line)); continue; }

      if (ch==='-'&&this.peek(1)==='>') { this.advance(); this.advance(); this.tokens.push(new Token(TOKEN_TYPES.ARROW,'->',line)); continue; }
      if (ch==='='&&this.peek(1)==='=') { this.advance(); this.advance(); this.tokens.push(new Token(TOKEN_TYPES.EQUALS,'==',line)); continue; }
      // v31: single '=' is ASSIGN (used in 'let x = ...'). Must be checked AFTER '==' above.
      if (ch==='='&&this.peek(1)!=='=') { this.advance(); this.tokens.push(new Token(TOKEN_TYPES.ASSIGN,'=',line)); continue; }
      if (ch==='!'&&this.peek(1)==='=') { this.advance(); this.advance(); this.tokens.push(new Token(TOKEN_TYPES.NEQUALS,'!=',line)); continue; }
      if (ch==='&'&&this.peek(1)==='&') { this.advance(); this.advance(); this.tokens.push(new Token(TOKEN_TYPES.AND,'&&',line)); continue; }
      if (ch==='|'&&this.peek(1)==='|') { this.advance(); this.advance(); this.tokens.push(new Token(TOKEN_TYPES.OR,'||',line)); continue; }
      if (ch==='>'&&this.peek(1)==='=') { this.advance(); this.advance(); this.tokens.push(new Token(TOKEN_TYPES.GTE,'>=',line)); continue; }
      if (ch==='<'&&this.peek(1)==='=') { this.advance(); this.advance(); this.tokens.push(new Token(TOKEN_TYPES.LTE,'<=',line)); continue; }

      const single = {'{':TOKEN_TYPES.LBRACE,'}':TOKEN_TYPES.RBRACE,':':TOKEN_TYPES.COLON,
        '.':TOKEN_TYPES.DOT,'(':TOKEN_TYPES.LPAREN,')':TOKEN_TYPES.RPAREN,
        ',':TOKEN_TYPES.COMMA,'>':TOKEN_TYPES.GT,'<':TOKEN_TYPES.LT};
      if (single[ch]) { this.advance(); this.tokens.push(new Token(single[ch],ch,line)); continue; }

      if (/[a-zA-Z_]/.test(ch)) {
        const id = this.readIdentifier();
        const upper = id.toUpperCase();
        if (KEYWORDS.has(id.toLowerCase())) { this.tokens.push(new Token(upper,id,line)); }
        else { this.tokens.push(new Token(TOKEN_TYPES.IDENTIFIER,id,line)); }
        continue;
      }

      this.errors.push(`Line ${line}: unexpected character '${ch}'`);
      this.advance();
    }
    this.tokens.push(new Token(TOKEN_TYPES.EOF, null, this.line));
    return this.tokens;
  }
}

module.exports = { GaptLexer, Token, TOKEN_TYPES };
