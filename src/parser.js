// GAPT Parser -- builds AST from tokens
// Sprint 05 -- Language Foundation

const { TOKEN_TYPES } = require('./lexer');

class GaptParser {
  constructor(tokens) {
    this.tokens = tokens.filter(t => t.type !== TOKEN_TYPES.COMMENT);
    this.pos = 0; this.errors = [];
    // v13 patch: bound recursion depth to prevent stack overflow on crafted .gapt input.
    this._depth = 0;
    this._maxDepth = 256;
  }

  _enter() {
    this._depth++;
    if (this._depth > this._maxDepth) {
      const t = this.peek();
      const msg = `Line ${t.line}: parser depth limit ${this._maxDepth} exceeded`;
      this.errors.push(msg);
      // Throw a structured marker that parse() catches and converts to an error result.
      throw new Error('GAPT_PARSER_DEPTH_LIMIT: ' + msg);
    }
  }
  _exit() { this._depth--; }

  peek(offset=0) { return this.tokens[this.pos+offset] || {type:TOKEN_TYPES.EOF,value:null}; }
  advance() { const t=this.tokens[this.pos]; if(this.pos<this.tokens.length-1)this.pos++; return t; }

  expect(type) {
    const t=this.advance();
    if(t.type!==type) this.errors.push(`Line ${t.line}: expected ${type} but got ${t.type} ('${t.value}')`);
    return t;
  }

  match(...types) { return types.includes(this.peek().type); }

  parseExpression() { return this.parseOr(); }

  parseOr() {
    let left=this.parseAnd();
    while(this.match(TOKEN_TYPES.OR)) {
      const op=this.advance().value; const right=this.parseAnd();
      left={type:'BinaryExpr',op,left,right};
    }
    return left;
  }

  parseAnd() {
    let left=this.parseComparison();
    while(this.match(TOKEN_TYPES.AND)) {
      const op=this.advance().value; const right=this.parseComparison();
      left={type:'BinaryExpr',op,left,right};
    }
    return left;
  }

  parseComparison() {
    let left=this.parsePrimary();
    while(this.match(TOKEN_TYPES.EQUALS,TOKEN_TYPES.NEQUALS,TOKEN_TYPES.GT,TOKEN_TYPES.LT,TOKEN_TYPES.GTE,TOKEN_TYPES.LTE)) {
      const op=this.advance().value; const right=this.parsePrimary();
      left={type:'BinaryExpr',op,left,right};
    }
    return left;
  }

  parsePrimary() {
    const t=this.peek();
    if(t.type===TOKEN_TYPES.STRING) { this.advance(); return {type:'Literal',value:t.value,kind:'string'}; }
    if(t.type===TOKEN_TYPES.NUMBER) { this.advance(); return {type:'Literal',value:t.value,kind:'number'}; }
    if(t.type===TOKEN_TYPES.TRUE)   { this.advance(); return {type:'Literal',value:true,kind:'boolean'}; }
    if(t.type===TOKEN_TYPES.FALSE)  { this.advance(); return {type:'Literal',value:false,kind:'boolean'}; }

    if(t.type===TOKEN_TYPES.IDENTIFIER) {
      this.advance();
      let node={type:'Identifier',name:t.value};
      while(this.match(TOKEN_TYPES.DOT)) {
        this.advance();
        const prop=this.expect(TOKEN_TYPES.IDENTIFIER);
        node={type:'MemberExpr',object:node,property:prop.value};
      }
      if(this.match(TOKEN_TYPES.LPAREN)) {
        this.advance();
        const args=[];
        let callerOverride=null;
        while(!this.match(TOKEN_TYPES.RPAREN)&&!this.match(TOKEN_TYPES.EOF)) {
          // 0.11.0 -- named arg `as: <expr>` for gapfn caller override.
          if(this.match(TOKEN_TYPES.AS)) {
            this.advance(); this.expect(TOKEN_TYPES.COLON);
            callerOverride=this.parseExpression();
          } else {
            args.push(this.parseExpression());
          }
          if(this.match(TOKEN_TYPES.COMMA))this.advance();
        }
        this.expect(TOKEN_TYPES.RPAREN);
        node={type:'CallExpr',callee:node,args,callerOverride};
      }
      return node;
    }

    if(t.type===TOKEN_TYPES.LPAREN) {
      this.advance(); const expr=this.parseExpression(); this.expect(TOKEN_TYPES.RPAREN); return expr;
    }

    this.errors.push(`Line ${t.line}: unexpected token: ${t.type} ('${t.value}')`);
    this.advance(); return {type:'Literal',value:null,kind:'null'};
  }

  parse() {
    const ast={type:'Program',body:[]};
    try {
      while(!this.match(TOKEN_TYPES.EOF)) { const stmt=this.parseStatement(); if(stmt)ast.body.push(stmt); }
    } catch (e) {
      // v13 patch: catch depth-limit throws so callers get a normal AST + errors[] back instead of an exception.
      if (!String(e.message || '').startsWith('GAPT_PARSER_DEPTH_LIMIT')) throw e;
    }
    return ast;
  }

  parseStatement() {
    const t=this.peek();
    if(t.type===TOKEN_TYPES.LET)     return this.parseLet();      // v31
    if(t.type===TOKEN_TYPES.IF)      return this.parseIf();       // v31
    if(t.type===TOKEN_TYPES.GAPFN)   return this.parseGapFn();    // 0.11.0
    if(t.type===TOKEN_TYPES.RETURN)  return this.parseReturn();   // 0.11.0
    if(t.type===TOKEN_TYPES.NODE)    return this.parseNode();
    if(t.type===TOKEN_TYPES.EDGE)    return this.parseEdge();
    if(t.type===TOKEN_TYPES.SEND)    return this.parseSend();
    if(t.type===TOKEN_TYPES.GRAPH)   return this.parseGraph();
    if(t.type===TOKEN_TYPES.NETWORK) return this.parseNetwork();
    this.errors.push(`Line ${t.line}: unknown statement: ${t.type} ('${t.value}')`);
    this.advance(); return null;
  }

  // v31 lang-v2: let bindings.
  //   let name = expr
  parseLet() {
    this.expect(TOKEN_TYPES.LET);
    const id = this.expect(TOKEN_TYPES.IDENTIFIER);
    this.expect(TOKEN_TYPES.ASSIGN);
    const value = this.parseExpression();
    return { type: 'VarDecl', name: id.value, value };
  }

  // v31 lang-v2: if / else conditionals.
  //   if expr { ... } [else if expr { ... }]* [else { ... }]?
  parseIf() {
    this._enter();
    try {
      this.expect(TOKEN_TYPES.IF);
      const test = this.parseExpression();
      this.expect(TOKEN_TYPES.LBRACE);
      const consequent = [];
      while (!this.match(TOKEN_TYPES.RBRACE) && !this.match(TOKEN_TYPES.EOF)) {
        const s = this.parseStatement(); if (s) consequent.push(s);
      }
      this.expect(TOKEN_TYPES.RBRACE);
      let alternate = null;
      if (this.match(TOKEN_TYPES.ELSE)) {
        this.advance();
        if (this.match(TOKEN_TYPES.IF)) {
          // else-if: wrap the nested if as a one-statement alternate.
          alternate = [this.parseIf()];
        } else {
          this.expect(TOKEN_TYPES.LBRACE);
          alternate = [];
          while (!this.match(TOKEN_TYPES.RBRACE) && !this.match(TOKEN_TYPES.EOF)) {
            const s = this.parseStatement(); if (s) alternate.push(s);
          }
          this.expect(TOKEN_TYPES.RBRACE);
        }
      }
      return { type: 'IfStmt', test, consequent, alternate };
    } finally { this._exit(); }
  }

  // 0.11.0 lang-v3: gapfn -- holographic function (function as a gap).
  //   gapfn name(arg1, arg2, ...) {
  //     guard:   <expr>     # voidguard on args, optional
  //     lock:    <expr>     # edgelock on caller, optional
  //     body:    { <stmts> }
  //     persist: true|false # optional, default false
  //   }
  parseGapFn() {
    this._enter();
    try {
      this.expect(TOKEN_TYPES.GAPFN);
      const id = this.expect(TOKEN_TYPES.IDENTIFIER);
      this.expect(TOKEN_TYPES.LPAREN);
      const params = [];
      while (!this.match(TOKEN_TYPES.RPAREN) && !this.match(TOKEN_TYPES.EOF)) {
        const p = this.expect(TOKEN_TYPES.IDENTIFIER);
        params.push(p.value);
        if (this.match(TOKEN_TYPES.COMMA)) this.advance();
      }
      this.expect(TOKEN_TYPES.RPAREN);

      const decl = { type:'GapFnDecl', name:id.value, params,
        guard:null, lock:null, body:[], persist:false };

      this.expect(TOKEN_TYPES.LBRACE);
      while (!this.match(TOKEN_TYPES.RBRACE) && !this.match(TOKEN_TYPES.EOF)) {
        const key = this.advance();
        if (key.type === TOKEN_TYPES.GUARD) {
          this.expect(TOKEN_TYPES.COLON);
          decl.guard = this.parseExpression();
        } else if (key.type === TOKEN_TYPES.LOCK) {
          this.expect(TOKEN_TYPES.COLON);
          decl.lock = this.parseExpression();
        } else if (key.type === TOKEN_TYPES.BODY) {
          this.expect(TOKEN_TYPES.COLON);
          this.expect(TOKEN_TYPES.LBRACE);
          while (!this.match(TOKEN_TYPES.RBRACE) && !this.match(TOKEN_TYPES.EOF)) {
            const s = this.parseStatement(); if (s) decl.body.push(s);
          }
          this.expect(TOKEN_TYPES.RBRACE);
        } else if (key.type === TOKEN_TYPES.PERSIST) {
          this.expect(TOKEN_TYPES.COLON);
          const v = this.advance();
          decl.persist = (v.type === TOKEN_TYPES.TRUE);
        } else {
          this.errors.push(`Line ${key.line}: unknown gapfn field: ${key.type} ('${key.value}')`);
        }
      }
      this.expect(TOKEN_TYPES.RBRACE);
      return decl;
    } finally { this._exit(); }
  }

  // 0.11.0 lang-v3: return <expr>  (bare `return` returns null).
  parseReturn() {
    this.expect(TOKEN_TYPES.RETURN);
    const t = this.peek();
    if (t.type === TOKEN_TYPES.RBRACE || t.type === TOKEN_TYPES.EOF) {
      return { type:'ReturnStmt', value:{ type:'Literal', value:null, kind:'null' } };
    }
    return { type:'ReturnStmt', value: this.parseExpression() };
  }

  parseNode() {
    this.expect(TOKEN_TYPES.NODE);
    const id=this.expect(TOKEN_TYPES.IDENTIFIER);
    const props=this.parseProps();
    return {type:'NodeDecl',id:id.value,props};
  }

  parseEdge() {
    this.expect(TOKEN_TYPES.EDGE);
    const from=this.expect(TOKEN_TYPES.IDENTIFIER);
    this.expect(TOKEN_TYPES.ARROW);
    const to=this.expect(TOKEN_TYPES.IDENTIFIER);
    const config={guard:null,label:null,lock:null,inherit:true};
    this.expect(TOKEN_TYPES.LBRACE);
    while(!this.match(TOKEN_TYPES.RBRACE)&&!this.match(TOKEN_TYPES.EOF)) {
      const key=this.advance();
      if(key.type===TOKEN_TYPES.GUARD)   { this.expect(TOKEN_TYPES.COLON); config.guard=this.parseExpression(); }
      else if(key.type===TOKEN_TYPES.LABEL)  { this.expect(TOKEN_TYPES.COLON); config.label=this.parsePrimary(); }
      else if(key.type===TOKEN_TYPES.LOCK)   { this.expect(TOKEN_TYPES.COLON); config.lock=this.parseExpression(); }
      else if(key.type===TOKEN_TYPES.INHERIT){ this.expect(TOKEN_TYPES.COLON); const v=this.advance(); config.inherit=v.type===TOKEN_TYPES.TRUE; }
    }
    this.expect(TOKEN_TYPES.RBRACE);
    return {type:'EdgeDecl',from:from.value,to:to.value,config};
  }

  parseSend() {
    this.expect(TOKEN_TYPES.SEND);
    const from=this.expect(TOKEN_TYPES.IDENTIFIER);
    this.expect(TOKEN_TYPES.ARROW);
    const to=this.expect(TOKEN_TYPES.IDENTIFIER);
    const send={data:{},key:null,travellerId:null};
    this.expect(TOKEN_TYPES.LBRACE);
    while(!this.match(TOKEN_TYPES.RBRACE)&&!this.match(TOKEN_TYPES.EOF)) {
      const key=this.advance();
      if(key.value==='data')  { this.expect(TOKEN_TYPES.COLON); send.data=this.parseObject(); }
      else if(key.value==='key')  { this.expect(TOKEN_TYPES.COLON); send.key=this.parsePrimary().value; }
      else if(key.value==='as')   { this.expect(TOKEN_TYPES.COLON); send.travellerId=this.parsePrimary().value; }
    }
    this.expect(TOKEN_TYPES.RBRACE);
    return {type:'SendStmt',from:from.value,to:to.value,send};
  }

  parseGraph() {
    this._enter();
    try {
      this.expect(TOKEN_TYPES.GRAPH);
      const name=this.expect(TOKEN_TYPES.IDENTIFIER);
      const body=[];
      this.expect(TOKEN_TYPES.LBRACE);
      while(!this.match(TOKEN_TYPES.RBRACE)&&!this.match(TOKEN_TYPES.EOF)) {
        const stmt=this.parseStatement(); if(stmt)body.push(stmt);
      }
      this.expect(TOKEN_TYPES.RBRACE);
      return {type:'GraphDecl',name:name.value,body};
    } finally { this._exit(); }
  }

  parseNetwork() {
    this.expect(TOKEN_TYPES.NETWORK);
    const graphs=[];
    this.expect(TOKEN_TYPES.LBRACE);
    while(!this.match(TOKEN_TYPES.RBRACE)&&!this.match(TOKEN_TYPES.EOF)) {
      this.expect(TOKEN_TYPES.GRAPH); graphs.push(this.expect(TOKEN_TYPES.IDENTIFIER).value);
    }
    this.expect(TOKEN_TYPES.RBRACE);
    return {type:'NetworkDecl',graphs};
  }

  parseObject() {
    const obj={};
    this.expect(TOKEN_TYPES.LBRACE);
    while(!this.match(TOKEN_TYPES.RBRACE)&&!this.match(TOKEN_TYPES.EOF)) {
      const key=this.advance().value; this.expect(TOKEN_TYPES.COLON);
      const val=this.parsePrimary(); obj[key]=val.value;
      if(this.match(TOKEN_TYPES.COMMA))this.advance();
    }
    this.expect(TOKEN_TYPES.RBRACE); return obj;
  }

  parseProps() {
    if(!this.match(TOKEN_TYPES.LBRACE))return {};
    return this.parseObject();
  }
}

module.exports = { GaptParser };
