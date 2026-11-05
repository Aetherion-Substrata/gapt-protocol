// GAPT Interpreter -- executes AST against GaptGraph engine
// Sprint 05 -- Language Foundation

const { GaptGraph }   = require('./gapt');
const { GaptNetwork } = require('./network');

class GaptInterpreter {
  constructor() {
    this.graphs  = {}; this.network = null;
    this.results = []; this.errors  = []; this.log = [];
    // v31 lang-v2: top-level scope for `let` bindings. Flat namespace; if-branch
    // assignments leak to the surrounding scope (config-DSL semantics, not JS-let).
    this.scope = Object.create(null);
    // 0.11.0 lang-v3 -- holographic gapfn state.
    // Registry of declared gapfns. Each entry holds the internal one-edge graph
    // that routes every call through GaptEdge.transmit() -- the call IS the gap.
    this.fns = Object.create(null);
    // Active function-call frame chain. null at top level. Each call pushes a
    // frame with param bindings and lexical `let`s; pops on return. Lookups walk
    // frame -> parent frame -> this.scope (the flat top-level).
    this._currentFrame = null;
    // Name of the gapfn currently executing, for default caller-id propagation.
    this._enclosingFn = null;
    // Safety-net recursion bound. Behavioural lockdown handles attacker cases
    // (rapid failing recursion locks at 4-of-5 like any other gap), but a fn
    // that recurses ALWAYS PASSING would crash the JS stack -- not gap-y, just
    // unsound. Cap call depth at a generous 256 (same as parser depth) and emit
    // a structured GAPT_CALL_DEPTH_LIMIT error rather than a stack overflow.
    this._callDepth = 0;
    this._maxCallDepth = 256;
  }

  evalExpr(node, context={}) {
    if (!node) return true;
    switch(node.type) {
      case 'Literal': return node.value;
      case 'Identifier':
        if(node.name==='data') return context.data;
        if(node.name==='key')  return context.key;
        // v31 lang-v2: scope lookup falls back when context doesn't have the name.
        if (Object.prototype.hasOwnProperty.call(context, node.name)) return context[node.name];
        // 0.11.0 lang-v3: function-local frame takes precedence over top-level scope.
        if (this._currentFrame && Object.prototype.hasOwnProperty.call(this._currentFrame, node.name)) {
          return this._currentFrame[node.name];
        }
        if (this.scope && Object.prototype.hasOwnProperty.call(this.scope, node.name)) return this.scope[node.name];
        return null;
      case 'MemberExpr': {
        const obj=this.evalExpr(node.object,context);
        if(obj===null||obj===undefined) return null;
        return obj[node.property] ?? null;
      }
      case 'CallExpr': {
        const callee=node.callee;
        if(callee.type==='MemberExpr') {
          const obj=this.evalExpr(callee.object,context);
          const method=callee.property;
          const args=node.args.map(a=>this.evalExpr(a,context));
          if(obj!==null&&typeof obj[method]==='function') return obj[method](...args);
          return null;
        }
        // 0.11.0 lang-v3: identifier callee = gapfn invocation.
        if(callee.type==='Identifier') {
          const args=node.args.map(a=>this.evalExpr(a,context));
          let caller=null;
          if(node.callerOverride) caller=this.evalExpr(node.callerOverride,context);
          return this._callGapFn(callee.name, args, caller);
        }
        return null;
      }
      case 'BinaryExpr': {
        const left=this.evalExpr(node.left,context);
        const right=this.evalExpr(node.right,context);
        switch(node.op) {
          case '==': return left===right;
          case '!=': return left!==right;
          case '>':  return left>right;
          case '<':  return left<right;
          case '>=': return left>=right;
          case '<=': return left<=right;
          case '&&': return left&&right;
          case '||': return left||right;
          default:   return false;
        }
      }
      default: return null;
    }
  }

  buildVoidguard(exprNode) {
    if(!exprNode) return ()=>true;
    const interp=this;
    return (data)=>!!interp.evalExpr(exprNode,{data});
  }

  buildEdgelock(exprNode) {
    if(!exprNode) return null;
    const interp=this;
    return (key,data)=>!!interp.evalExpr(exprNode,{key,data});
  }

  execute(ast) {
    // v21 patch: defensive wrap. Reject bad shapes, catch per-stmt throws.
    if (!ast || typeof ast !== 'object') {
      this.errors.push('execute: ast must be an object');
      return this.results;
    }
    const body = ast.body;
    if (!Array.isArray(body)) {
      this.errors.push('execute: ast.body must be an array');
      return this.results;
    }
    for (const stmt of body) {
      if (!stmt || typeof stmt !== 'object') {
        this.errors.push('execute: skipped null/non-object stmt');
        continue;
      }
      try { this.executeStmt(stmt, null); }
      catch (e) {
        this.errors.push('execute: ' + (e && e.message ? e.message : String(e)));
      }
    }
    return this.results;
  }

  executeStmt(stmt, graphContext) {
    switch(stmt.type) {
      case 'GraphDecl': {
        const graph=new GaptGraph({autoRestore:false});
        this.graphs[stmt.name]=graph;
        this.log.push(`  [GRAPH] [${stmt.name}] created`);
        for(const child of stmt.body) this.executeStmt(child,graph);
        break;
      }
      case 'NetworkDecl': {
        this.network=new GaptNetwork();
        for(const gName of stmt.graphs) {
          if(this.graphs[gName]) { this.network.register(this.graphs[gName]); this.log.push(`  [NET] registered graph [${gName}]`); }
          else this.errors.push(`Network: unknown graph '${gName}'`);
        }
        break;
      }
      case 'NodeDecl': {
        const g=graphContext;
        if(!g){this.errors.push('NodeDecl outside graph');break;}
        g.addNode(stmt.id,stmt.props||{});
        this.log.push(`  [NODE] [${stmt.id}] added`);
        break;
      }
      case 'EdgeDecl': {
        const g=graphContext;
        if(!g){this.errors.push('EdgeDecl outside graph');break;}
        const cfg=stmt.config || { guard:null, label:null, lock:null, inherit:true };
        g.addEdge(stmt.from,stmt.to,{
          bridgetype: cfg.label?.value||`${stmt.from}->${stmt.to}`,
          voidguard:  this.buildVoidguard(cfg.guard),
          edgelock:   this.buildEdgelock(cfg.lock),
          inherit:    cfg.inherit!==false,
        });
        this.log.push(`  [EDGE] [${stmt.from} -> ${stmt.to}] added`);
        break;
      }
      case 'SendStmt': {
        let g=graphContext;
        if(!g) g=Object.values(this.graphs).find(gr=>gr.nodes[stmt.from]&&gr.nodes[stmt.to]);
        if(!g){this.errors.push(`Send: no graph with [${stmt.from}] and [${stmt.to}]`);break;}
        const result=g.send(stmt.from,stmt.to,stmt.send.data,stmt.send.key,
          stmt.send.travellerId?{travellerId:stmt.send.travellerId}:{});
        result._from=stmt.from; result._to=stmt.to;
        this.results.push(result);
        const icon=result.passed?'PASS':result.predicted?'PRED':'FAIL';
        this.log.push(`  [${icon}] [${stmt.from} -> ${stmt.to}] -- ${result.reason}`);
        break;
      }
      // v31 lang-v2 statements
      case 'VarDecl': {
        const v = this.evalExpr(stmt.value, {});
        // 0.11.0 lang-v3: inside a function frame, let is local to the frame.
        // At top level, let stays flat (writes to this.scope).
        if (this._currentFrame) this._currentFrame[stmt.name] = v;
        else this.scope[stmt.name] = v;
        this.log.push(`  [LET] ${stmt.name} = ${JSON.stringify(v)}`);
        break;
      }
      case 'IfStmt': {
        const cond = !!this.evalExpr(stmt.test, {});
        this.log.push(`  [IF] ${cond ? 'then' : 'else'} branch`);
        const body = cond ? stmt.consequent : stmt.alternate;
        if (Array.isArray(body)) {
          for (const s of body) this.executeStmt(s, graphContext);
        }
        break;
      }
      // 0.11.0 lang-v3: holographic function declaration. Wraps the body in a
      // one-edge GaptGraph so every call routes through the same threat/trust/
      // lockdown machinery that defends edges. The function IS a gap.
      case 'GapFnDecl': {
        const interp = this;
        const decl = stmt;
        // Internal graph: '__fn' -> '<name>'. The edge filename namespace
        // (gap___fn_<name>.json) is disjoint from real edges because no user
        // graph contains a '__fn' node.
        const graph = new GaptGraph({ autoRestore: !!decl.persist });
        graph.addNode('__fn', {});
        graph.addNode(decl.name, {});
        const voidguard = decl.guard
          ? (data) => {
              // Eval guard with args spread (so `guard: size < 100` works)
              // PLUS the data context (so `guard: data.size < 100` works too).
              const ctx = Object.assign({ data }, data || {});
              return !!interp.evalExpr(decl.guard, ctx);
            }
          : null;
        const edgelock = decl.lock
          ? (key, data) => {
              const ctx = Object.assign({ key, data, caller:key }, data || {});
              return !!interp.evalExpr(decl.lock, ctx);
            }
          : null;
        graph.addEdge('__fn', decl.name, {
          bridgetype: 'gapfn:' + decl.name,
          voidguard, edgelock, inherit: true,
        });
        this.fns[decl.name] = {
          name: decl.name, params: decl.params,
          guard: decl.guard, lock: decl.lock, body: decl.body,
          persist: !!decl.persist, graph, edge: graph.edges[0]
        };
        this.log.push(`  [GAPFN] ${decl.name}(${decl.params.join(', ')})${decl.persist?' [persist]':''}`);
        break;
      }
      // 0.11.0 lang-v3: return statement. Throws a structured marker that the
      // call-evaluator catches. Outside a function, lands in errors[].
      case 'ReturnStmt': {
        const v = this.evalExpr(stmt.value, this._currentFrame || {});
        const marker = new Error('__gapt_return__');
        marker.__gapt_return__ = true;
        marker.value = v;
        throw marker;
      }
    }
  }

  // 0.11.0 lang-v3: call a registered gapfn. Routes through the internal edge
  // so guard/lock/memory/lockdown/trust/patterns all apply identically to how
  // they apply to a user-declared edge. The function call IS an edge round-trip.
  _callGapFn(name, args, callerOverride) {
    const fn = this.fns[name];
    if (!fn) {
      this.errors.push(`gapfn '${name}' not found`);
      this.log.push(`  [FN-MISSING] ${name}`);
      return null;
    }
    // Caller id: explicit override > enclosing fn name > 'top-level'.
    const caller = (callerOverride != null && callerOverride !== '')
      ? String(callerOverride)
      : (this._enclosingFn || 'top-level');
    // Build args object for the voidguard/edgelock context AND bind params.
    const argsObj = Object.create(null);
    const frame = Object.create(null);
    for (let i = 0; i < fn.params.length; i++) {
      const p = fn.params[i];
      const v = (i < args.length) ? args[i] : null;
      argsObj[p] = v;
      frame[p] = v;
    }
    // Safety net: catch pathological recursion before the JS stack does.
    if (this._callDepth >= this._maxCallDepth) {
      const msg = `gapfn '${name}': call depth ${this._maxCallDepth} exceeded`;
      this.errors.push(msg);
      this.log.push(`  [FN-DEPTH] ${msg}`);
      return null;
    }
    // Route through the gap. Lockdown / threat patterns / trust accounting
    // all happen here -- same code path as a regular edge.transmit().
    const result = fn.edge.transmit(argsObj, caller, {});
    if (!result.passed) {
      this.log.push(`  [FN-FAIL] ${name} -- ${result.reason}`);
      return null;
    }
    // Push frame and run body. Recursion bound = lockdown (no separate counter).
    const prevFrame = this._currentFrame;
    const prevEnclosing = this._enclosingFn;
    this._currentFrame = frame;
    this._enclosingFn = name;
    this._callDepth++;
    try {
      for (const s of fn.body) this.executeStmt(s, null);
      return null; // body fell through without return
    } catch (e) {
      if (e && e.__gapt_return__) return e.value;
      throw e;
    } finally {
      this._currentFrame = prevFrame;
      this._enclosingFn = prevEnclosing;
      this._callDepth--;
    }
  }

  // 0.11.0 lang-v3: public introspection. Same shape as gapStatus().
  fnStatus(name) {
    const fn = this.fns[name];
    if (!fn) return null;
    const s = fn.edge.status();
    return Object.assign({ name, params: fn.params, persist: fn.persist }, s);
  }

  fnReset(name, authority) {
    const fn = this.fns[name];
    if (!fn) return false;
    fn.edge.memory.reset(authority || 'system');
    if (fn.persist) fn.edge.persist();
    return true;
  }
}

module.exports = { GaptInterpreter };
