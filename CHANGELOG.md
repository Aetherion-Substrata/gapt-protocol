# Changelog

All notable changes to **@gapt/protocol** are documented in this file. Format roughly follows [Keep a Changelog](https://keepachangelog.com/), versioning is [SemVer](https://semver.org/).

## [0.12.0] -- 2026-07-04

### Added

- **`bridgeclass`** -- optional typed property on edges. Six classes: `relay`, `guard`, `signal`, `boundary`, `transform`, `trust`. Each class changes what the gap enforces during transmission. Fully backward-compatible — omit it and nothing changes.

## [0.11.0] -- 2026-05-28

**Holographic gapfn.** Every function in `.gapt` is a gap. Each call routes through `GaptEdge.transmit()` under the hood, so the same threat patterns, trust accounting, lockdown, and persistence that defend edges defend functions. Programs declared in `.gapt` are now built out of the same primitives they protect.

### Added

- **`gapfn name(args...) { guard:... lock:... body:{...} persist:true|false }`** -- new top-level declaration in the `.gapt` language. The function body is wrapped in a one-edge internal `GaptGraph` (`__fn -> <name>`). Every invocation goes through `edge.transmit()`. Voidguard wraps the optional `guard:` expression -- args appear as named scope variables and as `data`. Edgelock wraps the optional `lock:` expression -- caller-id appears as `caller` (and as `key`). `body:` is a brace-delimited statement block ending in `return <expr>`; bare `return` returns `null`.
- **Caller-id is a first-class concept.** By default the caller of a `gapfn` is `"top-level"` (or the enclosing `gapfn`'s name for nested calls). Call sites can override with the named arg syntax: `isAdmin(key, as: "auth-flow")`. The caller string becomes the edgelock key and gets recorded in `edge.memory.attempts[].keySignature`.
- **`persist: true`** -- opt-in HMAC-signed disk persistence using the existing 0.6.0 seal. File namespace is `data/gap___fn_<name>.json` (disjoint from real edges; no user node is named `__fn`). Lockdowns and trust survive process restart, restored automatically via `autoRestore` on the internal graph.
- **`GaptInterpreter.fnStatus(name)`** -- returns the same shape as `gapStatus(from, to)` plus `name`, `params`, and `persist`. `null` for unknown names.
- **`GaptInterpreter.fnReset(name, authority?)`** -- mirrors `resetGap()`. Clears the lockdown, rebases trust to `40 * (passCount / total)`, persists if the fn was declared `persist: true`. Default authority is `'system'`.
- **Lexical scope inside `gapfn` bodies.** Params and body `let`s are local to the call frame and don't leak to the surrounding scope. Top-level `let` semantics from 0.8.0 are unchanged -- still flat at the top level.
- **`return` statement.** Throws a structured marker that the call evaluator catches and unwraps. Outside a function it lands in `errors[]` as `'return outside function'` -- never crashes the process.
- **Safety-net recursion bound.** Behavioural lockdown handles attacker-shaped recursion (rapid failing self-calls hit 4-of-5 lockdown like any other gap). Pathological always-passing recursion (e.g. `gapfn loop() { body: { return loop() } }`) is caught by an interpreter-level `_maxCallDepth` (default 256, mirrors the parser depth bound) and returns `null` with a `GAPT_CALL_DEPTH_LIMIT` error in `errors[]` instead of a JS stack overflow.
- **`examples/lang-v3.gapt`** -- runnable demo combining a reusable `validPayload(d)` guard, an `isAdmin(k)` lock with `lock: caller == "auth-flow"`, and an edge that calls both via the new function-as-expression syntax.
- **`tests/sprint06.js`** -- 13 cases covering: simple call returns body value; guard rejects; lock rejects; lockdown at 5 wrong callers; trust climbs to FAMILIAR; closure reads top-level `let`; local `let` does not leak; recursion safety net; `fnStatus` shape; `fnReset` clears lock; two gapfns track independently; gapfn used as an edge `lock:` (composition); `persist: true` survives reload in a fresh interpreter.
- **`tests/sprint06-fuzz.js`** -- random gapfn generator. ~10k cases, soft-capped at 10 seconds, runs as `npm run test:fuzz`. Zero uncaught exceptions is the pass condition.
- **`package.json` scripts** -- `test` now includes sprint06; new `test:fuzz` (gapfn grammar), new `test:all` chains test + fuzz + security; new `example:v3` runs `lang-v3.gapt`.
- **TypeScript types** -- `lexer.d.ts` gains `GAPFN`, `BODY`, `RETURN`, `AS`, `PERSIST` token types. `parser.d.ts` gains `GapFnDecl`, `ReturnStmt` AST nodes plus `CallExpr.callerOverride`. `interpreter.d.ts` gains `fns` registry, `fnStatus`, `fnReset`.

### Changed

- **Browser bundle picks up lang v3 automatically.** No shim changes needed -- `gapfn` is lang-only and depends on no Node APIs. `window.Gapt.GaptInterpreter.fnStatus` / `fnReset` available client-side. Rebuilt via the same zero-dep bundler.
- **`CallExpr` identifier-callee path** -- previously this parsed but evaluated to `null`. Now it dispatches to `_callGapFn`. Pure addition for callers; no existing test relied on the silent-null behaviour.

### Verified

- `sprint01 .. sprint04` + `browser-smoke` from 0.10.0 still pass unchanged.
- `sprint06`: 13 PASS / 0 FAIL.
- `sprint06-fuzz`: 0 uncaught exceptions across ~10k generated programs (lex + parse + interpret round-trip).
- `examples/lang-v3.gapt` runs cleanly via `npm run example:v3`.
- `examples/lang-v2.gapt` (the 0.8.0 demo) runs identically -- no regression on lang-v2 semantics.

### Upgrade

Drop-in. Pure additive at every layer:
- The lexer adds 5 keywords -- if you have an identifier literally named `gapfn`, `body`, `return`, `as`, or `persist`, you'll need to rename it. Unlikely in practice (none of the existing examples or tests collide).
- The parser adds two statement types -- existing `.gapt` programs parse identically.
- The interpreter adds one new switch arm for each new AST node and one new registry. Existing edge / graph / network / let / if execution unchanged.
- No persistence-file format change. Existing snapshots from 0.6.0+ still load identically.

The big idea: a `gapt` program is now made of the same primitives it protects. The launch story for this release is one sentence -- "in gapt, a function defends itself the same way an edge does."

---

## [0.10.0] -- 2026-05-28

**Browser build.** Drop-in `<script>` tag, zero deps, same API surface as the Node package. In-memory persistence shim is included; HMAC-signed disk persistence remains Node-only.

### Added

- **`dist/gapt.browser.js`** -- single-file IIFE bundle (~60 KB unminified, ~13 KB gzipped). Exposes `window.Gapt` containing every constructor and helper the README and 0.9.0 `.d.ts` advertise: `GaptGraph`, `GaptEdge`, `GaptMemory`, `GaptFingerprint`, `GaptNetwork`, `GaptLexer`, `GaptParser`, `GaptInterpreter`, `getTrustTier`, `DEFAULT_TRUST_CONFIG`, `Token`, `TOKEN_TYPES`, `version`.
- **`dist/gapt.browser.d.ts`** -- ambient `Window.Gapt` augmentation. TypeScript projects loading the script tag get full typings.
- **`src/persist.browser.js`** -- in-memory, sync, API-compatible stub for the Node `persist.js`. `saveGapMemory` / `loadGapMemory` use a process-local `Map`. `ensureHandshake` is a no-op `{ ok: true, reason: 'BROWSER_INMEMORY' }`. Refreshing the page wipes state. Real localStorage / IndexedDB + WebCrypto persistence is parked for v0.11.
- **`build/build-browser.js`** -- zero-dep bundler. Concats `src/` modules in dep order with a tiny CommonJS shim. No webpack / rollup / esbuild devDependency added; `package.json` `dependencies` and `devDependencies` are still both empty.
- **`tests/browser-smoke.js`** -- runs the built bundle inside a Node VM context that exposes ONLY browser-safe globals. `fs`, `crypto`, `process`, `Buffer`, `require`, `__dirname` are NOT in the sandbox. Asserts the full surface, happy-path transmit, lockdown after 6 failed keys, `GaptNetwork` wiring, and a `.gapt` lang round-trip (lex -> parse -> execute -> `passed: true`).
- **`package.json` `browser` / `unpkg` / `jsdelivr` fields** -- CDN-default. `<script src="https://unpkg.com/@gapt/protocol"></script>` serves `dist/gapt.browser.js` automatically.
- **`prepublishOnly` hook** -- runs `build:browser` so the npm tarball always ships a fresh bundle even if a contributor forgets the build step.

### Fixed

- **`GaptNetwork` is now actually exported from the main entry.** Through 0.9.0 the README and `src/gapt.d.ts` both advertised `const { GaptNetwork } = require('@gapt/protocol')`, but the runtime `module.exports` in `src/gapt.js` omitted it -- calling `new GaptNetwork()` after a destructure from the main entry crashed with `undefined is not a constructor`. Two-line fix in `src/gapt.js` (added the `require('./network')` and added `GaptNetwork` to the exports object). Now matches the docs and the types.

### Verified

- `npm test` is now `sprint01 && sprint02 && sprint03 && sprint04 && browser-smoke` -- 24 PASS / 0 FAIL on browser-smoke, sprints unchanged.
- Browser-smoke runs in a sandboxed VM with Node globals stripped. If any code path inside the bundle reached for `fs` / `crypto` / `process` / `Buffer`, the test would crash on the first call. It doesn't.
- Bundle size: 60,328 bytes unminified.

### Upgrade

Drop-in for Node users -- the `GaptNetwork` fix is additive, no removals. New for browser users: `<script src="https://unpkg.com/@gapt/protocol"></script>` then `new window.Gapt.GaptGraph()`. The browser shim has no persistence; if you need state across page loads in the browser, hold v0.10 and wait for v0.11.

---

## [0.9.0] -- 2026-05-27

**Programmable Gapt + TypeScript types + README refresh.** Bundles the 0.8.0 iteration (lang v2: `let` / `if` / `else`) that was staged but never published as its own npm release, plus this release's new TypeScript types and rewritten README. See the 0.8.0 entry below for full lang v2 details.

### Added

- **`src/gapt.d.ts`** -- types for the main entry. Covers `GaptGraph`, `GaptEdge`, `GaptMemory`, `GaptFingerprint`, `getTrustTier`, `DEFAULT_TRUST_CONFIG`, plus a re-export of `GaptNetwork`.
- **`src/network.d.ts`** -- types for `GaptNetwork`, the v0.7.0 `NetworkOptions { propagationRadius }`, `NetworkStatus`, `GaptAlert`.
- **`src/persist.d.ts`** -- types for `saveGapMemory`, `loadGapMemory`, `listPersistedGaps`, `deleteGapMemory`, `ensureSecret`, `canonicalStringify`, `signSnapshot`, `verifySnapshot`, and the v0.7.0 `ensureHandshake` (+ its `HandshakeResult` discriminated union).
- **`src/lexer.d.ts`** -- types for `GaptLexer`, `Token`, `TOKEN_TYPES`, including the v0.8.0 `LET` / `IF` / `ELSE` / `ASSIGN` tokens.
- **`src/parser.d.ts`** -- types for `GaptParser` and the full AST node union (including v0.8.0 `VarDecl` and `IfStmt`).
- **`src/interpreter.d.ts`** -- types for `GaptInterpreter`, exposing the v0.8.0 `scope` field.
- **`package.json` `types` field** -- points TS resolution at `src/gapt.d.ts` automatically.

### Changed

- **README rewritten** to reflect what shipped in 0.6.3 / 0.7.0 / 0.8.0:
  - Quickstart now uses `@gapt/protocol`.
  - New sections: *Network defence -- bounded blast radius*, *Multi-replica handshake*, *TypeScript*.
  - Operations guide notes the handshake check, key-rotation includes a step to delete the stale handshake file.
  - Features list updated; roadmap collapsed to reflect actual shipped state.
  - npm + types badges added.

### Verified

- `tsc --strict --noEmit` against `tests/type-smoke.ts` (in the v36 iteration scope) compiles cleanly.
- Smoke covers: build a graph + send; v0.7.0 `propagationRadius` config + `networkStatus`; v0.7.0 `ensureHandshake`; v0.8.0 lang v2 lex+parse+execute round-trip; let-bound scope reads.

### Upgrade

Drop-in. No runtime change. TypeScript users will start getting type errors on previously-untyped calls -- treat as opportunity for cleanup.

---

## [0.8.0] -- 2026-05-27

**Programmable Gapt.** The `.gapt` language gains real variables and conditionals. Closes the v31 iteration started 2026-05-26.

### Added

- **`let` bindings.** Top-level `let name = expr` writes a named value into the interpreter's scope. Values resolve in any expression downstream -- including the `lock:` and `guard:` clauses of an `edge` declaration, so a single named secret can be referenced from any number of edges.
- **`if` / `else` / `else if` conditionals.** Branch on environment, role, or any expression that can be evaluated to a boolean. Both branches accept the full statement grammar (nodes, edges, sends, nested ifs, nested lets).
- **`examples/lang-v2.gapt`** -- runnable demo combining both new constructs.

### How it looks

```gapt
let masterKey = "secret-123"
let env       = "prod"

graph main {
  node user  { role: "client" }
  node vault { role: "storage" }

  if env == "prod" {
    edge user -> vault { guard: data.type == "valid"  lock: key == masterKey }
  } else {
    edge user -> vault { guard: data.type == "valid"  lock: key == "dev-key" }
  }

  send user -> vault { data: { type: "valid" }  key: "secret-123" }
}
```

Same payload as the v1 demo, but config can now branch on environment and reuse named secrets without copy-paste.

### Semantics

- **Flat scope.** A `let` inside an `if` block leaks to the surrounding scope. Treat `.gapt` files like environment-variable manifests, not function bodies.
- **Identifier resolution priority.** `data` and `key` win first (runtime shortcuts). Then the caller-supplied context. Then the let-bound scope. A `let data = ...` therefore cannot shadow the runtime `data`.
- **Depth-guarded.** `parseIf` uses the same `_enter()/_exit()` guard the v32 expression parser uses. Crafted `.gapt` with thousands of nested `if`s returns a clean parser-depth error rather than crashing.

### Backward compatibility

- All additions are additive. Legacy `.gapt` programs that never used `let` / `if` parse and execute identically.
- Public API of `GaptInterpreter` is unchanged except for a new `scope` field, which callers can ignore.
- No persistence-file format change, no env-var contract change.

### Out of scope (deliberately deferred)

- Function declarations with closures (callable user functions are a larger semantics commitment).
- Block-scoped `let` (today every `let` is global to the program).
- `while` / `for` loops (a config DSL shouldn't have unbounded iteration).
- Imports / multi-file programs.

### Upgrade

Drop-in. `npm update @gapt/protocol` is sufficient. Existing programs keep working; mix in `let` / `if` wherever it helps.

---

## [0.7.0] -- 2026-05-27

**The Blast-Radius release.** Two opt-in safety features land alongside the 0.6.3 parser fix: operators can now bound how far a single edge's alerts propagate across the network, and multi-replica deployments are protected against silent HMAC-secret drift.

### Added

- **Bounded blast-radius propagation on `GaptNetwork`.** New constructor option `{ propagationRadius: k }` (default `Infinity`, preserves legacy behaviour). Set to `0` to silence cross-edge propagation, `1` for immediate neighbours only, or any `k` for k-hop edge-adjacency BFS. Two edges are adjacent when they share an endpoint node; distance is computed on demand and is sub-millisecond on a 1000-edge mesh.
  - `new GaptNetwork({ propagationRadius: 2 })`
  - `network.setPropagationRadius(k)` / `network.getPropagationRadius()`
  - `networkStatus().propagationRadius` exposes the current value.
- **Multi-replica HMAC handshake.** New `persist.ensureHandshake()` writes a `.gapt-handshake.json` file on first boot and verifies a key fingerprint on every later boot. If two replicas share a `data/` directory under different `GAPT_HMAC_SECRET` values, the misconfig now fails loud at startup instead of looking like a `[TAMPERED]` security incident at runtime. Auto-invoked once per process from `saveGapMemory` / `loadGapMemory`. Strict mode via `GAPT_HANDSHAKE_STRICT=1` raises `GAPT_HANDSHAKE_MISMATCH` instead of returning a `{ok:false}` result; default is warn-and-continue for backward compatibility.

### Iteration history

- **v32** parser fuzz (already shipped as 0.6.3).
- **v33** bounded blast-radius -- 17/17 property checks PASS first attempt.
- **v34** multi-replica handshake -- 21/21 checks PASS first attempt across boot replays.

### Backward compatibility

- No API breaks. All additions are new methods / new optional constructor arg.
- Defaults preserve pre-0.7.0 behaviour: `propagationRadius = Infinity` (every edge sees every alert) and non-strict handshake mode (warn, don't throw).
- No persistence-file format change. `.gapt-handshake.json` is a new sibling file in `data/`.
- Existing migration path from 0.4.x / 0.5.x continues to work unchanged.

### Upgrade

Drop-in. `npm update @gapt/protocol` is sufficient. If you operate multiple replicas sharing a `data/` directory, set `GAPT_HANDSHAKE_STRICT=1` on each replica's boot env to surface secret drift as a hard fail instead of a runtime warning.

### Recommended

- Multi-tenant SaaS: set `propagationRadius` to your tenant-isolation radius (often `0` or `1`) to prevent one bad customer from poisoning the trust state of every other customer-facing edge.
- Microservice mesh: `propagationRadius: 2` keeps alert delivery in the immediate neighbourhood without cascading mesh-wide.
- Small private deployments: leave `propagationRadius` unset to keep the legacy full-broadcast behaviour.

---

## [0.6.3] -- 2026-05-27

**Security patch release.** Closes two unbounded-recursion DoS paths in the `.gapt` expression parser that the v13 depth guard did not cover. Found by the v32 property-based parser fuzz suite (Blast-Radius Arc, sprint 1/3).

### Fixed

- **Parser DoS via nested parens.** `edge a -> b { guard: ((((true)))) }` with roughly 1,632 levels of nesting would crash V8 with a stack overflow. The LPAREN branch in `parsePrimary` re-enters `parseExpression` without bound.
- **Parser DoS via nested call expressions.** `edge a -> b { guard: f(f(f(...))) }` with roughly 5,223 levels would crash V8 likewise. CallExpr args re-enter `parseExpression`.
- Both crash classes are exploitable by any service that parses untrusted `.gapt` (the v29 Express adapter pattern in particular).

### Changed

- `src/parser.js`: `parseExpression()` now wraps its body in the existing `_enter()/_exit()` depth guard (the same guard v13 added to `parseGraph()`). Default `_maxDepth = 256` applies. Hostile input now returns a normal AST with `errors[]` containing a `GAPT_PARSER_DEPTH_LIMIT` line instead of throwing out of the process.

### Verified

- `tests/probe-depth-limits.js` (in iteration scope, `gapt-iteration/v32-20260527-parser-fuzz/`) -- both crash classes now clean to n=8192.
- `tests/sprint32-parser-fuzz.js --runs 10000` -- 8/8 PASS post-patch.
- Existing `npm test` (sprint01-04) and `npm run test:security` (sprint19/20) unchanged.

### Upgrade

Drop-in. No API change, no env-var change, no data-file change. `npm update @gapt/protocol` is sufficient.

---

## [0.6.2] -- 2026-05-27

**Naming-only release.** Final name: `@gapt/protocol` (under the `gapt` npm organization). Replaces the never-published `@bigvikclaw/gapt` interim name from 0.6.1. Functionally identical to 0.6.0.

### Changed
- `package.json` `name`: `@bigvikclaw/gapt` -> `@gapt/protocol`.
- Install: `npm install @gapt/protocol`.

## [0.6.1] -- 2026-05-27 (not published to npm)

Interim rename attempt to `@bigvikclaw/gapt`. Superseded by 0.6.2 before any npm publish.

## [0.6.0] -- 2026-05-26

**Security release.** Closes the entire "trust-the-file" class found during the v22-v24 iteration stress run, plus the in-memory inheritance-registry mutation path. Persistence snapshots are now HMAC-signed; the inheritance registry is now a private class field. Upgrade path includes a one-shot migration story.

> Version jump 0.4.0 -> 0.6.0 (skipped 0.5.0) because the changes well exceed a patch release: new persistence file format, new env-var contract, one breaking-but-undocumented API change (`graph._inheritanceRegistry`).

### Added

- **HMAC-signed persistence snapshots.** All `data/gap_*.json` files now live inside a `{ v:1, body, hmac:"sha256:..." }` envelope. The signature is computed over a canonicalized (key-sorted, whitespace-free) serialization of the body so two processes signing the same logical state always agree. Verify-fail is fail-safe: rejected files leave the edge with trust=0, same path as a corrupt file today, with a `[TAMPERED]` warning logged.
- **Env-var-first key management.** `GAPT_HMAC_SECRET` (32+ bytes hex or utf8 string) is the production knob. If unset, gapt auto-generates `data/.gapt-hmac-secret` on first boot with a logged warning. No silent off-switch.
- **Key rotation.** `GAPT_HMAC_SECRET_PREV` is checked as a fallback verify key. Files signed under the previous key are accepted and immediately re-signed with the current key. Operators drop `_PREV` once the next save cycle confirms migration is complete.
- **One-shot migration grace flag.** Set `GAPT_HMAC_ACCEPT_UNSIGNED=1` for a single boot to load unsigned 0.4.x/0.5.x snapshots and auto-re-sign them.
- **`bin/gapt-resign` CLI.** Idempotent migration helper: walks `data/`, loads each unsigned snapshot under the grace flag, writes back signed. Safe to run multiple times.
- **`GaptGraph#getRegistrySnapshot()`.** Read-only diagnostic accessor for the inheritance registry. Returns a deep-frozen clone; external mutation throws / silently fails depending on strict mode, and never affects the live registry.
- **Sprint 20 (security regression suite).** 8 cases / 11 checks covering: unsigned forgery, wrong-secret HMAC, right-secret HMAC, migration flow, rotation flow, post-sign body tampering, in-memory inheritance mutation, frozen diagnostic snapshot.
- **`npm run test:security`** runs sprint19 + sprint20.

### Changed

- `src/persist.js` rewritten with the HMAC layer. Existing public API (`saveGapMemory`, `loadGapMemory`, `listPersistedGaps`, `deleteGapMemory`) is preserved -- no caller-side changes required.
- `src/gapt.js`: `GaptGraph._inheritanceRegistry` swapped for the private class field `#inheritanceRegistry`. `retireEdge()` writes via the private field; `addEdge()` reads via it. External callers cannot reach it.
- `src/gapt.js GaptMemory.restoreFrom()` retains the v23 field-clamping and v24 history-check as belt-and-braces. They are now redundant for the file-forgery attack (HMAC kills it earlier) but cost near-zero and defend any future code path that might bypass `persist.js`.

### Fixed

Patches accumulated across iteration batches 1-4 are now part of the source tree:

- v06: circular-ref-safe `JSON.stringify` for snapshots (`gapt.js`, `persist.js`).
- v08: `accessKey` is coerced to string before any string op in `transmit()`.
- v09: global try/catch in `transmit()` returns structured `GAP_EXCEPTION` log instead of propagating any caller-input crash.
- v13: parser stack-overflow guard.
- v19: live `attempts` array capped at `GAPT_ATTEMPTS_MAX = 256`.
- v20: `network.broadcast` / `register` input guards; alert-shape validation; `attackerSignature` length bound; `=>f` typo fix on skip-self check.
- v21: `interpreter.execute()` defensive wrap; `EdgeDecl` null-cfg coercion.
- v23: `restoreFrom` validates and clamps every field; `threatLevel>=3` forces `locked=true`; optional `setAdminToken()` gate on `clearBlocklist`.
- v24: trust must be earned -- `trustScore >= 50` requires `passCount >= 5` or restore resets to 0.

### Breaking

- **`graph._inheritanceRegistry` returns undefined.** No public API ever exposed it, but any debug/inspection code that read it directly will need to use `graph.getRegistrySnapshot()` instead.
- **Existing 0.4.x / 0.5.x `data/gap_*.json` files will fail safe on first 0.6.0 boot** with the default `GAPT_HMAC_ACCEPT_UNSIGNED` unset. Either run `gapt-resign` once before upgrade, or boot once with `GAPT_HMAC_ACCEPT_UNSIGNED=1`. Both options are idempotent.

### Migration -- step by step

1. Set `GAPT_HMAC_SECRET` to a 32-byte hex (or longer utf8) secret you control. Recommended.
   ```bash
   export GAPT_HMAC_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
   ```
2. Either:
   - Run `npx gapt-resign` once against the data directory. Idempotent.
   - **Or** boot the app once with `GAPT_HMAC_ACCEPT_UNSIGNED=1` -- snapshots get re-signed on their next load.
3. Unset `GAPT_HMAC_ACCEPT_UNSIGNED` afterward. From this point, any tampered or unsigned file fails safe.

### Notes

- Performance: the analytical cost of HMAC-SHA256 on a ~2-3KB body is ~10us per save via native `crypto.createHmac`. Well within 1% wall-time cost at the v19 baseline of 1000-1200 sends/s. No optimization needed for typical workloads.
- The sprint 19 in-memory-attack case now records "attack blocked at property assignment: Cannot set properties of undefined" -- the desired outcome.
- `data/.gapt-hmac-secret` is created with `mode 0o600` on POSIX. Anyone who can read it is part of the trust boundary; document and treat accordingly.

## [0.4.0] -- earlier

(Pre-iteration baseline. See git history.)
