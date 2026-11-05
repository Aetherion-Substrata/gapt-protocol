# GAPT Protocol — Aetherion

> A data structure where the gap between nodes is a first-class citizen.

[![npm](https://img.shields.io/npm/v/gapt-protocol)](https://www.npmjs.com/package/gapt-protocol)
[![licence](https://img.shields.io/badge/licence-free_for_individuals_%C2%B7_companies_pay-blue)](./LICENSE)
[![types](https://img.shields.io/badge/types-bundled-blue)](./src/gapt.d.ts)
[![by](https://img.shields.io/badge/by-Aetherion_Substrata-brightgreen)](https://github.com/Aetherion-Substrata)

---

## The idea

In every data structure ever built — linked lists, graphs, trees — the connection between two nodes is passive. It moves data from A to B. That is all it does. The gap is ignored.

**Gapt changes that.**

In Gapt, the gap between nodes is structural. Every connection has three built-in properties:

| Property | Role | What it does |
|---|---|---|
| `voidguard` | Filter | Inspects the data before it may pass |
| `bridgetype` | Label | Describes the nature of the relationship |
| `edgelock` | Lock | Controls who or what may initiate a transmission |

The gap also has **memory**. It remembers every transmission. It escalates threat levels automatically. It learns to trust repeated clean travellers. It predicts attacks before they complete. It survives restarts.

---

## Install

```bash
npm install @gapt/protocol
```

TypeScript types are bundled — no `@types/...` package required.

---

## Quick start

```js
const { GaptGraph } = require('@gapt/protocol');

const g = new GaptGraph();

g.addNode('user',  {});
g.addNode('vault', {});

g.addEdge('user', 'vault', {
  bridgetype: 'vault-access',
  voidguard:  (data) => data.type === 'valid',
  edgelock:   'my-secret-key'
});

const result = g.send('user', 'vault', { type: 'valid' }, 'my-secret-key');
console.log(result.reason); // GAPT_CLEAR [UNKNOWN]
```

---

## Browser usage (0.10.0+)

Drop-in `<script>` tag, zero build step required on the consumer side.

```html
<script src="https://unpkg.com/@gapt/protocol"></script>
<script>
  const g = new window.Gapt.GaptGraph();
  g.addNode('user',  {});
  g.addNode('vault', {});
  g.addEdge('user', 'vault', {
    bridgetype: 'vault-access',
    voidguard:  d => d.type === 'valid',
    edgelock:   'my-secret'
  });
  const r = g.send('user', 'vault', { type: 'valid' }, 'my-secret');
  console.log(r.reason); // GAPT_CLEAR [UNKNOWN]
</script>
```

`window.Gapt` exposes the full surface: `GaptGraph`, `GaptEdge`, `GaptMemory`, `GaptFingerprint`, `GaptNetwork`, the `.gapt` lang pipeline (`GaptLexer`, `GaptParser`, `GaptInterpreter`), plus `getTrustTier`, `DEFAULT_TRUST_CONFIG`, `Token`, `TOKEN_TYPES`, `version`.

**Persistence in the browser is in-memory only.** Refreshing the page wipes gap state. The HMAC-signed disk persistence that ships with the Node package stays Node-only -- a localStorage / IndexedDB + WebCrypto backend is on the v0.11 roadmap. If you need cross-load state today, run gapt on a server.

TypeScript: `dist/gapt.browser.d.ts` augments `Window` with the `Gapt` namespace.

---

## Gapt Language

Write `.gapt` files and run them directly. As of **0.11.0** the language is **holographic**: functions are themselves gaps, defended by the same machinery they let you compose.

### Functions are gaps (0.11.0+)

```gapt
let adminKey = "secret-123"

gapfn isAdmin(k) {
  lock: caller == "auth-flow"   # only the auth flow can invoke
  body: { return k == adminKey }
}

graph main {
  node user  {}
  node vault {}
  edge user -> vault {
    lock: isAdmin(key, as: "auth-flow")
  }
  send user -> vault { data: { type: "valid" }  key: "secret-123" }
}
```

Every `gapfn` call routes through the same `GaptEdge.transmit()` machinery that defends user-declared edges. If you brute-force the function, it locks the same way the vault does. Threat patterns (`burst`, `key-rot`, `probe`) light up on the function itself. `fnStatus("isAdmin")` reports `passCount`, `trustScore`, `threatLevel`, `locked`, identical shape to `gapStatus()`. Add `persist: true` and the lockdown survives a process restart via the same HMAC-signed file format that 0.6.0 introduced for edges.

This is what makes gapt holographic: a `.gapt` program is built out of the same primitives it protects. Reusable lock predicates and guard expressions get the gap treatment for free, no extra wiring.

Run the demo: `npm run example:v3`. Lang v2 (`let` / `if` / `else`) is unchanged:

```gapt
let masterKey = "secret-123"
let env       = "prod"

graph main {
  node user  { role: "client" }
  node vault { role: "storage" }

  if env == "prod" {
    edge user -> vault {
      guard: data.type == "valid"
      label: "vault-access-prod"
      lock:  key == masterKey
    }
  } else {
    edge user -> vault {
      guard: data.type == "valid"
      label: "vault-access-dev"
      lock:  key == "dev-key"
    }
  }

  send user -> vault {
    data: { type: "valid" }
    key:  "secret-123"
  }
}
```

```bash
node gapt.run.js examples/lang-v2.gapt
```

---

## Features

- Three-layer gap on every connection
- Gap memory — threat escalation, trust building, lockdown
- Predictive pre-emption — four attack pattern detectors
- Persistence — memory survives restarts, **HMAC-signed since 0.6.0** (tamper-evident)
- **Multi-replica HMAC handshake (0.7.0)** — boot-time check that every replica shares the same secret. Catches misconfig before it looks like an attack.
- **Bounded blast-radius propagation (0.7.0)** — cap how far one edge's alerts spread across the network. Tenant-isolation friendly.
- Behavioural fingerprinting — detects account takeovers
- Gap communication — network-wide defence
- Gap inheritance — new edges inherit retired edge memory (registry is a private class field)
- **Programmable `.gapt` language (0.8.0)** — `let` bindings, `if` / `else` conditionals
- **TypeScript types bundled (0.9.0)**
- **Browser build (0.10.0)** — drop-in `<script>` tag, `window.Gapt` API
- **Holographic `gapfn` (0.11.0)** — functions defend themselves through the same gap machinery they let you compose

---

## Network defence — bounded blast radius (0.7.0+)

By default, one alert reaches every edge in every registered graph. Useful for tiny meshes, dangerous at scale.

```js
const { GaptNetwork } = require('@gapt/protocol');

// Bound propagation to immediate neighbours only.
const net = new GaptNetwork({ propagationRadius: 1 });
net.register(g);

// Or change it at runtime.
net.setPropagationRadius(2);
```

Recommended values:

- **Multi-tenant SaaS:** `0` or `1` — tenant isolation. One bad tenant doesn't poison the trust state of every customer-facing route.
- **Microservice mesh:** `2` — immediate neighbourhood, no mesh-wide cascade.
- **Small private cluster:** `Infinity` (default) — full network defence.

Distance is computed as edge-adjacency BFS (two edges are adjacent when they share at least one endpoint node). Sub-millisecond on a 1000-edge mesh.

---

## Multi-replica handshake (0.7.0+)

Two replicas share a `data/` directory. They must agree on `GAPT_HMAC_SECRET`. Today gapt catches this at boot rather than at the first `[TAMPERED]` log.

```js
const persist = require('@gapt/protocol/src/persist');

// Auto-invoked from saveGapMemory / loadGapMemory once per process,
// but apps that want hard-fail on misconfig can call it explicitly.
const r = persist.ensureHandshake({ strict: true });
// r.ok === true: replica is aligned (or this is the first boot)
// r.ok === false: secret mismatch / corrupt handshake / can't write
```

Strict mode via `GAPT_HANDSHAKE_STRICT=1` raises `GAPT_HANDSHAKE_MISMATCH` instead of returning `{ok:false}`. Default is warn-and-continue for backward compat.

---

## Operations (read before deploying to production)

### Set the HMAC secret explicitly

```bash
export GAPT_HMAC_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
```

Without this, gapt auto-generates `data/.gapt-hmac-secret` (mode 0o600 on POSIX) and prints a loud warning. The auto-gen path is fine for dev. In production:

- The audit boundary is whoever can read that file. Use env var instead.
- Multi-host deployments can't share an auto-gen file. Use env var.
- If the file gets rotated or deleted, every previously-signed snapshot fails fail-safe to trust=0. Use env var.

### Multi-process / multi-host deployments

Every process sharing the same `data/` directory must agree on `GAPT_HMAC_SECRET` *before any of them starts*. As of 0.7.0, mismatched processes are detected at boot via the handshake file (see above) rather than at the first `[TAMPERED]` log.

Recommendation: store the secret in your existing secrets manager (Vault, AWS SM, k8s secret) and inject it as env into every replica. Set `GAPT_HANDSHAKE_STRICT=1` on each replica to fail loud on drift.

### Key rotation

1. Move current key into `GAPT_HMAC_SECRET_PREV` on every host.
2. Set a new `GAPT_HMAC_SECRET` on every host. Restart processes.
3. Run `npx gapt-resign` once per host (or let gapt re-sign organically as snapshots are saved -- the on-load rotation path also re-signs).
4. Once `gapt-resign --dry-run` shows nothing to migrate, drop `GAPT_HMAC_SECRET_PREV` on the next deploy.
5. Delete `data/.gapt-handshake.json` so the first boot under the new key writes a fresh fingerprint.

### Migrating from 0.4.x / 0.5.x

Persistence files written by older versions are unsigned. On first 0.6.x+ boot, either:

```bash
# Option A: one-shot grace flag (boot once, then unset)
GAPT_HMAC_ACCEPT_UNSIGNED=1 node your-app.js

# Option B: pre-migrate via the CLI (idempotent, safe to re-run)
npx gapt-resign --data-dir ./data
```

The grace flag accepts unsigned snapshots and auto-resigns them. **Do not leave it on permanently** -- it would defeat the seal.

### Network admin token

If you use `GaptNetwork`, call `network.setAdminToken("<random-string-8+chars>")` at startup. This makes `clearBlocklist` require the token. Without it, anyone holding a reference to the network object can clear the blocklist; you'll see a loud SECURITY WARNING in logs.

### What the seal does and doesn't protect

See `SECURITY.md` for the full threat model. The short version: HMAC closes file-side forgery. It does **not** protect against attackers running code inside the same JS realm (use process isolation), or against attackers who can read the secret (key-mgmt boundary).

---

## Testing

```bash
npm test               # core sprints 01-04
npm run test:security  # sprints 19 + 20 (security regression suite)
```

`tests/sprint20.js` covers HMAC verify, migration, rotation, tampered-body rejection, and the in-memory inheritance attack.

---

## TypeScript

Types are bundled at `src/gapt.d.ts` with per-module sidecars (`network.d.ts`, `persist.d.ts`, `lexer.d.ts`, `parser.d.ts`, `interpreter.d.ts`). No `@types/...` package required.

```ts
import { GaptGraph, GaptNetwork } from '@gapt/protocol';
import { ensureHandshake } from '@gapt/protocol/src/persist';

const g = new GaptGraph({ autoRestore: false });
const n = new GaptNetwork({ propagationRadius: 1 });
const r = ensureHandshake({ strict: true });
```

---

## Roadmap

- **0.7.x** — security path: bounded propagation, multi-replica handshake. *Done.*
- **0.8.x** — `.gapt` language v2: `let`, `if`, `else`. *Done.*
- **0.9.x** — TypeScript types bundled. *Done.*
- **0.10.x** — browser build. *Done.*
- **0.11.x** — holographic `gapfn` (functions as gaps). *Done.*
- **0.12.x / 1.0** — observability hooks (function-level events, Prometheus exporter), browser persistence backend (localStorage / IndexedDB + WebCrypto), server-side persistence plugins (Redis / Postgres).

---

## Origin

Gapt emerged from a question about geometry — the principle in tangential flight research that the negative space between interlocking forms carries as much structural meaning as the forms themselves.

Applied to data structures: what if the gap between nodes did real work?

---

## Licence

Free for individuals, solo builders, students, researchers and nonprofits — use it, learn from it, change it for your own projects. **Companies pay.** Prices are in [COMMERCIAL.md](./COMMERCIAL.md); the terms are the [Aetherion Fair Use Licence](./LICENSE). Licensing: hello@aetherionsubstrata.xyz

© 2026 Aetherion Substrata Ltd · [Kizldn](https://github.com/kizldn) · [Aetherion-Substrata](https://github.com/Aetherion-Substrata) · [@fizznetwork](https://x.com/fizznetwork)
