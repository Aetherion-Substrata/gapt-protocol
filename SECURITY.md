# Security policy

Thanks for caring enough to read this. If you've found a vulnerability in **gapt** -- particularly anything that lets an attacker bypass trust, forge persistence state, or escalate beyond what the threat model below allows -- please report it privately.

## Reporting a vulnerability

Email the project maintainer (see `package.json` `author`) with the subject line `gapt security`. Please include:

- gapt version (`gapt --version` or `package.json`).
- Reproduction steps. A minimal failing test case is ideal.
- Your assessment of impact (data integrity, availability, escalation).
- Whether you've published anything publicly yet. If not, give us a reasonable window to ship a fix before you do.

Triage target: acknowledgement within 5 business days, fix or mitigation plan within 30. Severe issues get fast-tracked.

## Supported versions

| Version | Status | Notes |
|---|---|---|
| 0.6.x | Active. Security fixes land here. | HMAC-signed persistence, private inheritance registry. |
| 0.5.x | Not released (skipped). | Version reserved for retro fix shipments, if needed. |
| 0.4.x | EOL. **Do not use in production.** | Predates the HMAC seal. Persistence file is forgeable by anyone with write access to `data/`. |

## Threat model

**In scope for gapt's protocol guarantees:**

- An attacker with **read+write access to `data/` but no access to the HMAC secret** cannot forge a snapshot that elevates trust on load. Tampered files fail safe (trust=0).
- An attacker with **a previous-generation HMAC secret** during a planned rotation window (`GAPT_HMAC_SECRET_PREV` set) can have their snapshots accepted -- because that's exactly what rotation is for. Once the operator drops `_PREV`, old-key signatures are rejected.
- An attacker with **process-internal access** (e.g., calling `g._inheritanceRegistry[k] = {...}`) cannot poison inheritance. The registry is a private class field. The legacy public name resolves to `undefined`.
- An attacker injecting **hostile payloads via `transmit()`** (circular refs, prototype pollution attempts, weird types, oversize attempts arrays) gets structured error logs, not crashes. Coverage in sprints 06-21.

**Out of scope (and why):**

- **Process compromise / RCE / V8 escape.** Anyone executing code in the same JS realm can mutate any object, including `edge.memory.*`. gapt doesn't try to defend against attackers who own the runtime. Sandboxing, OS user separation, or container isolation are the right layers for this.
- **Secret extraction.** Anyone who can read `GAPT_HMAC_SECRET` from environment or `data/.gapt-hmac-secret` from disk can forge signatures. That's a key-management failure, not a protocol failure. We document it clearly, but we don't claim to defend against it.
- **Disk-level adversaries** that can flip bits in `data/` between save and load *without* changing the file mtime: still get caught by HMAC. But an adversary that can also rewrite the file metadata is in the "owns your storage" tier, same threat class as RCE.
- **Side-channels** (timing, cache). gapt uses `crypto.timingSafeEqual` for the HMAC comparison itself but does not claim full-stack constant-time behavior. Don't deploy gapt as a primary auth boundary in a side-channel-sensitive environment.

## Known operational footguns (read these before deploying)

1. **`GAPT_HMAC_SECRET` should be set explicitly in production.** If you don't set it, gapt auto-generates `data/.gapt-hmac-secret` with mode 0600 on first boot. That works for dev, but in production:
   - Anyone with read access to that file can forge signatures.
   - If the file gets deleted or rotated, every previously-signed snapshot fails fail-safe to trust=0.
   - Multi-host deployments cannot share the same auto-gen secret.
   You really want the env var.
2. **Multi-process deployments sharing `data/`** must agree on `GAPT_HMAC_SECRET` *before any process starts*. If two processes start with different secrets, the one that writes "wins" and the other rejects on load. We log [TAMPERED] in this case, but the symptom looks like a security incident even when it's a deployment-config bug.
3. **`clearBlocklist` is opt-in-auth.** If you call `network.setAdminToken(...)` (recommended), `clearBlocklist` requires that token. If you don't, anyone with a reference to the network object can clear it. We log a warning in the no-token case; do not ignore that warning in prod.
4. **The migration grace flag is dangerous if left on.** `GAPT_HMAC_ACCEPT_UNSIGNED=1` accepts unsigned snapshots on load. Use it for one boot to migrate from 0.4.x, then unset.
5. **`getRegistrySnapshot()` is read-only by design.** It returns a deep-frozen clone. If you find a way to mutate the live registry through it, that's a bug -- please report it under this policy.

## Cryptographic primitives

- HMAC-SHA-256 via native Node `crypto.createHmac`. Key 32+ bytes.
- Constant-time comparison via `crypto.timingSafeEqual`.
- Snapshot bodies are canonicalized (keys sorted recursively, no whitespace) before signing so two independent processes producing the same logical state always produce the same signature.

## What we don't do (intentionally)

- **No external network calls** during signing or verification. Everything is local-file + in-process.
- **No automatic key rotation.** Operators trigger rotation by setting `GAPT_HMAC_SECRET_PREV` to the previous key, deploying a new `GAPT_HMAC_SECRET`, letting snapshots get re-signed naturally, then dropping `_PREV` once `gapt-resign --dry-run` shows everything's converged.
- **No telemetry, no phone-home.** If gapt ever phones home, it's a vulnerability -- report it.

## Acknowledgements

Iteration arc that produced the 0.6.0 seal:
- v22 stress fuzz found the trust-the-file class.
- v23 closed the lazy-forgery sub-class via field clamping.
- v24 closed direct trust-max via a history-check (now redundant but kept as belt-and-braces).
- v25 (design) + v26 (impl) closed the coherent-history forgery via HMAC seal, and the in-memory inheritance mutation via the private class field.

The full iteration log lives in the project's `gapt-iteration/` archive (not part of the published package).
