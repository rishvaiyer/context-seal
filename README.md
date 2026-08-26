# CanaryNorth: AI Action Receipts



CanaryNorth is a trust and policy layer for AI-generated work. Its proxy keeps raw credentials out of model context while producing signed, hash-chained receipts that explain which actions were approved, which were blocked, and what remains unverified. The current demo is synthetic and shows decision-level receipts plus a portable artifact sidecar.

Compatibility note: repository paths, package names, API routes, schemas, database tables, headers, and legacy environment variables remain unchanged so existing integrations do not break.

## Why it is useful

- **Opaque capabilities:** `cap_*` references are safe to put in model context; the provider key never is.
- **Structural policy:** action and resource allowlists, expiry, and deny-by-default enforcement happen in the proxy.
- **Content firewall:** prompt-injection, hidden direction-changing characters, tool-shaped metadata, memory-poisoning cues, broad export intent, unsafe output formats, and credential-shaped payloads are quarantined before forwarding.
- **Agentic control work:** The active private fixture map now has 115 connected CanaryNorth evaluator checks with passing tests. Four lower-priority `dormant-rehearsal-variants` remain disabled by default, and the result does not claim universal, scanner, or production coverage.
- **Evidence:** every allow/deny decision produces a tamper-evident action receipt with a previous-receipt link.
- **Private provenance:** receipts expose process and evidence, not secrets, private identities, or unnecessary personal data.
- **MCP audit:** `POST /mcp/audit` supports a read-only `contextseal.audit` method.
- **Workspace boundaries:** production requests can bind to a tenant and workspace, with explicit principal, audience, nonce, and policy-version checks.
- **Durable storage:** memory, append-only JSONL, and PostgreSQL receipt stores use the same storage interface.
- **Human approval:** the synthetic `tickets.update` flow creates a short-lived approval, supports approve or deny, re-checks policy and nonce state, and records the decision in a signed receipt.
- **Verified release gate:** a fixed synthetic replay suite compares reviewed and candidate policy outcomes, records version changes, blocks regressions in CI, and emits Ed25519-verifiable release evidence.
- **Safe evidence ledger:** synthetic prompt-injection, DLP, replay, approval, malware-scan, and steganography-signal events use a versioned, redaction-aware schema. Malware and steganography rows are explicitly labeled as not-run or example-only.
- **Local evidence encryption:** the evidence package format uses envelope encryption with AES-256-GCM, a random data key, a wrapped customer key, retention metadata, tamper checks, and a separate integrity signature. Decryption is designed to happen locally with an operator-managed key.
- **ML direction:** the planned risk layer learns redacted workflow behavior in shadow mode and recommends review or quarantine. It cannot override deterministic deny rules and is not shipped as a trained detector yet.
- **Teaching graph:** the visual map supports guided scenarios, event timelines, node inspectors, keyboard navigation, touch dragging, and reset/recenter controls.

The sample data is synthetic. The demo does not call an external tool or connect to a secret vault. After running the safe path, use **[bind artifact]** to download `weather-brief.md` plus a `.receipt.json` sidecar containing the artifact hash, receipt hash, and signed manifest. This proves a policy decision and file integrity. It does not prove that the content is correct, safe, original, or human-approved.

For a plain-language walkthrough, use the **Explain like I'm five** link in the demo or open [public/learn.html](public/learn.html). 

## Run

```bash
npm test
npm run release:verify
npm run lint
npm start
open http://localhost:4178
```

Set `RECEIPT_SIGNING_KEY` in a real deployment. The development fallback is intentionally public and must not be used for production evidence. PostgreSQL deployments require the `pg` dependency already declared in `package.json`. Set `CONTEXTSEAL_EVIDENCE_WRAPPING_KEY` to a base64 or 64-character hex encoded 32-byte key before enabling encrypted evidence export. Keep that key in a KMS or secret manager and do not expose it to the browser.

Production mode (`NODE_ENV=production`) fails closed unless `RECEIPT_SIGNING_KEY` and `CONTEXTSEAL_AUTH_TOKEN` are set to values at least 32 characters long. Authenticated requests use `Authorization: Bearer <CONTEXTSEAL_AUTH_TOKEN>`. Outside demo mode, requests must also provide the existing technical headers `X-ContextSeal-Tenant`, `X-ContextSeal-Workspace`, principal, audience, policy version, and a one-time nonce. `CONTEXTSEAL_DEMO_MODE=1` is an explicit exception for this public synthetic demo only; it must never be used for real workloads or real receipts. Local development remains an explicitly unauthenticated synthetic demo unless `CONTEXTSEAL_REQUIRE_AUTH=1` is set.

Outside demo mode, configure either `DATABASE_URL` for PostgreSQL or `RECEIPT_LEDGER_PATH` for an append-only JSONL ledger. The PostgreSQL adapter initializes `contextseal_receipts` and `contextseal_nonces`, uses parameterized queries, and serializes receipt-chain writes. Mount JSONL storage on durable, access-controlled storage; an ephemeral container filesystem is not an audit store.

### Railway with PostgreSQL

A minimal deployment shape is one CanaryNorth service plus one Railway PostgreSQL service:

```bash
railway add --database postgres --json
railway variable set CONTEXTSEAL_DEMO_MODE=1 --service context-seal
railway up
```

Connect the database service's `DATABASE_URL` to the app service using Railway's variable reference UI or CLI. Keep demo mode enabled only for synthetic demonstrations. For a real deployment, disable demo mode, configure identity-bound authentication, and use a separate environment for testing.

The hosted synthetic demo is [context-seal-production.up.railway.app](https://context-seal-production.up.railway.app/). It contains no external tool connection, real capability store, identity provider, or user data. A real deployment must disable demo mode, add identity-bound authorization, configure durable ledger storage, and complete an independent security review before exposing receipt APIs.

The current metadata-policy work uses deterministic evaluators over request metadata. The active private fixture catalog now has 115 connected CanaryNorth evaluator pairings, each covered by a passing direct or authorization-path test. The separate `dormant-rehearsal-variants` family has four lower-priority, opt-in variants and remains excluded from the active count. These are deterministic metadata authorization controls, not malware scanners or trained ML.

## API

- `GET /health` - liveness and active storage mode, plus signing posture when Ed25519 is enabled.
- `GET /api/signing-key` - the Ed25519 public key used to sign receipts. Served only when Ed25519 signing is enabled, and unauthenticated by design, because a receipt is only independently verifiable if the verifier can fetch the key without credentials.
- `GET /api/bootstrap` - redacted capabilities, graph, and scoped receipts.
- `POST /api/authorize` - evaluate a scoped request and append a receipt.
- `GET /api/receipts` - read receipts within the request scope.
- `GET /api/evidence` - read the synthetic, redaction-aware human ledger.
- `POST /api/evidence/package` - create an encrypted synthetic evidence package when an operator-managed wrapping key is configured. The service never returns that key.
- `POST /mcp/audit` - read-only JSON-RPC audit (`{ "method": "contextseal.audit", "id": 1 }`).
- `POST /api/artifacts/export` - bind an allowed receipt to a synthetic artifact and return the artifact plus signed receipt sidecar.
- `POST /api/artifacts/verify` - verify the artifact hash, manifest hash, and server signature.


## Limits

This is a focused reference implementation. Capabilities, approvals, and evidence events are fixture-backed, the public deployment remains synthetic, and the DLP/injection detectors are intentionally small deterministic signals, not a general classifier. They are defense in depth, not the boundary: the capability allowlist, expiry, nonce, and scope checks are what actually enforce, and they do not depend on the wording of an input. The active private pairing map has 115 passing fixture-to-CanaryNorth evaluator checks; the four `dormant-rehearsal-variants` remain disabled by default and lower priority. That pairing result is not a claim of universal protection, live target detection, scanner coverage, malware or steganography detection, or production safety. The evidence module is an encrypted package format, not a malware scanner, steganography detector, or production retention service. The ML risk layer is a roadmap, not a trained security model. The PostgreSQL path is a durable persistence foundation, not a finished security platform. A production release still needs a real identity provider, durable approval and evidence persistence, tenant administration, policy management, secret-manager integration, structured logging, monitoring, backup/restore procedures, key rotation, independent security review, and a broader content-security test corpus.



## Receipt signing and independent verification

> **Status: built but OFF by default.** Receipts are still signed with
> HMAC-SHA256 exactly as before. Nothing in this section is active until the
> toggle is switched on, and the deployed demo is unaffected. Turn it on for one
> run with `CONTEXTSEAL_ED25519=1`, or permanently by setting
> `ED25519_ENABLED_BY_DEFAULT = true` in `src/signing.mjs`. Turn it off by
> undoing either. Tests cover both states.

Once enabled, receipts and artifact manifests are signed with **Ed25519**. The service holds
the private key; the public key is published at `GET /api/signing-key`. Anyone
can therefore verify that a receipt is authentic **without holding any material
that would let them forge one**.

This replaces the previous HMAC-SHA256 scheme. An HMAC is symmetric, so
verifying a receipt required the same secret used to produce it: any party able
to check a receipt was also able to forge one, and an outside reviewer could not
check anything at all. That is the wrong property for a tamper-evident audit
record.

Verify a receipt yourself, with no credentials and no dependencies:

```bash
curl -s "$ORIGIN/api/receipts" | jq '.receipts[0].receipt' > receipt.json
node scripts/verify-receipt.mjs receipt.json --url "$ORIGIN"
```

Exit code 0 means verified. Change any signed field and it returns 1.

Configuration:

- `CONTEXTSEAL_SIGNING_KEY` accepts a PEM private key or a 32-byte seed in hex or
  base64. Set it in production so receipts stay verifiable across restarts.
- If it is unset outside production, an **ephemeral** key is generated in memory.
  `/health` and `/api/signing-key` both report `ephemeralKey: true`, because an
  ephemeral key means receipts signed before a restart will no longer verify.
- Signed payloads are canonicalized with sorted keys, so a harmless property
  reordering upstream cannot invalidate a receipt.
- Receipts carry `signatureAlgorithm` and a short `keyId` fingerprint, so a
  verifier can tell "signed by a different key" apart from "payload altered".
- Manifests written before this change carry `signatureAlgorithm: hmac-sha256`
  and still verify when the old `RECEIPT_SIGNING_KEY` is supplied. Nothing signs
  with HMAC anymore.
