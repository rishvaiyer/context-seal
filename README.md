# CanaryNorth

CanaryNorth is a reference implementation of a policy boundary for AI-assisted actions. An application sends a scoped request to the proxy, which checks the requested action, resource, expiry, identity context, nonce, and any required human approval before recording an allow or deny receipt.

[Open the demo](https://context-seal-production.up.railway.app/) · [Read the plain-language guide](https://context-seal-production.up.railway.app/learn.html) · [Run a controlled rehearsal](https://context-seal-production.up.railway.app/threat-lab.html)

## Request to receipt

1. The application gives the model an opaque capability reference instead of a provider credential.
2. The proxy resolves that reference and checks the allowed action, resource, expiry, principal, audience, tenant, workspace, policy version, and nonce.
3. Bounded deterministic signals can hold suspicious input before it reaches the forwarding boundary.
4. A higher-risk synthetic action can pause for a short-lived human approval, then run the policy checks again.
5. Every decision is written as a signed receipt linked to the previous receipt.

The public demo uses synthetic capabilities and does not forward requests to an external tool.

## Architecture

| Module | Responsibility |
| --- | --- |
| `server.mjs` | HTTP boundary, request validation, scope binding, rate limiting, and API routes |
| `src/policy.mjs` | Capability lookup, allowlists, expiry, replay checks, and bounded input signals |
| `src/agentic-defense.mjs` | Optional checks for tool manifests, memory context, provenance, delegation, and approval freshness |
| `src/approvals.mjs` | Short-lived approval state and resolution |
| `src/storage.mjs` | In-memory, append-only JSONL, and PostgreSQL receipt stores |
| `src/signing.mjs` | HMAC compatibility and optional Ed25519 signing |
| `src/artifacts.mjs` | Artifact hash binding and sidecar verification |
| `src/evidence.mjs` | Redacted synthetic evidence events and encrypted export packages |
| `public/` | Guided demo, system view, plain-language guide, and controlled rehearsal |

Repository and API identifiers retain the earlier `context-seal` name. The public project name is CanaryNorth.

## Run locally

Requires Node.js 20 or newer.

```bash
cp .env.example .env
npm ci
npm test
npm run release:verify
npm run lint
npm run start:env
```

Then visit <http://127.0.0.1:4178>.

Local development starts in synthetic demo mode. To inspect one decision directly:

```bash
curl -s http://127.0.0.1:4178/api/authorize \
  -H 'Content-Type: application/json' \
  -d '{
    "capabilityId": "cap_weather_read_7f3d",
    "action": "weather.get_forecast",
    "resource": "weather://nyc",
    "input": "Forecast for tomorrow",
    "principal": "weather-agent",
    "audience": "contextseal",
    "tenantId": "tenant_demo",
    "workspaceId": "workspace_demo",
    "policyVersion": "contextseal-policy-v2",
    "nonce": "readme-demo-0001"
  }'
```

The response includes the decision, the policy reason, any input signals, and the receipt.

## Receipt signing

The repository defaults to HMAC-SHA256 receipt signing for compatibility. Enable independently verifiable Ed25519 receipts for a run with:

```bash
CONTEXTSEAL_ED25519=1 npm start
```

Set `CONTEXTSEAL_SIGNING_KEY` to a stable Ed25519 private key or 32-byte seed when receipts must remain verifiable across restarts. When Ed25519 is active:

- `GET /api/signing-key` publishes the public key and key identifier.
- Receipts and artifact manifests include `signatureAlgorithm` and `keyId`.
- `scripts/verify-receipt.mjs` verifies a receipt without the private key.

Legacy HMAC verification remains available for receipts created in the default mode.

## API

| Route | Purpose |
| --- | --- |
| `GET /health` | Runtime mode, storage adapter, evidence posture, and active signing posture |
| `GET /api/bootstrap` | Redacted demo capabilities, graph data, and scoped receipts |
| `POST /api/authorize` | Evaluate a scoped request and append its receipt |
| `GET /api/receipts` | Read receipts within the request scope |
| `GET /api/approvals` | Read current approval records within the request scope |
| `POST /api/approvals/request` | Create a short-lived approval request for an eligible action |
| `POST /api/approvals/:id/approve` | Resolve a pending synthetic approval and re-check policy |
| `POST /api/approvals/:id/deny` | Deny a pending synthetic approval |
| `POST /api/artifacts/export` | Bind an allowed receipt to a synthetic artifact |
| `POST /api/artifacts/verify` | Verify the artifact hash, manifest hash, and signature |
| `GET /api/evidence` | Read redacted synthetic evidence events |
| `POST /api/evidence/package` | Create an encrypted evidence package when a wrapping key is configured |
| `POST /mcp/audit` | Read-only `contextseal.audit` JSON-RPC method |

## Configuration

Every server variable is documented in `.env.example`. The main deployment controls are:

| Variable | Purpose |
| --- | --- |
| `CONTEXTSEAL_DEMO_MODE=1` | Explicit synthetic demo mode |
| `CONTEXTSEAL_REQUIRE_AUTH=1` | Require bearer authentication outside production |
| `CONTEXTSEAL_AUTH_TOKEN` | Bearer token used when authentication is enabled |
| `RECEIPT_SIGNING_KEY` | HMAC signing material and legacy verification key |
| `CONTEXTSEAL_ED25519=1` | Enable Ed25519 signing |
| `CONTEXTSEAL_SIGNING_KEY` | Stable Ed25519 private key or seed |
| `DATABASE_URL` | PostgreSQL receipt and nonce storage |
| `RECEIPT_LEDGER_PATH` | Append-only JSONL storage when PostgreSQL is not used |
| `CONTEXTSEAL_EVIDENCE_WRAPPING_KEY` | Operator-managed key for encrypted evidence export |

Outside demo mode, production startup requires authentication, signing material, and durable receipt storage. Adapting the reference implementation for real actions also requires an identity system, managed keys, operational monitoring, and an independent security review.

## What the tests cover

The automated suite exercises:

- capability scope, expiry, identity, and policy-version decisions
- nonce replay protection
- bounded input and metadata signals
- approval creation, expiry, approval, denial, and policy re-checks
- receipt chaining and tamper detection
- artifact binding and verification
- encrypted evidence package integrity
- storage adapters and fail-closed deployment configuration
- release replay comparisons and signed release evidence

Run the commands locally to inspect the current results. The PostgreSQL integration test runs when `TEST_DATABASE_URL` is configured.
