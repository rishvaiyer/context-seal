import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { DEMO_CAPABILITIES, POLICY_VERSION, authorize, hashReceipt } from './src/policy.mjs';
import { artifactManifest, verifyApprovedArtifact, verifyArtifact } from './src/artifacts.mjs';
import { createReceiptStore } from './src/storage.mjs';
import { createApprovalStore } from './src/approvals.mjs';
import { createEvidenceEvent, createEvidencePackage } from './src/evidence.mjs';
import { createSigner, ed25519Enabled } from './src/signing.mjs';
import { config } from './config.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(root, 'public');
const { port, isProduction, host, demoMode, requireAuth, signingSecret, authToken } = config;
// Ed25519 signer. Receipts are signed with the private key; the public key is
// served at /api/signing-key so anyone can verify a receipt without it.
// An ephemeral key is allowed only outside production, and /health reports it,
// because an ephemeral key means receipts stop verifying after a restart.
// Ed25519 signing is OFF by default; see the toggle block in src/signing.mjs.
// While off, `signer` is a legacy HMAC signer and every path below behaves
// exactly as it did before Ed25519 existed.
const signer = createSigner({
  enabled: ed25519Enabled(),
  privateKey: config.ed25519PrivateKey,
  allowEphemeral: !isProduction || demoMode,
  legacySecret: signingSecret
});
const evidenceWrappingKey = config.evidenceWrappingKey;
if (isProduction && !demoMode && (!signingSecret || signingSecret.length < 32)) throw new Error('RECEIPT_SIGNING_KEY must be at least 32 characters in production');
if (requireAuth && (!authToken || authToken.length < 32)) throw new Error('CONTEXTSEAL_AUTH_TOKEN must be at least 32 characters when authentication is enabled');
if (isProduction && !demoMode && !config.databaseUrl && !config.ledgerPath) throw new Error('DATABASE_URL or RECEIPT_LEDGER_PATH is required outside synthetic demo mode');
const receiptStore = await createReceiptStore({ databaseUrl: config.databaseUrl, ledgerPath: config.ledgerPath });
await receiptStore.initialize();
const approvalTtlMs = config.approvalTtlMs;
const approvalStore = createApprovalStore({ ttlMs: approvalTtlMs });
const requestWindows = new Map();
const MAX_REQUESTS_PER_MINUTE = config.maxRequestsPerMinute;
const SYNTHETIC_EVIDENCE_EVENTS = Object.freeze([
  { id: 'syn-evt-001', type: 'prompt-injection', severity: 'high', summary: 'Instruction-conflict example stopped at the policy boundary.', details: { payload: '[REDACTED]' }, metadata: { status: 'blocked', source: 'synthetic-demo' } },
  { id: 'syn-evt-002', type: 'dlp', severity: 'high', summary: 'Secret-like pattern example stopped before tool forwarding.', details: { matchedValue: '[REDACTED]' }, metadata: { status: 'blocked', source: 'synthetic-demo' } },
  { id: 'syn-evt-003', type: 'replay', severity: 'medium', summary: 'A synthetic nonce was presented a second time.', details: {}, metadata: { status: 'blocked', source: 'synthetic-demo' } },
  { id: 'syn-evt-004', type: 'approval', severity: 'medium', summary: 'A human decision is required before a synthetic ticket update.', details: {}, metadata: { status: 'pending-review', source: 'synthetic-demo' } }
]);
const syntheticEvidence = SYNTHETIC_EVIDENCE_EVENTS.map((event) => createEvidenceEvent(event));

function securityHeaders() { return { 'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'", 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer', 'permissions-policy': 'camera=(), microphone=(), geolocation=()', ...(isProduction ? { 'strict-transport-security': 'max-age=31536000; includeSubDomains' } : {}) }; }
function json(res, status, body) { res.writeHead(status, { ...securityHeaders(), 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); }
function graph() {
  return { nodes: [
    { id: 'agent', label: 'Agent context', type: 'agent', note: 'opaque refs only' }, { id: 'proxy', label: 'CanaryNorth', type: 'proxy', note: 'policy + DLP + expiry' },
    { id: 'weather', label: 'weather.get_forecast', type: 'tool', note: 'allowlisted' }, { id: 'tickets', label: 'tickets.update', type: 'tool', note: 'scoped resource' },
    { id: 'vault', label: 'Credential boundary', type: 'vault', note: 'server-side only' }, { id: 'ledger', label: 'Receipt ledger', type: 'ledger', note: 'hash chained' }
  ], edges: [
    { from: 'agent', to: 'proxy', label: 'cap_*' }, { from: 'proxy', to: 'weather', label: 'permit' }, { from: 'proxy', to: 'tickets', label: 'permit' },
    { from: 'vault', to: 'proxy', label: 'server-side lookup' }, { from: 'proxy', to: 'ledger', label: 'signed receipt' }
  ] };
}
async function body(req) {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 100_000) throw new Error('payload-too-large');
  }
  return raw ? JSON.parse(raw) : {};
}
function clientKey(req) { return req.socket.remoteAddress || 'unknown'; }
function rateLimited(req) {
  const now = Date.now();
  const key = clientKey(req);
  const window = requestWindows.get(key) || { startedAt: now, count: 0 };
  if (now - window.startedAt >= 60_000) { window.startedAt = now; window.count = 0; }
  window.count += 1;
  requestWindows.set(key, window);
  if (requestWindows.size > 10_000) for (const [entryKey, entry] of requestWindows) if (now - entry.startedAt >= 60_000) requestWindows.delete(entryKey);
  return window.count > MAX_REQUESTS_PER_MINUTE;
}
function authorized(req) {
  if (!requireAuth) return true;
  const header = req.headers.authorization || '';
  const provided = header.startsWith('Bearer ') ? Buffer.from(header.slice(7)) : Buffer.alloc(0);
  const expected = Buffer.from(authToken);
  return provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
}
function scopeForRequest(req) {
  const tenantId = req.headers['x-contextseal-tenant'];
  const workspaceId = req.headers['x-contextseal-workspace'];
  if (Array.isArray(tenantId) || Array.isArray(workspaceId)) throw new Error('invalid-scope-header');
  if (!!tenantId !== !!workspaceId) throw new Error('complete-scope-header-required');
  if (!demoMode && (!tenantId || !workspaceId)) throw new Error('scope-header-required');
  return { tenantId: tenantId || undefined, workspaceId: workspaceId || undefined };
}
function validateAgenticMetadata(request) {
  const optionalObject = (name) => {
    const value = request[name];
    if (value === undefined) return undefined;
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`invalid-${name}`);
    if (JSON.stringify(value).length > 8_000) throw new Error(`${name}-too-large`);
    return value;
  };
  const toolManifest = optionalObject('toolManifest');
  if (toolManifest) {
    for (const field of ['schema', 'tool', 'version', 'owner', 'signatureStatus', 'digest']) {
      if (typeof toolManifest[field] !== 'string' || toolManifest[field].length < 1 || toolManifest[field].length > 256) throw new Error(`invalid-tool-manifest-${field}`);
    }
    if (!Array.isArray(toolManifest.capabilities) || toolManifest.capabilities.length > 32 || toolManifest.capabilities.some((value) => typeof value !== 'string' || value.length < 1 || value.length > 128)) throw new Error('invalid-tool-manifest-capabilities');
  }
  const memoryContext = optionalObject('memoryContext');
  if (memoryContext) {
    for (const field of ['originTrust', 'tenantId', 'workspaceId', 'policyVersion']) {
      if (memoryContext[field] !== undefined && (typeof memoryContext[field] !== 'string' || memoryContext[field].length < 1 || memoryContext[field].length > 128)) throw new Error(`invalid-memory-${field}`);
    }
    for (const field of ['ageSeconds', 'maxAgeSeconds']) {
      if (memoryContext[field] !== undefined && (!Number.isFinite(memoryContext[field]) || memoryContext[field] < 0 || memoryContext[field] > 31_536_000)) throw new Error(`invalid-memory-${field}`);
    }
  }
  const provenance = optionalObject('provenance');
  if (provenance) {
    for (const field of ['sourceTrust', 'sourceId', 'destinationAgentId', 'intendedRecipient', 'authority']) {
      if (provenance[field] !== undefined && (typeof provenance[field] !== 'string' || provenance[field].length < 1 || provenance[field].length > 256)) throw new Error(`invalid-provenance-${field}`);
    }
    if (provenance.delegated !== undefined && typeof provenance.delegated !== 'boolean') throw new Error('invalid-provenance-delegated');
  }
  const canaryContext = optionalObject('canaryContext');
  if (canaryContext && canaryContext.resource !== undefined && (typeof canaryContext.resource !== 'string' || canaryContext.resource.length > 256)) throw new Error('invalid-canary-resource');
  const delegationContext = optionalObject('delegationContext');
  if (delegationContext) {
    if (delegationContext.delegationExpiresAt !== undefined && (typeof delegationContext.delegationExpiresAt !== 'string' || delegationContext.delegationExpiresAt.length < 1 || delegationContext.delegationExpiresAt.length > 128)) throw new Error('invalid-delegation-expiry');
    for (const field of ['delegatorTrusted', 'receiverTrusted', 'delegated', 'audienceMatches']) if (delegationContext[field] !== undefined && typeof delegationContext[field] !== 'boolean') throw new Error(`invalid-delegation-${field}`);
  }
  const approvalFreshnessContext = optionalObject('approvalFreshnessContext');
  if (approvalFreshnessContext) {
    if (approvalFreshnessContext.approvalExpired !== undefined && typeof approvalFreshnessContext.approvalExpired !== 'boolean') throw new Error('invalid-approval-freshness-expired');
  }
  return { toolManifest, memoryContext, provenance, canaryContext, delegationContext, approvalFreshnessContext };
}

function validateAuthorizationRequest(request) {
  if (!request || Array.isArray(request) || typeof request !== 'object') throw new Error('request-object-required');
  if ('now' in request) throw new Error('server-time-only');
  for (const field of ['capabilityId', 'action', 'resource']) if (typeof request[field] !== 'string' || request[field].length < 1 || request[field].length > 256) throw new Error(`invalid-${field}`);
  if (request.input !== undefined && typeof request.input !== 'string' && (typeof request.input !== 'object' || request.input === null)) throw new Error('invalid-input');
  const input = request.input === undefined ? '' : request.input;
  if (JSON.stringify(input).length > 50_000) throw new Error('input-too-large');
  for (const field of ['principal', 'audience', 'tenantId', 'workspaceId', 'policyVersion', 'nonce']) {
    if (request[field] !== undefined && (typeof request[field] !== 'string' || request[field].length < 1 || request[field].length > 128)) throw new Error(`invalid-${field}`);
  }
  if (!demoMode && !request.principal) throw new Error('principal-required');
  if (!demoMode && !request.audience) throw new Error('audience-required');
  if (!demoMode && !request.nonce) throw new Error('nonce-required');
  if (!demoMode && request.policyVersion !== POLICY_VERSION) throw new Error('policy-version-required');
  if (!demoMode && !request.tenantId) throw new Error('tenant-required');
  if (!demoMode && !request.workspaceId) throw new Error('workspace-required');
  const demoControls = request.demoControls === undefined ? undefined : request.demoControls;
  if (demoControls !== undefined && (!demoMode || !demoControls || typeof demoControls !== 'object' || Array.isArray(demoControls))) throw new Error('demo-controls-disabled');
  if (demoControls && Object.values(demoControls).some((value) => typeof value !== 'boolean')) throw new Error('invalid-demo-controls');
  const agenticMetadata = validateAgenticMetadata(request);
  return {
    capabilityId: request.capabilityId,
    action: request.action,
    resource: request.resource,
    input,
    principal: request.principal,
    audience: request.audience,
    tenantId: request.tenantId,
    workspaceId: request.workspaceId,
    policyVersion: request.policyVersion,
    nonce: request.nonce,
    demoControls,
    ...agenticMetadata
  };
}
function validateApprovalRequest(request) {
  const validated = validateAuthorizationRequest(request);
  if (!Object.prototype.hasOwnProperty.call(request, 'input')) throw new Error('approval-input-required');
  for (const field of ['principal', 'audience', 'tenantId', 'workspaceId', 'policyVersion', 'nonce']) {
    if (!validated[field]) throw new Error(`approval-${field}-required`);
  }
  if (validated.action !== 'tickets.update') throw new Error('approval-capability-not-supported');
  return validated;
}
function validateApprovalCommand(request, approvalId) {
  if (!request || Array.isArray(request) || typeof request !== 'object') throw new Error('request-object-required');
  if (request.approvalId !== undefined && (typeof request.approvalId !== 'string' || request.approvalId !== approvalId)) throw new Error('approval-id-mismatch');
  return request;
}
function validateAuditRequest(request) {
  if (!request || Array.isArray(request) || typeof request !== 'object' || request.method !== 'contextseal.audit') throw new Error('read-only-audit-method-required');
  if (request.id !== undefined && request.id !== null && !['string', 'number'].includes(typeof request.id)) throw new Error('invalid-jsonrpc-id');
  return request;
}
function validateArtifactRequest(request) {
  if (!request || Array.isArray(request) || typeof request !== 'object') throw new Error('request-object-required');
  if (typeof request.receiptId !== 'string' || request.receiptId.length > 64) throw new Error('invalid-receipt-id');
  if (typeof request.filename !== 'string' || !/^[a-zA-Z0-9._-]{1,120}$/.test(request.filename)) throw new Error('invalid-filename');
  if (typeof request.content !== 'string' || request.content.length > 100_000) throw new Error('invalid-artifact-content');
  for (const field of ['tenantId', 'workspaceId']) {
    if (request[field] !== undefined && (typeof request[field] !== 'string' || request[field].length < 1 || request[field].length > 128)) throw new Error(`invalid-${field}`);
  }
  if (!demoMode && (!request.tenantId || !request.workspaceId)) throw new Error('artifact-scope-required');
  return request;
}
function validateVerifyRequest(request) {
  if (!request || Array.isArray(request) || typeof request !== 'object') throw new Error('request-object-required');
  if (typeof request.filename !== 'string' || typeof request.content !== 'string' || !request.manifest || typeof request.manifest !== 'object') throw new Error('artifact-package-required');
  if (request.approved !== undefined) {
    if (!request.approved || typeof request.approved !== 'object' || typeof request.approved.filename !== 'string' || typeof request.approved.content !== 'string' || !request.approved.manifest || typeof request.approved.manifest !== 'object') throw new Error('approved-artifact-package-required');
    if (request.approved.content.length > 100_000 || request.content.length > 100_000) throw new Error('artifact-content-too-large');
  }
  return request;
}
function validateEvidencePackageRequest(request) {
  if (!request || Array.isArray(request) || typeof request !== 'object') throw new Error('request-object-required');
  if (request.eventIds !== undefined && (!Array.isArray(request.eventIds) || request.eventIds.some((id) => typeof id !== 'string'))) throw new Error('invalid-evidence-event-ids');
  return request;
}
function makeReceipt(result, request, { sequence, previousReceipt, approvalId, approvalDecision } = {}) {
  const base = {
    id: `rcpt_${String(sequence).padStart(4, '0')}`,
    timestamp: new Date().toISOString(),
    policyVersion: POLICY_VERSION,
    principal: result.capability?.principal || 'unknown',
    audience: result.capability?.audience || request.audience || null,
    tenantId: result.capability?.tenantId || request.tenantId || 'unscoped',
    workspaceId: result.capability?.workspaceId || request.workspaceId || 'unscoped',
    nonce: request.nonce || null,
    action: request.action || 'unknown',
    resource: request.resource || 'unknown',
    decision: result.allowed ? 'allow' : 'deny',
    reasonCode: result.allowed ? 'policy-passed' : result.code,
    capabilityId: request.capabilityId || null,
    previousReceipt
  };
  if (approvalId) {
    base.approvalId = approvalId;
    base.approvalDecision = approvalDecision;
  }
  const receiptHash = hashReceipt(base);
  const signed = { ...base, receiptHash };
  if (signer.legacy) return { ...signed, signature: signer.sign(signed) };
  return { ...signed, signatureAlgorithm: signer.algorithm, keyId: signer.keyId, signature: signer.sign(signed) };
}
function receiptForResponse(receipt) {
  // While Ed25519 is off, decision responses shorten the signature for display,
  // exactly as they did before. That is safe here because an HMAC signature is
  // not independently verifiable anyway. Once Ed25519 is on, the signature is
  // returned whole: a truncated one would be unverifiable against the published
  // public key, which would defeat the point of publishing it.
  if (!signer.legacy) return receipt;
  return { ...receipt, signature: `${receipt.signature.slice(0, 14)}\u2026` };
}
function staticFile(res, pathname) {
  const safe = pathname === '/' ? '/index.html' : pathname;
  const file = path.normalize(path.join(publicDir, safe));
  const relative = path.relative(publicDir, file);
  if (relative.startsWith('..') || path.isAbsolute(relative)) return json(res, 403, { error: 'forbidden' });
  fs.readFile(file, (err, content) => { if (err) return json(res, 404, { error: 'not-found' }); const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml' }; res.writeHead(200, { ...securityHeaders(), 'content-type': types[path.extname(file)] || 'text/plain; charset=utf-8', 'cache-control': 'no-store' }); res.end(content); });
}
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (req.method === 'GET' && url.pathname === '/health') return json(res, 200, { ok: true, service: 'context-seal', mode: demoMode ? 'synthetic-demo' : (isProduction ? 'production' : 'local-demo'), storage: receiptStore.mode, evidence: { ledger: 'synthetic-demo', encryptedExport: Boolean(evidenceWrappingKey) }, ...(signer.legacy ? {} : { signing: { algorithm: signer.algorithm, keyId: signer.keyId, ephemeralKey: signer.ephemeral } }) });
    // The signing key is public by design and deliberately sits above the auth
    // gate: a receipt is only independently verifiable if the verifier can fetch
    // the key without credentials.
    if (req.method === 'GET' && url.pathname === '/api/signing-key' && !signer.legacy) {
      return json(res, 200, {
        algorithm: signer.algorithm,
        keyId: signer.keyId,
        publicKey: signer.publicKeyPem,
        publicKeyBase64: signer.publicKeyBase64,
        ephemeralKey: signer.ephemeral,
        note: signer.ephemeral
          ? 'Ephemeral demo key. It is regenerated on restart, so receipts signed before a restart will not verify.'
          : 'Stable key. Receipts signed by this key verify offline with the public key alone.',
        verify: 'node scripts/verify-receipt.mjs <receipt.json> --url <origin>'
      });
    }
    if (url.pathname.startsWith('/api/') || url.pathname === '/mcp/audit') {
      if (!authorized(req)) return json(res, 401, { error: 'authentication-required' });
      if (rateLimited(req)) return json(res, 429, { error: 'rate-limit-exceeded' });
    }
    if (req.method === 'GET' && url.pathname === '/api/bootstrap') { const scope = scopeForRequest(req); return json(res, 200, { capabilities: DEMO_CAPABILITIES.map(({ id, principal, label, tool, resource, scopes, expiresAt, status, reason, audience, tenantId, workspaceId, policyVersion }) => ({ id, principal, label, tool, resource, scopes, expiresAt, status, reason, audience, tenantId, workspaceId, policyVersion })), graph: graph(), receipts: await receiptStore.list(scope) }); }
    if (req.method === 'GET' && url.pathname === '/api/receipts') return json(res, 200, { receipts: await receiptStore.list(scopeForRequest(req)) });
    if (req.method === 'GET' && url.pathname === '/api/evidence') return json(res, 200, { schema: 'contextseal.synthetic-evidence-event.v1', syntheticOnly: true, events: syntheticEvidence });
    if (req.method === 'GET' && url.pathname === '/api/approvals') return json(res, 200, { approvals: approvalStore.list({ scope: scopeForRequest(req) }) });
    if (req.method === 'POST' && !req.headers['content-type']?.toLowerCase().startsWith('application/json')) return json(res, 415, { error: 'application-json-required' });
    if (req.method === 'POST' && url.pathname === '/api/authorize') {
      const request = validateAuthorizationRequest(await body(req));
      const headerScope = scopeForRequest(req);
      if (!demoMode && (request.tenantId !== headerScope.tenantId || request.workspaceId !== headerScope.workspaceId)) throw new Error('scope-binding-required');
      let result = authorize(request);
      if (result.allowed && request.nonce && !(await receiptStore.claimNonce({ principal: result.capability.principal, nonce: request.nonce, expiresAt: result.capability.expiresAt }))) result = authorize({ ...request, replayDetected: true });
      const entry = await receiptStore.appendEntry(({ sequence, previousReceipt }) => ({ receipt: makeReceipt(result, request, { sequence, previousReceipt }), execution: result.allowed ? 'would-forward-to-tool' : 'quarantined' }));
      const receipt = entry.receipt;
      return json(res, result.allowed ? 200 : 403, { allowed: result.allowed, reason: result.reason, code: result.code, inspection: result.inspection, receipt: receiptForResponse(receipt) });
    }
    const approvalMatch = url.pathname.match(/^\/api\/approvals\/([^/]+)\/(approve|deny)$/);
    if (req.method === 'POST' && url.pathname === '/api/approvals/request') {
      const request = validateApprovalRequest(await body(req));
      const headerScope = scopeForRequest(req);
      if (headerScope.tenantId && (request.tenantId !== headerScope.tenantId || request.workspaceId !== headerScope.workspaceId)) throw new Error('scope-binding-required');
      const result = authorize(request);
      if (!result.allowed) {
        const entry = await receiptStore.appendEntry(({ sequence, previousReceipt }) => ({ receipt: makeReceipt(result, request, { sequence, previousReceipt }), execution: 'quarantined' }));
        return json(res, 403, { allowed: false, reason: result.reason, code: result.code, inspection: result.inspection, receipt: receiptForResponse(entry.receipt) });
      }
      const approval = approvalStore.create({ request, policyResult: result });
      return json(res, 202, {
        allowed: false,
        status: approval.status,
        approvalId: approval.id,
        approval: { id: approval.id, status: approval.status, expiresAt: approval.expiresAt },
        expiresAt: approval.expiresAt,
        reason: 'Human approval is required before forwarding to the tool.',
        code: 'approval-required',
        inspection: result.inspection,
        policy: { allowed: true, reason: result.reason, code: 'policy-passed' }
      });
    }
    if (req.method === 'POST' && approvalMatch) {
      const approvalId = decodeURIComponent(approvalMatch[1]);
      const decision = approvalMatch[2] === 'approve' ? 'approve' : 'deny';
      validateApprovalCommand(await body(req), approvalId);
      const headerScope = scopeForRequest(req);
      const scope = headerScope.tenantId ? headerScope : undefined;
      const begun = approvalStore.begin(approvalId, decision, { scope });
      if (!begun) return json(res, 404, { error: 'approval-not-found' });
      if (begun.kind === 'already-resolved') return json(res, 409, { error: 'approval-not-pending', status: begun.record.status, approvalId });
      if (begun.kind === 'expired') {
        const expired = begun.record;
        const result = { allowed: false, code: 'approval-expired', reason: 'Human approval expired before resolution.', capability: { principal: expired.request.principal, audience: expired.request.audience, tenantId: expired.request.tenantId, workspaceId: expired.request.workspaceId } };
        const entry = await receiptStore.appendEntry(({ sequence, previousReceipt }) => ({ receipt: makeReceipt(result, expired.request, { sequence, previousReceipt, approvalId, approvalDecision: 'expired' }), execution: 'quarantined' }));
        approvalStore.completeDenial(approvalId, { receiptId: entry.receipt.id });
        return json(res, 410, { allowed: false, status: 'expired', approvalId, reason: result.reason, code: result.code, execution: 'quarantined', receipt: receiptForResponse(entry.receipt) });
      }
      if (decision === 'deny') {
        const denied = begun.record;
        const result = { allowed: false, code: 'human-denied', reason: 'Human approval was denied.', capability: { principal: denied.request.principal, audience: denied.request.audience, tenantId: denied.request.tenantId, workspaceId: denied.request.workspaceId }, inspection: denied.policy.inspection };
        const entry = await receiptStore.appendEntry(({ sequence, previousReceipt }) => ({ receipt: makeReceipt(result, denied.request, { sequence, previousReceipt, approvalId, approvalDecision: 'deny' }), execution: 'quarantined' }));
        approvalStore.completeDenial(approvalId, { receiptId: entry.receipt.id });
        return json(res, 200, { allowed: false, status: 'denied', approvalId, reason: result.reason, code: result.code, execution: 'quarantined', receipt: receiptForResponse(entry.receipt) });
      }
      const approved = begun.record;
      let result = authorize(approved.request);
      if (result.allowed && !(await receiptStore.claimNonce({ principal: result.capability.principal, nonce: approved.request.nonce, expiresAt: result.capability.expiresAt }))) result = authorize({ ...approved.request, replayDetected: true });
      const entry = await receiptStore.appendEntry(({ sequence, previousReceipt }) => ({ receipt: makeReceipt(result, approved.request, { sequence, previousReceipt, approvalId, approvalDecision: 'approve' }), execution: result.allowed ? 'would-forward-to-tool' : 'quarantined' }));
      approvalStore.completeApproval(approvalId, { outcome: result.allowed ? 'allow' : 'deny', reasonCode: result.allowed ? 'policy-passed' : result.code, receiptId: entry.receipt.id });
      return json(res, result.allowed ? 200 : 403, { allowed: result.allowed, status: 'approved', approvalId, reason: result.allowed ? 'Human approval accepted and policy checks passed.' : result.reason, code: result.allowed ? 'approved' : result.code, execution: result.allowed ? 'would-forward-to-tool' : 'quarantined', inspection: result.inspection, receipt: receiptForResponse(entry.receipt) });
    }
    if (req.method === 'POST' && url.pathname === '/api/artifacts/export') { const request = validateArtifactRequest(await body(req)); const headerScope = scopeForRequest(req); if (!demoMode && (request.tenantId !== headerScope.tenantId || request.workspaceId !== headerScope.workspaceId)) throw new Error('scope-binding-required'); const entry = await receiptStore.findByReceiptId(request.receiptId, { tenantId: request.tenantId, workspaceId: request.workspaceId }); if (!entry) return json(res, 404, { error: 'receipt-not-found' }); if (entry.receipt.decision !== 'allow') return json(res, 409, { error: 'artifact-requires-allowed-receipt' }); const manifest = artifactManifest({ filename: request.filename, content: request.content, receipt: entry.receipt, signer }); return json(res, 200, { artifact: { filename: request.filename, content: request.content }, manifest }); }
    if (req.method === 'POST' && url.pathname === '/api/artifacts/verify') { const request = validateVerifyRequest(await body(req)); const result = request.approved ? verifyApprovedArtifact({ approved: request.approved, observed: { filename: request.filename, content: request.content, manifest: request.manifest }, publicKey: signer.publicKeyPem, secret: signingSecret }) : verifyArtifact({ ...request, publicKey: signer.publicKeyPem, secret: signingSecret }); return json(res, 200, result); }
    if (req.method === 'POST' && url.pathname === '/api/evidence/package') {
      if (!evidenceWrappingKey) return json(res, 503, { error: 'evidence-export-unconfigured', reason: 'Configure CONTEXTSEAL_EVIDENCE_WRAPPING_KEY before enabling encrypted evidence export.' });
      const request = validateEvidencePackageRequest(await body(req));
      const selected = request.eventIds?.length ? syntheticEvidence.filter((event) => request.eventIds.includes(event.id)) : syntheticEvidence;
      if (!selected.length || selected.length !== (request.eventIds?.length || selected.length)) throw new Error('evidence-event-not-found');
      const evidencePackage = createEvidencePackage({ events: selected, wrappingKey: evidenceWrappingKey, keyId: config.evidenceKeyId, retentionDeadline: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() });
      return json(res, 200, { syntheticOnly: true, decryptLocally: true, package: evidencePackage });
    }
    if (req.method === 'POST' && url.pathname === '/mcp/audit') { const request = validateAuditRequest(await body(req)); return json(res, 200, { jsonrpc: '2.0', result: { service: 'context-seal', capabilities: DEMO_CAPABILITIES.length, receipts: (await receiptStore.list(scopeForRequest(req))).map(({ receipt }) => receipt), policy: 'deny-by-default', policyVersion: POLICY_VERSION }, id: request.id ?? 1 }); }
    if (req.method === 'GET') return staticFile(res, url.pathname);
    return json(res, 405, { error: 'method-not-allowed' });
  } catch (error) { const status = error.message === 'payload-too-large' || error.message === 'input-too-large' ? 413 : error.code === 'receipt-storage-unavailable' || error.message === 'receipt-ledger-integrity-failure' ? 503 : 400; return json(res, status, { error: status === 503 ? 'service-unavailable' : 'invalid-request', ...(isProduction ? {} : { detail: error.message }) }); }
});
server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
server.listen(port, host, () => { const address = server.address(); console.log(`CanaryNorth listening on http://${host}:${typeof address === 'object' ? address.port : port}${requireAuth ? ' (auth required)' : ' (demo mode)'}`); });
process.on('SIGTERM', async () => { await receiptStore.close(); server.close(); });
