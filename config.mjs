// Central security and runtime configuration.
// Every environment variable the server reads is declared here, in one
// editable page. Change values in .env or your host's variable settings;
// do not edit server.mjs to reconfigure things.

export const config = loadConfig();

function loadConfig() {
  // isProduction: true only when NODE_ENV is exactly "production".
  const isProduction = process.env.NODE_ENV === 'production';
  // demoMode: synthetic demo mode. On by default outside production,
  // or forced on with CONTEXTSEAL_DEMO_MODE=1.
  const demoMode = process.env.CONTEXTSEAL_DEMO_MODE === '1' || !isProduction;
  // requireAuth: whether requests need the auth token. Never in demo mode.
  const requireAuth = !demoMode && (isProduction || process.env.CONTEXTSEAL_REQUIRE_AUTH === '1');
  // signingSecret: the legacy HMAC secret used to sign receipts.
  // In production it must come from RECEIPT_SIGNING_KEY; a fixed dev value
  // is only allowed outside production.
  const signingSecret = process.env.RECEIPT_SIGNING_KEY || (isProduction ? null : 'context-seal-dev-signing-key');
  // authToken: the bearer token for authenticated requests.
  const authToken = process.env.CONTEXTSEAL_AUTH_TOKEN || null;
  // databaseUrl / ledgerPath: where receipts are stored. Outside demo mode
  // at least one of these is required.
  const databaseUrl = process.env.DATABASE_URL || null;
  const ledgerPath = process.env.RECEIPT_LEDGER_PATH || null;

  // Fail-closed production validation lives in server.mjs so error ordering
  // stays identical to the pre-config behavior.
  const configuredRateLimit = Number(process.env.CONTEXTSEAL_MAX_REQUESTS_PER_MINUTE || 60);

  return {
    // port: the port the server listens on. Default 4178.
    port: Number(process.env.PORT || 4178),
    // host: network interface. Production listens on all interfaces,
    // development stays on localhost only.
    host: process.env.HOST || (isProduction ? '0.0.0.0' : '127.0.0.1'),
    isProduction,
    demoMode,
    requireAuth,
    signingSecret,
    authToken,
    // ed25519PrivateKey: PEM private key. When set, receipts get real
    // Ed25519 signatures instead of legacy HMAC.
    ed25519PrivateKey: process.env.CONTEXTSEAL_SIGNING_KEY,
    // evidenceWrappingKey: must decode to exactly 32 bytes (hex or base64).
    // Encrypts exported evidence packages.
    evidenceWrappingKey: parseEvidenceWrappingKey(process.env.CONTEXTSEAL_EVIDENCE_WRAPPING_KEY),
    // evidenceKeyId: label stored inside evidence packages. Change the value
    // whenever you rotate the wrapping key.
    evidenceKeyId: process.env.CONTEXTSEAL_EVIDENCE_KEY_ID || 'contextseal-evidence-key',
    databaseUrl,
    ledgerPath,
    // approvalTtlMs: how long an approval stays fresh. Default 5 minutes.
    approvalTtlMs: Number(process.env.CONTEXTSEAL_APPROVAL_TTL_MS || 5 * 60 * 1000),
    // maxRequestsPerMinute: request rate limit. Bad values fall back to 60.
    maxRequestsPerMinute: Number.isFinite(configuredRateLimit) && configuredRateLimit > 0 ? configuredRateLimit : 60
  };
}

// parseEvidenceWrappingKey: accepts 64 hex chars or base64, always 32 bytes.
export function parseEvidenceWrappingKey(value) {
  if (!value) return null;
  const key = /^[0-9a-f]{64}$/i.test(value) ? Buffer.from(value, 'hex') : Buffer.from(value, 'base64');
  if (key.length !== 32) throw new Error('CONTEXTSEAL_EVIDENCE_WRAPPING_KEY must decode to exactly 32 bytes');
  return key;
}
