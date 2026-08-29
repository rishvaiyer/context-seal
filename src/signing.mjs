import crypto from 'node:crypto';

// Receipt and manifest signing.
//
// Why this module exists: the original implementation signed with
// crypto.createHmac('sha256', secret). That is a symmetric MAC, so verifying a
// receipt required the same secret used to produce it. Anyone able to check a
// receipt was therefore also able to forge one, and an outside reviewer could
// not verify anything at all without being handed the signing key. That is the
// wrong property for a tamper-evident audit record.
//
// Ed25519 splits those roles. The service holds the private key and signs; the
// public key is published at GET /api/signing-key, and anyone can verify a
// receipt offline with the public key alone. See scripts/verify-receipt.mjs for
// a dependency-free third-party verifier.
//
// HMAC signing and verification remain available while Ed25519 is disabled.
// This keeps the default behavior compatible with receipts created before the
// asymmetric signing path was added.

// ---------------------------------------------------------------------------
// TOGGLE: Ed25519 signing is OFF by default.
//
// While it is off, CanaryNorth behaves exactly as it did before this module
// existed: receipts and manifests are signed with HMAC-SHA256 using
// RECEIPT_SIGNING_KEY, they carry no signatureAlgorithm or keyId field,
// /api/signing-key is not served, and /health reports no signing block. The
// deployed demo and open PR are unaffected until this is switched on.
//
// Turn it ON, either way:
//
//   1. One run only, no file edits:
//        CONTEXTSEAL_ED25519=1 npm start
//
//   2. Always on: change the line below from `false` to `true`.
//        const ED25519_ENABLED_BY_DEFAULT = true;
//
// Turn it OFF again: drop the variable, or set the line back to `false`.
//
// Before switching it on in production, set CONTEXTSEAL_SIGNING_KEY to a stable
// key. Without one, an ephemeral key is generated per process and receipts stop
// verifying after a restart. /health and /api/signing-key both report that.
// ---------------------------------------------------------------------------

const ED25519_ENABLED_BY_DEFAULT = false;

export function ed25519Enabled(env = process.env) {
  return ED25519_ENABLED_BY_DEFAULT || env.CONTEXTSEAL_ED25519 === '1';
}

export const SIGNATURE_ALGORITHM = 'ed25519';
export const LEGACY_SIGNATURE_ALGORITHM = 'hmac-sha256';

// Canonical JSON: sort keys recursively so that two structurally equal objects
// always produce identical bytes to sign. JSON.stringify alone is
// key-order-dependent, which made the previous signatures sensitive to a
// harmless property reordering anywhere upstream.
export function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
}

function normalizePrivateKey(material) {
  if (!material) return null;
  const text = String(material).trim();
  if (text.includes('BEGIN')) return crypto.createPrivateKey(text);
  // Accept a bare 32-byte seed as hex or base64 so operators can supply a key
  // without pasting PEM into an environment variable.
  const seed = /^[0-9a-f]{64}$/i.test(text) ? Buffer.from(text, 'hex') : Buffer.from(text, 'base64');
  if (seed.length !== 32) throw new Error('CONTEXTSEAL_SIGNING_KEY must be PEM, or a 32-byte seed in hex or base64');
  // RFC 8410 PKCS#8 prefix for an Ed25519 private key, followed by the seed.
  const der = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]);
  return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

/**
 * Build a signer.
 *
 * @param {object}  options
 * @param {string=} options.privateKey  PEM, or a 32-byte seed as hex/base64.
 * @param {boolean=} options.allowEphemeral  When no key is supplied, generate one
 *   in memory. Intended for the synthetic demo and for tests. An ephemeral key
 *   changes on restart, so receipts signed before a restart stop verifying. The
 *   caller is expected to surface that fact rather than hide it.
 */
export function createSigner({ privateKey, allowEphemeral = false, enabled = ed25519Enabled(), legacySecret } = {}) {
  // Toggle off: hand back a legacy HMAC signer wearing the same interface, so
  // every call site stays identical and the emitted bytes match what shipped
  // before Ed25519 existed. `legacy: true` is how callers suppress the new
  // signatureAlgorithm and keyId fields.
  if (!enabled) return createLegacySigner(legacySecret);

  let key = normalizePrivateKey(privateKey);
  let ephemeral = false;
  if (!key) {
    if (!allowEphemeral) throw new Error('CONTEXTSEAL_SIGNING_KEY is required');
    key = crypto.generateKeyPairSync('ed25519').privateKey;
    ephemeral = true;
  }
  const publicKey = crypto.createPublicKey(key);
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const publicKeyRaw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  // A short, stable fingerprint so a receipt can name the key that signed it and
  // a verifier can tell "wrong key" apart from "tampered payload".
  const keyId = `ed25519:${crypto.createHash('sha256').update(publicKeyRaw).digest('hex').slice(0, 16)}`;

  return {
    algorithm: SIGNATURE_ALGORITHM,
    keyId,
    ephemeral,
    publicKeyPem,
    publicKeyBase64: publicKeyRaw.toString('base64'),
    sign(payload) {
      return crypto.sign(null, Buffer.from(canonicalize(payload), 'utf8'), key).toString('base64');
    },
    verify(payload, signature) {
      return verifySignature({ payload, signature, publicKey: publicKeyPem });
    }
  };
}

/**
 * The pre-Ed25519 signer, kept behind the same interface.
 *
 * Deliberately signs `JSON.stringify(payload)` rather than the canonical form,
 * because it must reproduce the exact bytes the old implementation produced.
 */
export function createLegacySigner(secret) {
  if (!secret) throw new Error('RECEIPT_SIGNING_KEY is required while Ed25519 signing is disabled');
  return {
    algorithm: LEGACY_SIGNATURE_ALGORITHM,
    legacy: true,
    keyId: null,
    ephemeral: false,
    publicKeyPem: null,
    publicKeyBase64: null,
    sign(payload) {
      return crypto.createHmac('sha256', secret).update(JSON.stringify(payload)).digest('hex');
    },
    verify(payload, signature) {
      return verifyLegacyHmac({ payload, signature, secret });
    }
  };
}

/** Verify a signature with a public key only. No private material required. */
export function verifySignature({ payload, signature, publicKey }) {
  if (!signature || !publicKey) return false;
  try {
    const key = typeof publicKey === 'string' && publicKey.includes('BEGIN')
      ? crypto.createPublicKey(publicKey)
      : crypto.createPublicKey({
        key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(publicKey, 'base64')]),
        format: 'der',
        type: 'spki'
      });
    return crypto.verify(null, Buffer.from(canonicalize(payload), 'utf8'), key, Buffer.from(signature, 'base64'));
  } catch {
    return false;
  }
}

/** Legacy verification for receipts issued before Ed25519. Never used to sign. */
export function verifyLegacyHmac({ payload, signature, secret }) {
  if (!signature || !secret) return false;
  const expected = crypto.createHmac('sha256', secret).update(JSON.stringify(payload)).digest('hex');
  const a = Buffer.from(expected);
  const b = Buffer.from(String(signature));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
