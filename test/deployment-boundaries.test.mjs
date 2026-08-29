import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const legacySigningKey = 'synthetic-deployment-signing-key-0001';
const authToken = 'synthetic-deployment-auth-token-000001';
const ed25519Seed = '11'.repeat(32);

function controlledEnvironment(overrides = {}) {
  return {
    PATH: process.env.PATH || '',
    LANG: 'C',
    HOST: '127.0.0.1',
    PORT: '0',
    ...overrides
  };
}

function expectBootFailure(name, environment, expected) {
  const result = spawnSync(process.execPath, ['server.mjs'], {
    cwd: root,
    env: controlledEnvironment(environment),
    encoding: 'utf8',
    timeout: 5_000
  });
  const output = `${result.stdout || ''}\n${result.stderr || ''}`;
  assert.notEqual(result.status, 0, `${name} unexpectedly started`);
  assert.match(output, expected, `${name} failed for an unexpected reason`);
}

function startServer(environment) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['server.mjs'], {
      cwd: root,
      env: controlledEnvironment(environment),
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let output = '';
    let settled = false;
    const timeout = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill('SIGKILL');
      reject(new Error(`server-start-timeout\n${output}`));
    }, 8_000);

    const read = (chunk) => {
      output += chunk.toString();
      const match = output.match(/CanaryNorth listening on http:\/\/127\.0\.0\.1:(\d+)/);
      if (!match || settled) return;
      settled = true;
      clearTimeout(timeout);
      resolve({ child, origin: `http://127.0.0.1:${match[1]}`, output: () => output });
    };
    child.stdout.on('data', read);
    child.stderr.on('data', read);
    child.once('exit', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      reject(new Error(`server-exited-before-listen:${code}\n${output}`));
    });
  });
}

async function stopServer(child) {
  if (child.exitCode !== null) return;
  child.kill('SIGTERM');
  await Promise.race([
    once(child, 'exit'),
    new Promise((resolve) => setTimeout(resolve, 2_000))
  ]);
  if (child.exitCode === null) {
    child.kill('SIGKILL');
    await once(child, 'exit');
  }
}

async function jsonRequest(origin, pathname, options = {}) {
  const response = await fetch(`${origin}${pathname}`, {
    ...options,
    signal: AbortSignal.timeout(4_000)
  });
  const payload = await response.json();
  return { status: response.status, payload };
}

function productionEnvironment(overrides = {}) {
  return {
    NODE_ENV: 'production',
    RECEIPT_SIGNING_KEY: legacySigningKey,
    CONTEXTSEAL_AUTH_TOKEN: authToken,
    CONTEXTSEAL_ED25519: '1',
    CONTEXTSEAL_SIGNING_KEY: ed25519Seed,
    ...overrides
  };
}

function scopedHeaders() {
  return {
    authorization: `Bearer ${authToken}`,
    'content-type': 'application/json',
    'x-contextseal-tenant': 'tenant_demo',
    'x-contextseal-workspace': 'workspace_demo'
  };
}

function validSyntheticRequest() {
  return {
    capabilityId: 'cap_weather_read_7f3d',
    action: 'weather.get_forecast',
    resource: 'weather://nyc',
    input: 'Synthetic deployment-boundary regression only',
    principal: 'weather-agent',
    audience: 'contextseal',
    tenantId: 'tenant_demo',
    workspaceId: 'workspace_demo',
    policyVersion: 'contextseal-policy-v2',
    nonce: 'nonce_deployment_0001'
  };
}

test('production fails closed without signing material', () => {
  expectBootFailure(
    'missing-signing-material',
    { NODE_ENV: 'production' },
    /RECEIPT_SIGNING_KEY is required/
  );
});

test('production fails closed without authentication', () => {
  expectBootFailure(
    'missing-authentication',
    {
      NODE_ENV: 'production',
      RECEIPT_SIGNING_KEY: legacySigningKey
    },
    /CONTEXTSEAL_AUTH_TOKEN must be at least 32 characters/
  );
});

test('production fails closed without durable receipt storage', () => {
  expectBootFailure(
    'missing-durable-storage',
    {
      NODE_ENV: 'production',
      RECEIPT_SIGNING_KEY: legacySigningKey,
      CONTEXTSEAL_AUTH_TOKEN: authToken
    },
    /DATABASE_URL or RECEIPT_LEDGER_PATH is required/
  );
});

test('explicit demo mode stays labeled synthetic and exposes ephemeral signing posture', async () => {
  const runtime = await startServer({
    NODE_ENV: 'production',
    CONTEXTSEAL_DEMO_MODE: '1',
    RECEIPT_SIGNING_KEY: legacySigningKey,
    CONTEXTSEAL_ED25519: '1'
  });
  try {
    const health = await jsonRequest(runtime.origin, '/health');
    const publicKey = await jsonRequest(runtime.origin, '/api/signing-key');
    assert.equal(health.status, 200);
    assert.equal(health.payload.mode, 'synthetic-demo');
    assert.equal(health.payload.storage, 'memory');
    assert.equal(health.payload.evidence.ledger, 'synthetic-demo');
    assert.equal(health.payload.signing.algorithm, 'ed25519');
    assert.equal(health.payload.signing.ephemeralKey, true);
    assert.equal(publicKey.status, 200);
    assert.equal(publicKey.payload.ephemeralKey, true);
    assert.match(publicKey.payload.note, /regenerated on restart/);

    const removedConsole = await jsonRequest(runtime.origin, '/pen-console/index.html');
    const removedEntrance = await jsonRequest(runtime.origin, '/pen-entry.html');
    assert.equal(removedConsole.status, 404);
    assert.equal(removedConsole.payload.error, 'not-found');
    assert.equal(removedEntrance.status, 404);
    assert.equal(removedEntrance.payload.error, 'not-found');
  } finally {
    await stopServer(runtime.child);
  }
});

test('configured production binds auth, scope, identity, nonce, and persistence', async () => {
  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'canarynorth-boundary-'));
  const ledgerPath = path.join(temporaryDirectory, 'receipts.jsonl');
  const runtime = await startServer(
    productionEnvironment({ RECEIPT_LEDGER_PATH: ledgerPath })
  );
  try {
    const health = await jsonRequest(runtime.origin, '/health');
    assert.equal(health.status, 200);
    assert.equal(health.payload.mode, 'production');
    assert.equal(health.payload.storage, 'jsonl');
    assert.deepEqual(health.payload.signing, {
      algorithm: 'ed25519',
      keyId: health.payload.signing.keyId,
      ephemeralKey: false
    });
    assert.match(health.payload.signing.keyId, /^ed25519:[0-9a-f]{16}$/);

    const unauthenticated = await jsonRequest(runtime.origin, '/api/bootstrap');
    assert.equal(unauthenticated.status, 401);

    const missingScope = await jsonRequest(runtime.origin, '/api/bootstrap', {
      headers: { authorization: `Bearer ${authToken}` }
    });
    assert.equal(missingScope.status, 400);

    const missingIdentity = await jsonRequest(runtime.origin, '/api/authorize', {
      method: 'POST',
      headers: scopedHeaders(),
      body: JSON.stringify({
        capabilityId: 'cap_weather_read_7f3d',
        action: 'weather.get_forecast',
        resource: 'weather://nyc'
      })
    });
    assert.equal(missingIdentity.status, 400);

    const request = validSyntheticRequest();
    const allowed = await jsonRequest(runtime.origin, '/api/authorize', {
      method: 'POST',
      headers: scopedHeaders(),
      body: JSON.stringify(request)
    });
    assert.equal(allowed.status, 200);
    assert.equal(allowed.payload.allowed, true);
    assert.equal(allowed.payload.receipt.decision, 'allow');
    assert.equal(allowed.payload.receipt.signatureAlgorithm, 'ed25519');

    const replay = await jsonRequest(runtime.origin, '/api/authorize', {
      method: 'POST',
      headers: scopedHeaders(),
      body: JSON.stringify(request)
    });
    assert.equal(replay.status, 403);
    assert.equal(replay.payload.code, 'replay-detected');

    const mismatchedScope = await jsonRequest(runtime.origin, '/api/authorize', {
      method: 'POST',
      headers: scopedHeaders(),
      body: JSON.stringify({
        ...validSyntheticRequest(),
        nonce: 'nonce_deployment_0002',
        tenantId: 'tenant_other'
      })
    });
    assert.equal(mismatchedScope.status, 400);

    const persisted = fs.readFileSync(ledgerPath, 'utf8').trim().split('\n');
    assert.equal(persisted.length, 2);
    assert.deepEqual(
      persisted.map((line) => JSON.parse(line).receipt.decision),
      ['allow', 'deny']
    );
  } finally {
    await stopServer(runtime.child);
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});
