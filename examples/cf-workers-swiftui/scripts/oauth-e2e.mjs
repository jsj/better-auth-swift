import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import assert from 'node:assert/strict';
import path from 'node:path';
import process from 'node:process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const exampleDir = path.resolve(scriptDir, '..');
const workerDir = path.join(exampleDir, 'worker');
const workerPort = process.env.E2E_WORKER_PORT ?? '8877';
const appleEmulatorPort = process.env.E2E_APPLE_EMULATOR_PORT ?? '4410';
const googleEmulatorPort = process.env.E2E_GOOGLE_EMULATOR_PORT ?? '4402';
const workerURL = process.env.E2E_WORKER_URL ?? `http://127.0.0.1:${workerPort}`;
const callbackURL = `${workerURL}/e2e/oauth/success`;
const wranglerPersistTo = process.env.E2E_WRANGLER_PERSIST_TO ?? mkdtempSync(path.join(tmpdir(), 'better-auth-oauth-e2e-'));
const children = [];

function log(message) {
  process.stdout.write(`${message}\n`);
}

function appendCookies(jar, headers) {
  const setCookies = typeof headers.getSetCookie === 'function'
    ? headers.getSetCookie()
    : [headers.get('set-cookie')].filter(Boolean);
  for (const header of setCookies) {
    const cookie = header.split(';')[0];
    const separator = cookie.indexOf('=');
    if (separator > 0) {
      jar.set(cookie.slice(0, separator), cookie.slice(separator + 1));
    }
  }
}

function cookieHeader(jar) {
  return Array.from(jar.entries()).map(([name, value]) => `${name}=${value}`).join('; ');
}

async function fetchChecked(url, init) {
  const response = await fetch(url, init);
  if (response.status >= 400) {
    throw new Error(`${init?.method ?? 'GET'} ${url} failed with ${response.status}: ${await response.text()}`);
  }
  return response;
}

async function waitFor(url, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // keep polling
    }
    await delay(500);
  }
  throw new Error(`Timed out waiting for ${url}`);
}

async function shutdown() {
  for (const child of children) {
    if (!child.killed) {
      child.kill('SIGTERM');
    }
  }
  await delay(300);
}

process.on('SIGINT', () => {
  void shutdown().finally(() => process.exit(130));
});
process.on('SIGTERM', () => {
  void shutdown().finally(() => process.exit(143));
});

const migration = spawnSync('npm', [
  'exec',
  'wrangler',
  '--',
  'd1',
  'migrations',
  'apply',
  'DB',
  '--local',
  '--persist-to',
  wranglerPersistTo,
], {
  cwd: workerDir,
  stdio: 'inherit',
  env: process.env,
});
if (migration.status !== 0) {
  process.exit(migration.status ?? 1);
}

const stack = spawn('node', [path.join(scriptDir, 'dev-stack.mjs')], {
  cwd: exampleDir,
  stdio: ['ignore', 'pipe', 'pipe'],
  env: {
    ...process.env,
    WORKER_PORT: workerPort,
    APPLE_EMULATOR_PORT: appleEmulatorPort,
    GOOGLE_EMULATOR_PORT: googleEmulatorPort,
    WRANGLER_PERSIST_TO: wranglerPersistTo,
  },
});
children.push(stack);
stack.stdout.on('data', (chunk) => process.stdout.write(`[stack] ${chunk}`));
stack.stderr.on('data', (chunk) => process.stderr.write(`[stack] ${chunk}`));

try {
  await waitFor(`${workerURL}/health`);

  const jar = new Map();
  const signIn = await fetchChecked(`${workerURL}/api/auth/sign-in/oauth2`, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'content-type': 'application/json',
      origin: workerURL,
    },
    body: JSON.stringify({
      providerId: 'apple-emulator',
      disableRedirect: true,
      callbackURL,
      requestSignUp: true,
    }),
  });
  appendCookies(jar, signIn.headers);

  const signInBody = await signIn.json();
  assert.equal(signInBody.redirect, false);
  assert.equal(new URL(signInBody.url).origin, `http://127.0.0.1:${appleEmulatorPort}`);

  const authorize = await fetchChecked(signInBody.url, { redirect: 'manual' });
  assert.equal(authorize.status, 302);
  const callbackLocation = authorize.headers.get('location');
  assert.ok(callbackLocation, 'Apple emulator did not redirect back with an OAuth code');

  const callback = await fetchChecked(callbackLocation, {
    redirect: 'manual',
    headers: {
      cookie: cookieHeader(jar),
    },
  });
  appendCookies(jar, callback.headers);

  assert.equal(callback.status, 302);
  assert.equal(callback.headers.get('location'), callbackURL);
  assert.ok(cookieHeader(jar).includes('better-auth.session_token='), 'OAuth callback did not set a session cookie');

  log('OAuth e2e passed: apple-emulator authorization code flow created a Better Auth session.');
} finally {
  await shutdown();
}
