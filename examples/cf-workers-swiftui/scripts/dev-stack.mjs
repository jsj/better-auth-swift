import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const exampleDir = path.resolve(scriptDir, '..');
const workerDir = path.join(exampleDir, 'worker');
const workerPort = process.env.WORKER_PORT ?? '8787';
const appleEmulatorPort = process.env.APPLE_EMULATOR_PORT ?? '4010';
const googleEmulatorPort = process.env.GOOGLE_EMULATOR_PORT ?? '4002';
const workerBaseURL = `http://127.0.0.1:${workerPort}`;
const appleEmulatorBaseURL = `http://127.0.0.1:${appleEmulatorPort}`;
const googleEmulatorBaseURL = `http://127.0.0.1:${googleEmulatorPort}`;
const workerURL = `${workerBaseURL}/health`;
const appleEmulatorURL = `${appleEmulatorBaseURL}/auth/keys`;
const googleEmulatorURL = `${googleEmulatorBaseURL}/.well-known/openid-configuration`;
const googleWorkspaceEmulatorURL = `${googleEmulatorBaseURL}/$discovery/rest?version=v1&service=drive`;
const tunnelURL = workerBaseURL;
const defaultApiEmulatorRepo = '/Users/james/Developer/zzabandoned/api-emulator';
const defaultApiEmulatorRegistry = '/Users/james/Developer/zmirror/api-emulator-registry';

const args = new Set(process.argv.slice(2));
const wantsTunnel = args.has('--cloudflared');
const statusOnly = args.has('--status');

const emulatorRepo = process.env.API_EMULATOR_REPO
  ?? process.env.APPLE_API_EMULATOR_REPO
  ?? process.env.APPLE_EMULATOR_REPO
  ?? (existsSync(defaultApiEmulatorRepo) ? defaultApiEmulatorRepo : undefined);
const emulatorRepoEntry = emulatorRepo
  ? path.join(emulatorRepo, 'packages', 'emulate', 'dist', 'index.js')
  : null;
const emulatorCli = process.env.API_EMULATOR_CLI
  ?? (emulatorRepo ? path.join(emulatorRepo, 'packages', 'api-emulator', 'dist', 'index.js') : null);
const emulatorRegistry = process.env.API_EMULATOR_REGISTRY
  ?? (existsSync(defaultApiEmulatorRegistry) ? defaultApiEmulatorRegistry : undefined);
const installedApiEmulatorCandidates = [
  path.join(exampleDir, 'node_modules', '.bin', 'api-emulator'),
  path.join(exampleDir, 'node_modules', '.bin', 'api'),
];
const localApiEmulatorBin = installedApiEmulatorCandidates.find((candidate) => existsSync(candidate));
const canUseInstalledApiEmulator = Boolean(localApiEmulatorBin);
const canUseRepoEntry = emulatorRepoEntry ? existsSync(emulatorRepoEntry) : false;
const canUseEmulatorCli = emulatorCli ? existsSync(emulatorCli) : false;
const wranglerPersistTo = process.env.WRANGLER_PERSIST_TO;

function log(message) {
  process.stdout.write(`${message}\n`);
}

function getPluginPath(service) {
  const envKey = `${service.toUpperCase()}_API_EMULATOR_PLUGIN`;
  const candidates = [
    process.env[envKey],
    emulatorRegistry ? path.join(emulatorRegistry, `@${service}`, 'api-emulator', 'dist', 'index.js') : null,
    emulatorRegistry ? path.join(emulatorRegistry, `@${service}`, 'api-emulator.mjs') : null,
  ];
  return candidates.find((candidate) => candidate && existsSync(candidate)) ?? null;
}

function buildEmulatorService({ name, service, port, healthURL }) {
  const pluginPath = getPluginPath(service);
  const resolvedHealthURL = service === 'google' && pluginPath?.endsWith('/api-emulator.mjs')
    ? googleWorkspaceEmulatorURL
    : healthURL;

  if (canUseEmulatorCli && pluginPath) {
    return {
      name,
      command: 'node',
      args: [emulatorCli, 'start', '--service', service, '--port', port, '--plugin', pluginPath],
      healthURL: resolvedHealthURL,
      source: `${emulatorCli} + ${pluginPath}`,
    };
  }

  if (canUseInstalledApiEmulator) {
    return {
      name,
      command: localApiEmulatorBin,
      args: ['--service', service, '--port', port],
      healthURL: resolvedHealthURL,
      source: localApiEmulatorBin,
    };
  }

  if (canUseRepoEntry) {
    return {
      name,
      command: 'node',
      args: [emulatorRepoEntry, '--service', service, '--port', port],
      healthURL: resolvedHealthURL,
      source: emulatorRepoEntry,
    };
  }

  const guidance = [
    `${service} emulator dependency is not available.`,
    `Expected local CLI: ${emulatorCli ?? '(unset)'}`,
    `Expected ${service} plugin: ${pluginPath ?? path.join(emulatorRegistry ?? '(unset)', `@${service}`, 'api-emulator.mjs')}`,
    `Install it with: npm --prefix "${exampleDir}" install`,
    'Or set API_EMULATOR_REPO=/path/to/api-emulator and API_EMULATOR_REGISTRY=/path/to/api-emulator-registry',
  ].join('\n');
  throw new Error(guidance);
}

const services = [
  buildEmulatorService({
    name: 'apple-emulator',
    service: 'apple',
    port: appleEmulatorPort,
    healthURL: appleEmulatorURL,
  }),
  buildEmulatorService({
    name: 'google-emulator',
    service: 'google',
    port: googleEmulatorPort,
    healthURL: googleEmulatorURL,
  }),
  {
    name: 'worker',
    command: 'npm',
    args: [
      'run',
      'dev',
      '--',
      '--port',
      workerPort,
      '--var',
      `BETTER_AUTH_URL:${workerBaseURL}`,
      '--var',
      `TRUSTED_ORIGIN:${workerBaseURL}`,
      '--var',
      `APPLE_EMULATOR_BASE_URL:${appleEmulatorBaseURL}`,
      '--var',
      `GOOGLE_EMULATOR_BASE_URL:${googleEmulatorBaseURL}`,
    ].concat(wranglerPersistTo ? ['--persist-to', wranglerPersistTo] : []),
    cwd: workerDir,
    healthURL: workerURL,
  },
];

if (wantsTunnel) {
  services.push({
    name: 'cloudflared',
    command: 'cloudflared',
    args: ['tunnel', '--url', tunnelURL],
  });
}

const children = [];
let shuttingDown = false;

async function checkHealth(url) {
  try {
    const response = await fetch(url, { method: 'GET' });
    return response.ok;
  } catch {
    return false;
  }
}

async function printStatus() {
  for (const service of services.filter((service) => service.healthURL)) {
    const healthy = await checkHealth(service.healthURL);
    log(`${service.name}: ${healthy ? 'up' : 'down'} (${service.healthURL})`);
  }
  log(`cloudflared: ${wantsTunnel ? 'managed by this wrapper when started with --cloudflared' : 'not requested'}`);
  for (const service of services.filter((service) => service.name.endsWith('-emulator'))) {
    log(`${service.name} source: ${service.source ?? 'missing'}`);
  }
}

function attachOutput(child, name) {
  child.stdout?.on('data', (chunk) => {
    process.stdout.write(`[${name}] ${chunk}`);
  });
  child.stderr?.on('data', (chunk) => {
    process.stderr.write(`[${name}] ${chunk}`);
  });
}

function spawnService(service) {
  const child = spawn(service.command, service.args, {
    cwd: service.cwd,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: process.env,
  });

  attachOutput(child, service.name);
  child.on('exit', (code, signal) => {
    if (!shuttingDown) {
      log(`[${service.name}] exited (${signal ?? code ?? 'unknown'})`);
    }
  });

  children.push(child);
}

async function waitForHealth(service, timeoutMs = 60_000) {
  if (!service.healthURL) return true;

  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await checkHealth(service.healthURL)) {
      log(`[${service.name}] healthy`);
      return true;
    }
    await delay(500);
  }

  log(`[${service.name}] health check failed: ${service.healthURL}`);
  return false;
}

async function shutdown(code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;

  for (const child of children) {
    if (!child.killed) {
      child.kill('SIGTERM');
    }
  }

  await delay(300);
  for (const child of children) {
    if (!child.killed) {
      child.kill('SIGKILL');
    }
  }

  process.exit(code);
}

if (statusOnly) {
  await printStatus();
  process.exit(0);
}

process.on('SIGINT', () => {
  void shutdown(0);
});
process.on('SIGTERM', () => {
  void shutdown(0);
});

log('Starting local example stack...');
for (const service of services) {
  spawnService(service);
  if (service.healthURL) {
    const healthy = await waitForHealth(service);
    if (!healthy) {
      await shutdown(1);
    }
  }
}

log('All requested services started.');
log('Press Ctrl+C to stop them.');

await new Promise(() => {});
