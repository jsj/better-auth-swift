import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const exampleDir = path.resolve(scriptDir, '..');
const workerDir = path.join(exampleDir, 'worker');
const workerURL = 'http://127.0.0.1:8787/health';
const emulatorURL = 'http://127.0.0.1:4010/.well-known/openid-configuration';
const tunnelURL = 'http://127.0.0.1:8787';

const args = new Set(process.argv.slice(2));
const wantsTunnel = args.has('--cloudflared');
const statusOnly = args.has('--status');

const emulatorRepo = process.env.APPLE_EMULATOR_REPO;
const emulatorRepoEntry = emulatorRepo
  ? path.join(emulatorRepo, 'packages', 'emulate', 'dist', 'index.js')
  : null;
const localEmulateBin = path.join(exampleDir, 'node_modules', '.bin', 'emulate');
const canUseInstalledEmulate = existsSync(localEmulateBin);
const canUseRepoEntry = emulatorRepoEntry ? existsSync(emulatorRepoEntry) : false;

function log(message) {
  process.stdout.write(`${message}\n`);
}

function buildEmulatorService() {
  if (canUseInstalledEmulate) {
    return {
      name: 'apple-emulator',
      command: localEmulateBin,
      args: ['--service', 'apple', '--port', '4010'],
      healthURL: emulatorURL,
    };
  }

  if (canUseRepoEntry) {
    return {
      name: 'apple-emulator',
      command: 'node',
      args: [emulatorRepoEntry, '--service', 'apple', '--port', '4010'],
      healthURL: emulatorURL,
    };
  }

  const guidance = [
    'Apple emulator dependency is not available.',
    `Install it with: npm --prefix "${exampleDir}" install`,
    'Or set APPLE_EMULATOR_REPO=/path/to/vercel-labs/emulate',
  ].join('\n');
  throw new Error(guidance);
}

const services = [
  buildEmulatorService(),
  {
    name: 'worker',
    command: 'npm',
    args: ['run', 'dev', '--', '--port', '8787'],
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
  const [emulatorHealthy, workerHealthy] = await Promise.all([
    checkHealth(emulatorURL),
    checkHealth(workerURL),
  ]);

  log(`apple-emulator: ${emulatorHealthy ? 'up' : 'down'} (${emulatorURL})`);
  log(`worker: ${workerHealthy ? 'up' : 'down'} (${workerURL})`);
  log(`cloudflared: ${wantsTunnel ? 'managed by this wrapper when started with --cloudflared' : 'not requested'}`);
  log(`emulate source: ${canUseInstalledEmulate ? 'npm dependency' : canUseRepoEntry ? emulatorRepoEntry : 'missing'}`);
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

async function waitForHealth(service, timeoutMs = 20_000) {
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
