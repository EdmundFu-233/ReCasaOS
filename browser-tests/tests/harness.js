import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { test as base, expect } from '@playwright/test';

const readyKeys = ['control_origin', 'fixtures', 'origin'];
const fixtureKeys = ['report.txt', 'stream.bin'];
const fixtureValueKeys = ['sha256', 'size'];
const snapshotKeys = [
  'active_file_requests',
  'authorization_on_other_path',
  'authorized_file_requests',
  'authorized_list_requests',
  'canceled_file_requests',
  'completed_file_requests',
  'credential_query_requests',
];

function exactKeys(value, expected) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length &&
    actual.every((key, index) => key === wanted[index]);
}

function requiredAbsoluteEnvironmentPath(name) {
  const value = process.env[name];
  if (typeof value !== 'string' || value.length === 0 || !path.isAbsolute(value)) {
    throw new Error(`required absolute environment path ${name} is missing`);
  }
  return value;
}

function parseURL(value, protocol, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} is not a valid URL`);
  }
  if (
    parsed.protocol !== protocol ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.search !== '' ||
    parsed.hash !== ''
  ) {
    throw new Error(`${label} does not satisfy the browser harness contract`);
  }
  return parsed;
}

function validateFixture(value) {
  if (!exactKeys(value, fixtureValueKeys)) {
    throw new Error('browser harness fixture schema is invalid');
  }
  if (!Number.isSafeInteger(value.size) || value.size < 0) {
    throw new Error('browser harness fixture size is invalid');
  }
  if (typeof value.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.sha256)) {
    throw new Error('browser harness fixture digest is invalid');
  }
}

function parseReadyLine(line) {
  let value;
  try {
    value = JSON.parse(line);
  } catch {
    throw new Error('browser harness ready message is not JSON');
  }
  if (!exactKeys(value, readyKeys) || !exactKeys(value.fixtures, fixtureKeys)) {
    throw new Error('browser harness ready schema is invalid');
  }
  validateFixture(value.fixtures['report.txt']);
  validateFixture(value.fixtures['stream.bin']);

  const portalURL = parseURL(value.origin, 'https:', 'browser harness origin');
  const controlURL = parseURL(
    value.control_origin,
    'http:',
    'browser harness control origin',
  );
  if (portalURL.pathname !== '/') {
    throw new Error('browser harness origin path is invalid');
  }
  if (controlURL.pathname !== '/') {
    throw new Error('browser harness control origin path is invalid');
  }
  return Object.freeze({
    origin: new URL('/public-files/', portalURL).href,
    controlOrigin: controlURL.href.replace(/\/$/, ''),
    fixtures: Object.freeze({
      'report.txt': Object.freeze({ ...value.fixtures['report.txt'] }),
      'stream.bin': Object.freeze({ ...value.fixtures['stream.bin'] }),
    }),
  });
}

function readReadyLine(child) {
  return new Promise((resolve, reject) => {
    let buffer = '';
    let settled = false;

    const finish = (error, value) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      child.stdout.off('data', onData);
      child.off('error', onError);
      child.off('exit', onExit);
      if (error) {
        reject(error);
      } else {
        resolve(value);
      }
    };
    const onData = (chunk) => {
      buffer += chunk.toString('utf8');
      if (buffer.length > 65_536) {
        finish(new Error('browser harness ready message is too large'));
        return;
      }
      const newline = buffer.indexOf('\n');
      if (newline !== -1) {
        const line = buffer.slice(0, newline).trim();
        if (line === '' || buffer.slice(newline + 1).trim() !== '') {
          finish(new Error('browser harness emitted an invalid ready message'));
          return;
        }
        finish(null, line);
      }
    };
    const onError = () => {
      finish(new Error('browser harness could not be started'));
    };
    const onExit = () => {
      finish(new Error('browser harness exited before becoming ready'));
    };
    const timer = setTimeout(
      () => finish(new Error('browser harness did not become ready in time')),
      15_000,
    );

    child.stdout.on('data', onData);
    child.once('error', onError);
    child.once('exit', onExit);
  });
}

async function stopHarness(child) {
  if (child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  const exited = new Promise((resolve) => child.once('exit', resolve));
  child.kill('SIGTERM');
  const stopped = await Promise.race([
    exited.then(() => true),
    delay(3_000, false),
  ]);
  if (!stopped && child.exitCode === null && child.signalCode === null) {
    child.kill('SIGKILL');
    await exited;
  }
}

async function startHarness(verifierSHA256) {
  const executable = requiredAbsoluteEnvironmentPath('RECASAOS_BROWSER_HARNESS');
  const certificateFile = requiredAbsoluteEnvironmentPath(
    'RECASAOS_BROWSER_CERTIFICATE',
  );
  const privateKeyFile = requiredAbsoluteEnvironmentPath(
    'RECASAOS_BROWSER_PRIVATE_KEY',
  );
  const runnerTemp = requiredAbsoluteEnvironmentPath('RUNNER_TEMP');

  const child = spawn(executable, [], {
    cwd: runnerTemp,
    env: {
      RECASAOS_BROWSER_TEST: '1',
      RUNNER_TEMP: runnerTemp,
    },
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  child.on('error', () => {});
  child.stderr.resume();

  const readyLine = readReadyLine(child);
  child.stdin.on('error', () => {});
  child.stdin.end(`${JSON.stringify({
    verifier_sha256: verifierSHA256,
    certificate_file: certificateFile,
    private_key_file: privateKeyFile,
  })}\n`);

  try {
    const ready = parseReadyLine(await readyLine);
    child.stdout.resume();
    return { child, ready };
  } catch (error) {
    await stopHarness(child);
    throw error;
  }
}

function validateSnapshot(value) {
  if (!exactKeys(value, snapshotKeys)) {
    throw new Error('browser harness snapshot schema is invalid');
  }
  for (const key of snapshotKeys) {
    if (!Number.isSafeInteger(value[key]) || value[key] < 0) {
      throw new Error('browser harness snapshot counter is invalid');
    }
  }
  return value;
}

export async function readSnapshot(portal) {
  let response;
  try {
    response = await fetch(`${portal.controlOrigin}/snapshot`, {
      method: 'GET',
      redirect: 'error',
      signal: AbortSignal.timeout(3_000),
    });
  } catch {
    throw new Error('browser harness snapshot request failed');
  }
  if (
    response.status !== 200 ||
    response.redirected ||
    response.url !== `${portal.controlOrigin}/snapshot`
  ) {
    throw new Error('browser harness snapshot response was rejected');
  }
  let value;
  try {
    value = await response.json();
  } catch {
    throw new Error('browser harness snapshot response is not JSON');
  }
  return validateSnapshot(value);
}

export async function waitForSnapshot(portal, predicate, label, timeout = 10_000) {
  const deadline = Date.now() + timeout;
  do {
    const snapshot = await readSnapshot(portal);
    if (predicate(snapshot)) {
      return snapshot;
    }
    await delay(50);
  } while (Date.now() < deadline);
  throw new Error(`${label} was not observed before the deadline`);
}

export function freshBearer() {
  return `rc1_${randomBytes(32).toString('base64url')}`;
}

export const test = base.extend({
  portal: [
    async ({}, use) => {
      const bearer = freshBearer();
      const verifierSHA256 = createHash('sha256').update(bearer).digest('hex');
      const { child, ready } = await startHarness(verifierSHA256);
      try {
        await use(Object.freeze({ ...ready, bearer }));
      } finally {
        await stopHarness(child);
      }
    },
    { scope: 'worker' },
  ],
});

export { expect };
