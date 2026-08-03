import { execFile, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { lstat, mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { promisify } from 'node:util';
import { test as base, expect } from '@playwright/test';

const execFileAsync = promisify(execFile);
const readyKeys = ['control_origin', 'fixtures', 'origin'];
const fixtureKeys = ['report.txt', 'stream.bin'];
const fixtureValueKeys = ['sha256', 'size'];
const snapshotKeys = [
  'active_file_requests',
  'authorization_on_other_path',
  'authorized_file_requests',
  'authorized_list_requests',
  'authorized_range_file_requests',
  'canceled_file_requests',
  'completed_file_requests',
  'credential_query_requests',
  'partial_file_responses',
];
const serverDiagnosticKeys = [
  'accepted_connections',
  'active_connection_changes',
  'idle_connection_changes',
  'closed_connections',
  'hijacked_connections',
  'open_connections',
  'server_errors',
  'tls_handshake_errors',
  'active_requests',
  'started_requests',
  'completed_requests',
  'portal_documents_started',
  'portal_documents_completed',
  'static_assets_started',
  'static_assets_completed',
  'api_requests_started',
  'api_requests_completed',
  'other_requests_started',
  'other_requests_completed',
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

function isSafeFirefoxProfilePath(profilePath, runnerTemp) {
  return (
    path.dirname(profilePath) === runnerTemp &&
    path.basename(profilePath).startsWith('recasaos-firefox-profile-')
  );
}

async function removeFirefoxProfile(profilePath, runnerTemp) {
  if (!isSafeFirefoxProfilePath(profilePath, runnerTemp)) {
    throw new Error('refusing unsafe Firefox profile cleanup');
  }
  await rm(profilePath, {
    force: true,
    maxRetries: 3,
    recursive: true,
    retryDelay: 100,
  });
}

async function createTrustedFirefoxProfile(runnerTemp, caCertificateFile) {
  const profilePath = await mkdtemp(
    path.join(runnerTemp, 'recasaos-firefox-profile-'),
  );
  try {
    if (!isSafeFirefoxProfilePath(profilePath, runnerTemp)) {
      throw new Error('Firefox profile path is unsafe');
    }
    const metadata = await lstat(profilePath);
    if (
      !metadata.isDirectory() ||
      metadata.isSymbolicLink() ||
      metadata.uid !== process.geteuid() ||
      (metadata.mode & 0o777) !== 0o700
    ) {
      throw new Error('Firefox profile metadata is unsafe');
    }

    const database = `sql:${profilePath}`;
    await execFileAsync(
      'certutil',
      ['-N', '-d', database, '--empty-password'],
      { timeout: 5_000 },
    );
    await execFileAsync(
      'certutil',
      [
        '-A',
        '-d',
        database,
        '-n',
        'ReCasaOS ephemeral browser test CA',
        '-t',
        'C,,',
        '-i',
        caCertificateFile,
      ],
      { timeout: 5_000 },
    );
    await execFileAsync(
      'certutil',
      [
        '-L',
        '-d',
        database,
        '-n',
        'ReCasaOS ephemeral browser test CA',
      ],
      { timeout: 5_000 },
    );
    await execFileAsync(
      'certutil',
      [
        '-V',
        '-d',
        database,
        '-n',
        'ReCasaOS ephemeral browser test CA',
        '-u',
        'L',
        '-e',
      ],
      { timeout: 5_000 },
    );
    return profilePath;
  } catch {
    await removeFirefoxProfile(profilePath, runnerTemp);
    throw new Error('could not create the trusted Firefox test profile');
  }
}

async function launchIsolatedContext(browserName, playwright) {
  const contextOptions = {
    acceptDownloads: true,
    ignoreHTTPSErrors: false,
    serviceWorkers: 'allow',
  };
  if (browserName !== 'firefox') {
    const browser = await playwright[browserName].launch({
      headless: true,
    });
    try {
      const context = await browser.newContext(contextOptions);
      return { browser, context, profilePath: null };
    } catch (error) {
      await browser.close();
      throw error;
    }
  }

  const runnerTemp = requiredAbsoluteEnvironmentPath('RUNNER_TEMP');
  const caCertificateFile = requiredAbsoluteEnvironmentPath(
    'RECASAOS_BROWSER_CA_CERTIFICATE',
  );
  const profilePath = await createTrustedFirefoxProfile(
    runnerTemp,
    caCertificateFile,
  );
  try {
    const context = await playwright.firefox.launchPersistentContext(
      profilePath,
      {
        ...contextOptions,
        headless: true,
      },
    );
    return { browser: null, context, profilePath };
  } catch (error) {
    await removeFirefoxProfile(profilePath, runnerTemp);
    throw error;
  }
}

async function closeLaunchedContext(launched) {
  const cleanupErrors = [];
  try {
    await launched.context.close();
  } catch (error) {
    cleanupErrors.push(error);
  }
  if (launched.browser !== null) {
    try {
      await launched.browser.close();
    } catch (error) {
      cleanupErrors.push(error);
    }
  }
  if (launched.profilePath !== null) {
    try {
      const runnerTemp = requiredAbsoluteEnvironmentPath('RUNNER_TEMP');
      await removeFirefoxProfile(launched.profilePath, runnerTemp);
    } catch (error) {
      cleanupErrors.push(error);
    }
  }
  if (cleanupErrors.length !== 0) {
    throw new AggregateError(
      cleanupErrors,
      'browser test context cleanup failed',
    );
  }
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
  return validateSnapshot(
    await readControlObject(portal, '/snapshot', 'snapshot'),
  );
}

async function readControlObject(portal, pathName, label) {
  let response;
  try {
    response = await fetch(`${portal.controlOrigin}${pathName}`, {
      method: 'GET',
      redirect: 'error',
      signal: AbortSignal.timeout(3_000),
    });
  } catch {
    throw new Error(`browser harness ${label} request failed`);
  }
  if (
    response.status !== 200 ||
    response.redirected ||
    response.url !== `${portal.controlOrigin}${pathName}`
  ) {
    throw new Error(`browser harness ${label} response was rejected`);
  }
  let value;
  try {
    value = await response.json();
  } catch {
    throw new Error(`browser harness ${label} response is not JSON`);
  }
  return value;
}

export async function readServerDiagnostics(portal) {
  const value = await readControlObject(
    portal,
    '/diagnostics',
    'diagnostics',
  );
  if (!exactKeys(value, serverDiagnosticKeys)) {
    throw new Error('browser harness diagnostics schema is invalid');
  }
  for (const key of serverDiagnosticKeys) {
    if (!Number.isSafeInteger(value[key]) || value[key] < 0) {
      throw new Error('browser harness diagnostics value is invalid');
    }
  }
  return value;
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
  context: async ({ browserName, playwright }, use) => {
    const launched = await launchIsolatedContext(browserName, playwright);
    try {
      await use(launched.context);
    } finally {
      await closeLaunchedContext(launched);
    }
  },
  page: async ({ context }, use) => {
    const page = await context.newPage();
    try {
      await use(page);
    } finally {
      await page.close();
    }
  },
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
