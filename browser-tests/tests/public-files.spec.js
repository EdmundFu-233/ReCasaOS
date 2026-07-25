import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import {
  expect,
  freshBearer,
  readSnapshot,
  test,
  waitForSnapshot,
} from './harness.js';

async function openPortal(page, portal) {
  const response = await page.goto(portal.origin, {
    waitUntil: 'domcontentloaded',
  });
  expect(response !== null && response.ok(), 'portal document must load').toBe(
    true,
  );
  await expect(page.locator('#login')).toBeVisible();
  await expect(page.locator('#browser')).toBeHidden();
  await expect(page.locator('#token')).toHaveValue('');
}

async function submitBearer(page, bearer) {
  try {
    await page.evaluate((candidate) => {
      const form = document.getElementById('login');
      const input = document.getElementById('token');
      if (
        !(form instanceof HTMLFormElement) ||
        !(input instanceof HTMLInputElement)
      ) {
        throw new Error('login controls are unavailable');
      }
      input.value = candidate;
      form.requestSubmit();
    }, bearer);
  } catch {
    throw new Error('browser login submission failed');
  }
}

async function loginAndWaitForNativeStreaming(page, portal) {
  await openPortal(page, portal);
  await submitBearer(page, portal.bearer);

  await expect(page.locator('#login')).toBeHidden();
  await expect(page.locator('#browser')).toBeVisible();
  await expect(page.locator('#token')).toHaveValue('');
  await expect(page.locator('#entries li')).toHaveCount(2);
  await expect(
    page.locator('#entries a', { hasText: 'report.txt' }),
  ).toHaveCount(1);
  await expect(
    page.locator('#entries a', { hasText: 'stream.bin' }),
  ).toHaveCount(1);

  await expect
    .poll(() =>
      page.evaluate(
        () =>
          window.isSecureContext === true &&
          'serviceWorker' in navigator &&
          navigator.serviceWorker.controller !== null,
      ),
    )
    .toBe(true);
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          typeof window.canUseNativeStreaming === 'function' &&
          window.canUseNativeStreaming() === true,
      ),
    )
    .toBe(true);
}

async function hashDownload(download) {
  let stream;
  try {
    stream = await download.createReadStream();
  } catch {
    throw new Error('completed browser download could not be opened');
  }
  const digest = createHash('sha256');
  let size = 0;
  try {
    for await (const chunk of stream) {
      size += chunk.length;
      digest.update(chunk);
    }
  } catch {
    throw new Error('completed browser download could not be read');
  }
  return { sha256: digest.digest('hex'), size };
}

async function browserStorageResidue(page, bearer) {
  try {
    return await page.evaluate(async (secret) => {
      const contains = (value) =>
        typeof value === 'string' && value.includes(secret);
      const storageContains = (storage) => {
        for (let index = 0; index < storage.length; index += 1) {
          const key = storage.key(index);
          if (
            contains(key) ||
            contains(key === null ? null : storage.getItem(key))
          ) {
            return true;
          }
        }
        return false;
      };
      let historyContains = false;
      try {
        historyContains = contains(JSON.stringify(history.state));
      } catch {
        historyContains = true;
      }
      const cacheNames = await caches.keys();
      const databases =
        typeof indexedDB.databases === 'function'
          ? await indexedDB.databases()
          : null;
      return {
        cacheCount: cacheNames.length,
        cacheNameContainsBearer: cacheNames.some(contains),
        cookieContainsBearer: contains(document.cookie),
        databaseCount: databases === null ? -1 : databases.length,
        databaseNameContainsBearer:
          databases === null
            ? true
            : databases.some((database) => contains(database.name)),
        historyContainsBearer: historyContains,
        localStorageContainsBearer: storageContains(localStorage),
        localStorageCount: localStorage.length,
        pageURLContainsBearer: contains(location.href),
        sessionStorageContainsBearer: storageContains(sessionStorage),
        sessionStorageCount: sessionStorage.length,
      };
    }, bearer);
  } catch {
    throw new Error('browser storage inspection failed');
  }
}

function assertNoBrowserStorageResidue(residue) {
  expect(residue, 'browser-visible storage must remain credential-free').toEqual({
    cacheCount: 0,
    cacheNameContainsBearer: false,
    cookieContainsBearer: false,
    databaseCount: 0,
    databaseNameContainsBearer: false,
    historyContainsBearer: false,
    localStorageContainsBearer: false,
    localStorageCount: 0,
    pageURLContainsBearer: false,
    sessionStorageContainsBearer: false,
    sessionStorageCount: 0,
  });
}

test('trusted HTTPS login is controlled by the service worker', async ({
  page,
  portal,
}) => {
  await loginAndWaitForNativeStreaming(page, portal);

  const state = await page.evaluate(() => ({
    controlled: navigator.serviceWorker.controller !== null,
    inputEmpty: document.getElementById('token')?.value === '',
    protocol: location.protocol,
    secureContext: window.isSecureContext,
  }));
  expect(state).toEqual({
    controlled: true,
    inputEmpty: true,
    protocol: 'https:',
    secureContext: true,
  });
});

test('an incorrect bearer fails closed', async ({ page, portal }) => {
  await openPortal(page, portal);
  const before = await readSnapshot(portal);
  let incorrectBearer = freshBearer();
  while (incorrectBearer === portal.bearer) {
    incorrectBearer = freshBearer();
  }
  await submitBearer(page, incorrectBearer);

  await expect(page.locator('#login')).toBeVisible();
  await expect(page.locator('#browser')).toBeHidden();
  await expect(page.locator('#token')).toHaveValue('');
  await expect(page.locator('#status')).toHaveText('Authorization failed');
  await expect(page.locator('#entries li')).toHaveCount(0);

  const after = await readSnapshot(portal);
  expect(
    after.authorized_list_requests === before.authorized_list_requests,
    'incorrect credentials must not authorize a listing',
  ).toBe(true);
  expect(
    after.authorization_on_other_path === before.authorization_on_other_path,
    'incorrect credentials must not authorize another route',
  ).toBe(true);
  expect(
    after.credential_query_requests === before.credential_query_requests,
    'credentials must not be sent in a query',
  ).toBe(true);
});

test('native browser download preserves bytes and leaves no bearer residue', async ({
  context,
  page,
  portal,
}) => {
  await loginAndWaitForNativeStreaming(page, portal);
  const before = await readSnapshot(portal);
  const initialPageURL = page.url();
  const initialHistoryLength = await page.evaluate(() => history.length);

  const downloadPromise = page.waitForEvent('download');
  await page.locator('#entries a', { hasText: 'stream.bin' }).click();
  const download = await downloadPromise;

  expect(
    download.suggestedFilename() === 'stream.bin',
    'native browser download must use the reviewed filename',
  ).toBe(true);
  const downloadURL = download.url();
  let parsedDownloadURL;
  try {
    parsedDownloadURL = new URL(downloadURL);
  } catch {
    throw new Error('native browser download URL is invalid');
  }
  const portalURL = new URL(portal.origin);
  expect(
    !downloadURL.includes(portal.bearer) &&
      parsedDownloadURL.protocol === 'https:' &&
      parsedDownloadURL.origin === portalURL.origin &&
      parsedDownloadURL.pathname === '/public-files/api/file' &&
      parsedDownloadURL.searchParams.size === 1 &&
      parsedDownloadURL.searchParams.getAll('path').length === 1 &&
      parsedDownloadURL.searchParams.get('path') === 'stream.bin',
    'native download URL must be HTTPS, scoped, and credential-free',
  ).toBe(true);

  const failure = await download.failure();
  expect(failure === null, 'native browser download must complete').toBe(true);
  const downloaded = await hashDownload(download);
  expect(downloaded.size).toBe(portal.fixtures['stream.bin'].size);
  expect(downloaded.sha256).toBe(portal.fixtures['stream.bin'].sha256);

  expect(
    page.url() === initialPageURL &&
      !page.url().includes(portal.bearer) &&
      (await page.evaluate(() => history.length)) === initialHistoryLength,
    'native download must not add a credential-bearing history entry',
  ).toBe(true);

  const cookies = await context.cookies();
  expect(
    cookies.length === 0 &&
      !cookies.some(
        (cookie) =>
          cookie.name.includes(portal.bearer) ||
          cookie.value.includes(portal.bearer),
      ),
    'browser cookies must remain credential-free',
  ).toBe(true);
  const storageState = await context.storageState();
  expect(
    !JSON.stringify(storageState).includes(portal.bearer),
    'Playwright storage state must remain credential-free',
  ).toBe(true);
  assertNoBrowserStorageResidue(
    await browserStorageResidue(page, portal.bearer),
  );

  const after = await waitForSnapshot(
    portal,
    (snapshot) =>
      snapshot.active_file_requests === 0 &&
      snapshot.completed_file_requests > before.completed_file_requests,
    'completed native browser download cleanup',
  );
  expect(
    after.authorized_file_requests > before.authorized_file_requests,
    'native download must use the authenticated file endpoint',
  ).toBe(true);
  expect(after.authorization_on_other_path).toBe(0);
  expect(after.credential_query_requests).toBe(0);
});

test('canceling a browser download reaches bounded terminal cleanup', async ({
  browserName,
  page,
  portal,
}) => {
  await loginAndWaitForNativeStreaming(page, portal);
  const before = await readSnapshot(portal);

  const downloadPromise = page.waitForEvent('download');
  await page.locator('#entries a', { hasText: 'stream.bin' }).click();
  const download = await downloadPromise;
  await waitForSnapshot(
    portal,
    (snapshot) => snapshot.active_file_requests > 0,
    'active native browser download',
  );

  await download.cancel();
  const failure = await download.failure();
  expect(
    failure === 'canceled',
    'Playwright must report an explicitly canceled download',
  ).toBe(true);
  const after = await waitForSnapshot(
    portal,
    (snapshot) => {
      const authorizedDelta =
        snapshot.authorized_file_requests -
        before.authorized_file_requests;
      const canceledDelta =
        snapshot.canceled_file_requests -
        before.canceled_file_requests;
      const completedDelta =
        snapshot.completed_file_requests -
        before.completed_file_requests;
      return (
        snapshot.active_file_requests === 0 &&
        authorizedDelta >= 1 &&
        canceledDelta + completedDelta === authorizedDelta
      );
    },
    'terminal native browser download cleanup',
    40_000,
  );
  const authorizedDelta =
    after.authorized_file_requests - before.authorized_file_requests;
  const canceledDelta =
    after.canceled_file_requests - before.canceled_file_requests;
  const completedDelta =
    after.completed_file_requests - before.completed_file_requests;
  expect(
    canceledDelta + completedDelta,
    'every authenticated browser request must reach one terminal state',
  ).toBe(authorizedDelta);
  expect(
    authorizedDelta,
    'the canceled browser download must use the authenticated endpoint',
  ).toBeGreaterThanOrEqual(1);
  if (browserName !== 'firefox') {
    expect(
      canceledDelta,
      'Chromium and WebKit must propagate cancellation upstream',
    ).toBeGreaterThanOrEqual(1);
  }
  await delay(1_000);
  const quiescent = await readSnapshot(portal);
  expect(
    {
      active_file_requests: quiescent.active_file_requests,
      authorized_file_requests: quiescent.authorized_file_requests,
      canceled_file_requests: quiescent.canceled_file_requests,
      completed_file_requests: quiescent.completed_file_requests,
    },
    'the terminal file-request counters must remain quiescent',
  ).toEqual({
    active_file_requests: 0,
    authorized_file_requests: after.authorized_file_requests,
    canceled_file_requests: after.canceled_file_requests,
    completed_file_requests: after.completed_file_requests,
  });
});
