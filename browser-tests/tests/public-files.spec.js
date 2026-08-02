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

async function prepareManualDownload(page, bearer, path) {
  return page.evaluate(
    async ({ bearerValue, relativePath }) => {
      const controller = navigator.serviceWorker.controller;
      if (controller === null) {
        throw new Error('service worker controller is unavailable');
      }
      navigator.serviceWorker.removeEventListener(
        'message',
        handleWorkerChallenge,
      );

      const bytes = new Uint8Array(24);
      crypto.getRandomValues(bytes);
      let rawNonce = '';
      for (const byte of bytes) {
        rawNonce += String.fromCharCode(byte);
      }
      const nonce = btoa(rawNonce)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
      const requestURL = new URL('api/file', location.href);
      requestURL.search = '';
      requestURL.hash = nonce;
      requestURL.searchParams.set('path', relativePath);

      window.__recasaosIsolation = {
        challengeCount: 0,
        httpStatus: 0,
        status: '',
      };
      const onChallenge = (event) => {
        const data = event.data;
        const port = event.ports?.length === 1 ? event.ports[0] : null;
        if (
          port === null ||
          event.source !== controller ||
          data?.type !== 'recasaos-download-auth' ||
          data?.version !== 1 ||
          data?.nonce !== nonce ||
          data?.path !== relativePath ||
          data?.requestURL !== requestURL.href
        ) {
          return;
        }
        window.__recasaosIsolation.challengeCount += 1;
        port.onmessage = (statusEvent) => {
          const status = statusEvent.data;
          window.__recasaosIsolation.httpStatus = status?.httpStatus ?? 0;
          window.__recasaosIsolation.status = status?.status ?? '';
          navigator.serviceWorker.removeEventListener('message', onChallenge);
          port.close();
        };
        port.start();
        port.postMessage({
          type: 'recasaos-download-auth-response',
          version: 1,
          nonce,
          path: relativePath,
          token: bearerValue,
        });
      };
      navigator.serviceWorker.addEventListener('message', onChallenge);

      const prepared = await new Promise((resolve) => {
        const channel = new MessageChannel();
        let settled = false;
        const finish = (value) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          channel.port1.close();
          resolve(value);
        };
        const timer = setTimeout(() => finish(false), 3_000);
        channel.port1.onmessage = (event) =>
          finish(
            event.data?.type === 'recasaos-download-prepared' &&
              event.data?.version === 1 &&
              event.data?.nonce === nonce,
          );
        channel.port1.onmessageerror = () => finish(false);
        channel.port1.start();
        controller.postMessage(
          {
            type: 'recasaos-download-prepare',
            version: 1,
            nonce,
            path: relativePath,
            requestURL: requestURL.href,
          },
          [channel.port2],
        );
      });
      if (!prepared) {
        navigator.serviceWorker.removeEventListener('message', onChallenge);
        throw new Error('manual download reservation was denied');
      }
      return { nonce, path: relativePath, requestURL: requestURL.href };
    },
    { bearerValue: bearer, relativePath: path },
  );
}

async function navigateHiddenFrame(page, requestURL) {
  await page.evaluate((url) => {
    const frame = document.createElement('iframe');
    frame.hidden = true;
    frame.title = 'Cross-tab download probe';
    frame.referrerPolicy = 'no-referrer';
    document.body.append(frame);
    frame.src = url;
  }, requestURL);
}

function fileRequestState(snapshot) {
  return {
    active_file_requests: snapshot.active_file_requests,
    authorized_file_requests: snapshot.authorized_file_requests,
    authorized_range_file_requests:
      snapshot.authorized_range_file_requests,
    canceled_file_requests: snapshot.canceled_file_requests,
    completed_file_requests: snapshot.completed_file_requests,
    partial_file_responses: snapshot.partial_file_responses,
  };
}

async function expectFileRequestStateToRemainQuiescent(portal, terminal) {
  await delay(1_000);
  expect(
    fileRequestState(await readSnapshot(portal)),
    'the terminal file-request counters must remain quiescent',
  ).toEqual(fileRequestState(terminal));
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

test('a different tab cannot consume another tab download reservation', async ({
  context,
  page,
  portal,
}) => {
  await loginAndWaitForNativeStreaming(page, portal);
  const attacker = await context.newPage();
  try {
    await openPortal(attacker, portal);
    await expect
      .poll(() =>
        attacker.evaluate(
          () =>
            'serviceWorker' in navigator &&
            navigator.serviceWorker.controller !== null,
        ),
      )
      .toBe(true);

    const before = await readSnapshot(portal);
    const prepared = await prepareManualDownload(
      page,
      portal.bearer,
      'report.txt',
    );
    const attackerDownload = attacker
      .waitForEvent('download', { timeout: 750 })
      .then(
        () => true,
        () => false,
      );
    await navigateHiddenFrame(attacker, prepared.requestURL);
    expect(
      await attackerDownload,
      'a mismatched tab must not receive the prepared download',
    ).toBe(false);
    expect(
      await page.evaluate(() => window.__recasaosIsolation.challengeCount),
      'a mismatched tab must not trigger an authorization challenge',
    ).toBe(0);
    expect(
      fileRequestState(await readSnapshot(portal)),
      'a mismatched tab must not issue an authenticated file request',
    ).toEqual(fileRequestState(before));

    const downloadPromise = page.waitForEvent('download');
    await navigateHiddenFrame(page, prepared.requestURL);
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe('report.txt');
    expect(await download.failure()).toBeNull();
    expect(await hashDownload(download)).toEqual(portal.fixtures['report.txt']);
    await expect
      .poll(() => page.evaluate(() => window.__recasaosIsolation))
      .toEqual({ challengeCount: 1, httpStatus: 200, status: 'handed' });

    const after = await waitForSnapshot(
      portal,
      (snapshot) =>
        snapshot.active_file_requests === 0 &&
        snapshot.authorized_file_requests - before.authorized_file_requests ===
          1 &&
        snapshot.canceled_file_requests - before.canceled_file_requests === 0 &&
        snapshot.completed_file_requests - before.completed_file_requests === 1,
      'original tab download after cross-tab rejection',
    );
    expect(after.authorization_on_other_path).toBe(0);
    expect(after.credential_query_requests).toBe(0);
    await expectFileRequestStateToRemainQuiescent(portal, after);
  } finally {
    await attacker.close();
  }
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
        authorizedDelta === 1 &&
        canceledDelta === 0 &&
        completedDelta === 1
      );
    },
    'completed native browser download cleanup',
  );
  expect(
    after.authorized_file_requests - before.authorized_file_requests,
    'native download must use exactly one authenticated file request',
  ).toBe(1);
  expect(after.authorization_on_other_path).toBe(0);
  expect(after.credential_query_requests).toBe(0);
  await expectFileRequestStateToRemainQuiescent(portal, after);
});

test('browser HTTPS fetch preserves an initial byte range', async ({
  context,
  page,
  portal,
}) => {
  await loginAndWaitForNativeStreaming(page, portal);
  const before = await readSnapshot(portal);
  const expectedPayload = Buffer.from('public-file');
  const fileURL = new URL(
    '/public-files/api/file?path=report.txt',
    portal.origin,
  ).href;

  // Chromium's fresh-download manager rejects an explicitly ranged top-level
  // attachment as an invalid partial save. Exercise the browser transport
  // with fetch instead; the native full-download path is covered separately.
  const rangedResponse = await page.evaluate(
    async ({ bearer, url }) => {
      const response = await fetch(url, {
        cache: 'no-store',
        headers: {
          Authorization: `Bearer ${bearer}`,
          Range: 'bytes=9-19',
        },
        redirect: 'error',
      });
      return {
        acceptRanges: response.headers.get('Accept-Ranges'),
        contentDisposition: response.headers.get('Content-Disposition'),
        contentLength: response.headers.get('Content-Length'),
        contentRange: response.headers.get('Content-Range'),
        contentType: response.headers.get('Content-Type'),
        lastModified: response.headers.get('Last-Modified'),
        status: response.status,
        url: response.url,
        bytes: Array.from(new Uint8Array(await response.arrayBuffer())),
      };
    },
    { bearer: portal.bearer, url: fileURL },
  );

  expect(rangedResponse.status).toBe(206);
  expect(rangedResponse.url).toBe(fileURL);
  expect(rangedResponse.acceptRanges).toBe('bytes');
  expect(rangedResponse.contentDisposition).toMatch(
    /^attachment(?:\s*;|$)/i,
  );
  expect(rangedResponse.contentLength).toBe(String(expectedPayload.length));
  expect(rangedResponse.contentRange).toBe('bytes 9-19/50');
  expect(rangedResponse.contentType).toBe('application/octet-stream');
  expect(rangedResponse.lastModified).toBeNull();
  const downloaded = Buffer.from(rangedResponse.bytes);
  expect({
    sha256: createHash('sha256').update(downloaded).digest('hex'),
    size: downloaded.length,
  }).toEqual({
    sha256: createHash('sha256').update(expectedPayload).digest('hex'),
    size: expectedPayload.length,
  });

  expect(await context.cookies()).toEqual([]);
  expect(JSON.stringify(await context.storageState())).not.toContain(
    portal.bearer,
  );
  assertNoBrowserStorageResidue(
    await browserStorageResidue(page, portal.bearer),
  );

  const after = await waitForSnapshot(
    portal,
    (snapshot) =>
      snapshot.active_file_requests === 0 &&
      snapshot.authorized_file_requests -
        before.authorized_file_requests ===
        1 &&
      snapshot.authorized_range_file_requests -
        before.authorized_range_file_requests ===
        1 &&
      snapshot.partial_file_responses - before.partial_file_responses === 1 &&
      snapshot.canceled_file_requests - before.canceled_file_requests === 0 &&
      snapshot.completed_file_requests - before.completed_file_requests === 1,
    'completed initial range fetch',
  );
  expect(after.authorization_on_other_path).toBe(0);
  expect(after.credential_query_requests).toBe(0);
  await expectFileRequestStateToRemainQuiescent(portal, after);
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
        authorizedDelta === 1 &&
        canceledDelta + completedDelta === 1 &&
        (browserName === 'firefox' ||
          (canceledDelta === 1 && completedDelta === 0))
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
    'the authenticated browser request must reach exactly one terminal state',
  ).toBe(1);
  expect(
    authorizedDelta,
    'the canceled browser download must use exactly one authenticated request',
  ).toBe(1);
  if (browserName !== 'firefox') {
    expect(
      canceledDelta,
      'Chromium and WebKit must propagate cancellation upstream',
    ).toBe(1);
  }
  await expectFileRequestStateToRemainQuiescent(portal, after);
});
