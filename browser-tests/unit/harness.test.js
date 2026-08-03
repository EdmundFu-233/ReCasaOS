import assert from 'node:assert/strict';
import test from 'node:test';
import { acquireFixturePage } from '../tests/harness.js';

function page(url = 'about:blank', closed = false) {
  return {
    isClosed: () => closed,
    url: () => url,
  };
}

test('Firefox reuses the clean page created by its persistent context', async () => {
  const initialPage = page();
  let newPageCalls = 0;
  const acquired = await acquireFixturePage('firefox', {
    pages: () => [initialPage],
    newPage: async () => {
      newPageCalls += 1;
      return page();
    },
  });

  assert.equal(acquired.page, initialPage);
  assert.equal(acquired.closeBeforeContext, false);
  assert.equal(newPageCalls, 0);
});

test('Firefox fails closed when the persistent initial page is not clean', async () => {
  await assert.rejects(
    acquireFixturePage('firefox', {
      pages: () => [page('https://example.invalid/')],
    }),
    /did not provide one clean initial page/,
  );
  await assert.rejects(
    acquireFixturePage('firefox', {
      pages: () => [page(), page()],
    }),
    /did not provide one clean initial page/,
  );
  await assert.rejects(
    acquireFixturePage('firefox', {
      pages: () => [page('about:blank', true)],
    }),
    /did not provide one clean initial page/,
  );
});

test('ephemeral contexts create and own exactly one fixture page', async () => {
  const createdPage = page();
  let newPageCalls = 0;
  const acquired = await acquireFixturePage('chromium', {
    pages: () => [],
    newPage: async () => {
      newPageCalls += 1;
      return createdPage;
    },
  });

  assert.equal(acquired.page, createdPage);
  assert.equal(acquired.closeBeforeContext, true);
  assert.equal(newPageCalls, 1);
});

test('ephemeral contexts fail closed when a page already exists', async () => {
  await assert.rejects(
    acquireFixturePage('webkit', {
      pages: () => [page()],
    }),
    /was not initially empty/,
  );
});
