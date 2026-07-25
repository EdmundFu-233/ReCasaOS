import os from 'node:os';
import path from 'node:path';
import { defineConfig } from '@playwright/test';

const runnerTemp = process.env.RUNNER_TEMP || os.tmpdir();

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  workers: process.env.CI ? 1 : undefined,
  timeout: 120_000,
  expect: {
    timeout: 10_000,
  },
  reporter: 'line',
  outputDir: path.join(runnerTemp, 'recasaos-playwright-results'),
  preserveOutput: 'never',
  use: {
    acceptDownloads: true,
    headless: true,
    ignoreHTTPSErrors: false,
    screenshot: 'off',
    serviceWorkers: 'allow',
    trace: 'off',
    video: 'off',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        browserName: 'chromium',
      },
    },
    {
      name: 'firefox',
      use: {
        browserName: 'firefox',
        launchOptions: {
          firefoxUserPrefs: {
            'security.enterprise_roots.enabled': true,
          },
        },
      },
    },
    {
      name: 'webkit',
      use: {
        browserName: 'webkit',
      },
    },
  ],
});
