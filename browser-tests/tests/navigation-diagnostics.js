import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, readFile, rm, writeFile } from 'node:fs/promises';
import { request as httpsRequest } from 'node:https';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { promisify } from 'node:util';
import { readServerDiagnostics, readSnapshot } from './harness.js';

const execFileAsync = promisify(execFile);
const bearerPattern = /rc1_[A-Za-z0-9_-]{43}/;
const bearerPatternGlobal = /rc1_[A-Za-z0-9_-]{43}/g;
const genericBearerPattern = /\bBearer\s+[A-Za-z0-9._~+/-]{8,}/gi;
const sensitiveTraceDataPattern =
  /(?:"name"\s*:\s*"(?:proxy-authorization|authorization|set-cookie|cookie)"|"(?:proxy-authorization|authorization|set-cookie|cookie)"\s*:|"cookies"\s*:\s*\[\s*\{)/i;
const navigationTimeoutMs = 20_000;
const diagnosticOperationTimeoutMs = 3_000;
const maximumDiagnosticEvents = 96;
const maximumDiagnosticStringLength = 512;
const maximumTraceArchiveBytes = 32 << 20;
const maximumExpandedTraceBytes = 64 << 20;

function errorSummary(error) {
  return {
    name: redactDiagnosticText(error?.name || 'Error'),
    message: redactDiagnosticText(error?.message || 'unknown error'),
  };
}

export function diagnosticBytesContainBearer(payload) {
  const bytes = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  return bearerPattern.test(bytes.toString('latin1'));
}

export function diagnosticBytesContainSensitiveTraceData(payload) {
  const bytes = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  return sensitiveTraceDataPattern.test(bytes.toString('latin1'));
}

export function redactDiagnosticText(value) {
  let text = String(value)
    .replace(bearerPatternGlobal, '[REDACTED_RECASAOS_BEARER]')
    .replace(genericBearerPattern, 'Bearer [REDACTED]');
  if (text.length > maximumDiagnosticStringLength) {
    text = `${text.slice(0, maximumDiagnosticStringLength)}[TRUNCATED]`;
  }
  return text;
}

export function summarizeDiagnosticURL(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    return {
      valid: false,
    };
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return {
      valid: true,
      protocol: url.protocol,
    };
  }
  return {
    valid: true,
    protocol: url.protocol,
    origin: url.origin,
    pathname: url.pathname,
    search_parameter_count: Array.from(url.searchParams.keys()).length,
    has_fragment: url.hash !== '',
    has_userinfo: url.username !== '' || url.password !== '',
  };
}

function recordPageEvents(page) {
  const started = Date.now();
  const events = [];
  let omitted = 0;
  let navigationResponse = null;
  const listeners = [];
  const record = (type, value = {}) => {
    if (events.length >= maximumDiagnosticEvents) {
      omitted += 1;
      return;
    }
    events.push({
      elapsed_ms: Date.now() - started,
      type,
      ...value,
    });
  };
  const listen = (name, handler) => {
    page.on(name, handler);
    listeners.push([name, handler]);
  };

  listen('request', (request) => {
    record('request', {
      method: request.method(),
      navigation: request.isNavigationRequest(),
      resource_type: request.resourceType(),
      url: summarizeDiagnosticURL(request.url()),
    });
  });
  listen('response', (response) => {
    const request = response.request();
    if (
      request.isNavigationRequest() &&
      request.frame() === page.mainFrame() &&
      navigationResponse === null
    ) {
      navigationResponse = response;
    }
    record('response', {
      navigation: request.isNavigationRequest(),
      resource_type: request.resourceType(),
      status: response.status(),
      url: summarizeDiagnosticURL(response.url()),
    });
  });
  listen('requestfailed', (request) => {
    record('request_failed', {
      failure: redactDiagnosticText(
        request.failure()?.errorText || 'unknown request failure',
      ),
      navigation: request.isNavigationRequest(),
      resource_type: request.resourceType(),
      url: summarizeDiagnosticURL(request.url()),
    });
  });
  listen('console', (message) => {
    record('console', {
      console_type: message.type(),
      text: redactDiagnosticText(message.text()),
    });
  });
  listen('pageerror', (error) => {
    record('page_error', errorSummary(error));
  });
  listen('domcontentloaded', () => record('dom_content_loaded'));
  listen('load', () => record('load'));
  listen('crash', () => record('page_crashed'));
  listen('close', () => record('page_closed'));
  listen('worker', (worker) => {
    record('worker_created', {
      url: summarizeDiagnosticURL(worker.url()),
    });
  });

  return {
    snapshot() {
      return {
        events: [...events],
        omitted_events: omitted,
      };
    },
    navigationResponse() {
      return navigationResponse;
    },
    stop() {
      for (const [name, handler] of listeners) {
        page.off(name, handler);
      }
    },
  };
}

async function bounded(operation, label) {
  return Promise.race([
    Promise.resolve(operation),
    delay(diagnosticOperationTimeoutMs).then(() => {
      throw new Error(`${label} exceeded the diagnostic deadline`);
    }),
  ]);
}

async function capture(operation) {
  try {
    return { ok: true, value: await operation };
  } catch (error) {
    return { ok: false, error: errorSummary(error) };
  }
}

async function inspectPage(page) {
  if (page.isClosed()) {
    return { closed: true };
  }
  const browser = page.context().browser();
  const driverURL = page.url();
  const value = await bounded(
    page.evaluate(async () => {
      let registrations = [];
      if ('serviceWorker' in navigator) {
        registrations = await navigator.serviceWorker.getRegistrations();
      }
      return {
        browser_hidden: document.getElementById('browser')?.hidden === true,
        controlled:
          'serviceWorker' in navigator &&
          navigator.serviceWorker.controller !== null,
        document_url: window.location.href,
        document_ready_state: document.readyState,
        login_visible: document.getElementById('login')?.hidden === false,
        secure_context: window.isSecureContext,
        service_worker_registration_scopes: registrations.map(
          (registration) => registration.scope,
        ),
        token_empty: document.getElementById('token')?.value === '',
        user_agent: navigator.userAgent,
        webdriver: navigator.webdriver,
      };
    }),
    'page inspection',
  );
  return {
    closed: false,
    browser_version: browser === null ? null : browser.version(),
    driver_url_is_about_blank: driverURL === 'about:blank',
    url: summarizeDiagnosticURL(driverURL),
    ...value,
    document_url: summarizeDiagnosticURL(value.document_url),
    service_worker_registration_scopes:
      value.service_worker_registration_scopes.map(summarizeDiagnosticURL),
    user_agent: redactDiagnosticText(value.user_agent),
  };
}

function requiredAbsoluteEnvironmentPath(name) {
  const value = process.env[name];
  if (typeof value !== 'string' || value.length === 0 || !path.isAbsolute(value)) {
    throw new Error(`required absolute environment path ${name} is missing`);
  }
  return path.resolve(value);
}

async function probePortalTLS(portal) {
  const certificatePath = requiredAbsoluteEnvironmentPath(
    'RECASAOS_BROWSER_CA_CERTIFICATE',
  );
  const ca = await readFile(certificatePath);
  const target = new URL(portal.origin);
  if (
    target.protocol !== 'https:' ||
    target.username !== '' ||
    target.password !== '' ||
    target.search !== '' ||
    target.hash !== ''
  ) {
    throw new Error('portal diagnostic target is unsafe');
  }

  return new Promise((resolve) => {
    let settled = false;
    let received = 0;
    const tls = {
      authorized: false,
      authorization_error: null,
      cipher: null,
      peer_fingerprint_sha256: null,
      protocol: null,
    };
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    const request = httpsRequest(
      target,
      {
        ca,
        headers: { Connection: 'close' },
        method: 'GET',
        rejectUnauthorized: true,
      },
      (response) => {
        response.on('data', (chunk) => {
          received += chunk.length;
          if (received > 128 << 10) {
            request.destroy(new Error('portal diagnostic response is too large'));
          }
        });
        response.once('end', () => {
          finish({
            ok: response.statusCode === 200 && tls.authorized,
            body_bytes: received,
            status: response.statusCode ?? 0,
            tls,
          });
        });
      },
    );
    request.once('socket', (socket) => {
      socket.once('secureConnect', () => {
        const cipher = socket.getCipher();
        const peer = socket.getPeerCertificate();
        tls.authorized = socket.authorized;
        tls.authorization_error = socket.authorizationError
          ? redactDiagnosticText(socket.authorizationError)
          : null;
        tls.cipher = cipher?.name || null;
        tls.peer_fingerprint_sha256 = peer?.fingerprint256 || null;
        tls.protocol = socket.getProtocol();
      });
    });
    request.setTimeout(diagnosticOperationTimeoutMs, () => {
      request.destroy(new Error('portal TLS probe timed out'));
    });
    request.once('error', (error) => {
      finish({ ok: false, error: errorSummary(error), tls });
    });
    request.end();
  });
}

async function diagnosticsRoot() {
  const root = requiredAbsoluteEnvironmentPath(
    'RECASAOS_BROWSER_DIAGNOSTICS_DIRECTORY',
  );
  const runnerTemp = requiredAbsoluteEnvironmentPath('RUNNER_TEMP');
  if (
    path.dirname(root) !== runnerTemp ||
    !/^recasaos-browser-diagnostics-[0-9]+-[0-9]+$/.test(
      path.basename(root),
    )
  ) {
    throw new Error('browser diagnostics directory is outside its safe root');
  }
  const metadata = await lstat(root);
  if (
    !metadata.isDirectory() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== process.geteuid() ||
    (metadata.mode & 0o777) !== 0o700
  ) {
    throw new Error('browser diagnostics directory metadata is unsafe');
  }
  return root;
}

async function validateTraceArchive(tracePath) {
  const metadata = await lstat(tracePath);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.uid !== process.geteuid() ||
    metadata.size <= 0 ||
    metadata.size > maximumTraceArchiveBytes
  ) {
    throw new Error('navigation trace metadata is unsafe');
  }
  const archive = await readFile(tracePath);
  if (diagnosticBytesContainBearer(archive)) {
    throw new Error('navigation trace archive contains a bearer');
  }
  if (diagnosticBytesContainSensitiveTraceData(archive)) {
    throw new Error('navigation trace archive contains credential metadata');
  }
  const { stdout } = await execFileAsync('unzip', ['-p', tracePath], {
    encoding: null,
    maxBuffer: maximumExpandedTraceBytes,
    timeout: 10_000,
  });
  if (diagnosticBytesContainBearer(stdout)) {
    throw new Error('expanded navigation trace contains a bearer');
  }
  if (diagnosticBytesContainSensitiveTraceData(stdout)) {
    throw new Error('expanded navigation trace contains credential metadata');
  }
}

async function preserveTrace(context, tracePath, traceStarted) {
  if (!traceStarted) {
    return { preserved: false, reason: 'trace did not start' };
  }
  try {
    await context.tracing.stop({ path: tracePath });
    await validateTraceArchive(tracePath);
    return {
      preserved: true,
      filename: path.basename(tracePath),
    };
  } catch (error) {
    await rm(tracePath, { force: true });
    return {
      preserved: false,
      reason: errorSummary(error),
    };
  }
}

async function persistDiagnostics(context, diagnostic, testInfo, traceStarted) {
  let root;
  try {
    root = await diagnosticsRoot();
  } catch (error) {
    if (traceStarted) {
      await context.tracing.stop().catch(() => {});
    }
    return { preserved: false, reason: errorSummary(error) };
  }

  const key = createHash('sha256')
    .update(testInfo.testId)
    .digest('hex')
    .slice(0, 12);
  const base = `${testInfo.project.name}-${key}`;
  const tracePath = path.join(root, `${base}-trace.zip`);
  const jsonPath = path.join(root, `${base}-diagnostics.json`);
  const trace = await preserveTrace(context, tracePath, traceStarted);
  const payload = {
    ...diagnostic,
    trace,
  };
  const serialized = `${JSON.stringify(payload, null, 2)}\n`;
  if (
    diagnosticBytesContainBearer(serialized) ||
    diagnosticBytesContainSensitiveTraceData(serialized)
  ) {
    await rm(tracePath, { force: true });
    return {
      preserved: false,
      reason: {
        name: 'Error',
        message: 'diagnostics contained credential material',
      },
    };
  }
  try {
    await writeFile(jsonPath, serialized, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
  } catch (error) {
    await rm(tracePath, { force: true });
    return { preserved: false, reason: errorSummary(error) };
  }
  return {
    preserved: true,
    diagnostics_filename: path.basename(jsonPath),
    trace,
  };
}

function serverDocumentDelta(before, after) {
  if (!before.ok || !after.ok) return null;
  return {
    completed:
      after.value.portal_documents_completed -
      before.value.portal_documents_completed,
    started:
      after.value.portal_documents_started -
      before.value.portal_documents_started,
  };
}

function exactPortalURL(summary, portalOrigin) {
  const expected = summarizeDiagnosticURL(portalOrigin);
  return (
    expected.valid === true &&
    summary !== null &&
    typeof summary === 'object' &&
    summary.valid === true &&
    summary.protocol === expected.protocol &&
    summary.origin === expected.origin &&
    summary.pathname === expected.pathname &&
    summary.search_parameter_count === 0 &&
    summary.has_fragment === false &&
    summary.has_userinfo === false
  );
}

function exactPreAuthorizationPage(state, portalOrigin, staleDriverURL) {
  if (state?.ok !== true || state.value?.closed !== false) return false;
  const value = state.value;
  const driverURLMatches = staleDriverURL
    ? value.driver_url_is_about_blank === true &&
      value.url?.valid === true &&
      value.url.protocol === 'about:'
    : exactPortalURL(value.url, portalOrigin);
  return (
    driverURLMatches &&
    exactPortalURL(value.document_url, portalOrigin) &&
    value.browser_hidden === true &&
    value.controlled === false &&
    value.document_ready_state === 'complete' &&
    value.login_visible === true &&
    value.secure_context === true &&
    Array.isArray(value.service_worker_registration_scopes) &&
    value.service_worker_registration_scopes.length === 0 &&
    value.token_empty === true
  );
}

export function isVerifiedFirefoxLifecycleDesynchronization({
  afterNavigationServer,
  browserName,
  firstPageState,
  navigationError,
  navigationResponse,
  portalOrigin,
  serverDelta,
  targetPageState,
  tlsProbe,
}) {
  return (
    browserName === 'firefox' &&
    navigationError?.name === 'TimeoutError' &&
    navigationResponse?.from_service_worker === false &&
    navigationResponse.method === 'GET' &&
    navigationResponse.redirected === false &&
    navigationResponse.resource_type === 'document' &&
    navigationResponse?.status === 200 &&
    navigationResponse.url === portalOrigin &&
    serverDelta?.started === 1 &&
    serverDelta.completed === 1 &&
    afterNavigationServer?.ok === true &&
    afterNavigationServer.value?.active_requests === 0 &&
    afterNavigationServer.value.server_errors === 0 &&
    afterNavigationServer.value.tls_handshake_errors === 0 &&
    tlsProbe?.ok === true &&
    tlsProbe.value?.ok === true &&
    tlsProbe.value.status === 200 &&
    tlsProbe.value.tls?.authorized === true &&
    tlsProbe.value.tls.protocol === 'TLSv1.3' &&
    exactPreAuthorizationPage(firstPageState, portalOrigin, false) &&
    exactPreAuthorizationPage(targetPageState, portalOrigin, true)
  );
}

async function requirePreAuthorizationTraceBoundary(firstPage, page, portal) {
  const first = await inspectPage(firstPage);
  if (
    first.closed ||
    firstPage.url() !== portal.origin ||
    first.login_visible !== true ||
    first.token_empty !== true ||
    first.controlled !== false ||
    first.service_worker_registration_scopes.length !== 0 ||
    page.isClosed() ||
    page.url() !== 'about:blank'
  ) {
    throw new Error('refusing to trace outside the pre-authorization boundary');
  }
  return first;
}

export async function navigatePortalWithDiagnostics({
  browserName,
  context,
  firstPage,
  page,
  portal,
  testInfo,
}) {
  const preflightFirstPage = await requirePreAuthorizationTraceBoundary(
    firstPage,
    page,
    portal,
  );
  const beforeServer = await capture(readServerDiagnostics(portal));
  const recorder = recordPageEvents(page);
  let traceStarted = false;
  let traceStartError = null;
  try {
    await context.tracing.start({
      screenshots: true,
      snapshots: true,
      sources: false,
      title: 'ReCasaOS pre-auth cross-tab navigation',
    });
    traceStarted = true;
  } catch (error) {
    traceStartError = errorSummary(error);
  }

  try {
    const response = await page.goto(portal.origin, {
      timeout: navigationTimeoutMs,
      waitUntil: 'domcontentloaded',
    });
    recorder.stop();
    if (traceStarted) {
      await context.tracing.stop();
    }
    return {
      response,
      verifiedFirefoxDocumentState: false,
    };
  } catch (error) {
    const navigationError = errorSummary(error);
    const afterNavigationServer = await capture(readServerDiagnostics(portal));
    const [fileSnapshot, firstPageState, targetPageState] = await Promise.all([
      capture(readSnapshot(portal)),
      capture(inspectPage(firstPage)),
      capture(inspectPage(page)),
    ]);
    const tlsProbe = await capture(probePortalTLS(portal));
    const afterProbeServer = await capture(readServerDiagnostics(portal));
    const delta = serverDocumentDelta(beforeServer, afterNavigationServer);
    const navigationResponse = recorder.navigationResponse();
    let lifecycleDesynchronization =
      isVerifiedFirefoxLifecycleDesynchronization({
        afterNavigationServer,
        browserName,
        firstPageState,
        navigationError,
        navigationResponse:
          navigationResponse === null
            ? null
            : {
                from_service_worker: navigationResponse.fromServiceWorker(),
                method: navigationResponse.request().method(),
                redirected:
                  navigationResponse.request().redirectedFrom() !== null,
                resource_type: navigationResponse.request().resourceType(),
                status: navigationResponse.status(),
                url: navigationResponse.url(),
              },
        portalOrigin: portal.origin,
        serverDelta: delta,
        targetPageState,
        tlsProbe,
      });
    let reconciliationRecheck = null;
    if (lifecycleDesynchronization) {
      const [finalFirstPageState, finalTargetPageState] = await Promise.all([
        capture(inspectPage(firstPage)),
        capture(inspectPage(page)),
      ]);
      reconciliationRecheck = {
        first: finalFirstPageState,
        target: finalTargetPageState,
      };
      lifecycleDesynchronization =
        exactPreAuthorizationPage(finalFirstPageState, portal.origin, false) &&
        exactPreAuthorizationPage(finalTargetPageState, portal.origin, true);
    }
    if (lifecycleDesynchronization && traceStarted) {
      try {
        await context.tracing.stop();
        traceStarted = false;
      } catch {
        lifecycleDesynchronization = false;
      }
    }
    if (lifecycleDesynchronization) {
      recorder.stop();
      console.warn(
        'ReCasaOS verified a Firefox navigation lifecycle desynchronization; ' +
          'validating the loaded document directly before continuing with ' +
          'the full cross-tab isolation assertions',
      );
      return {
        response: navigationResponse,
        verifiedFirefoxDocumentState: true,
      };
    }
    recorder.stop();

    const diagnostic = {
      schema: 'recasaos-browser-navigation-diagnostics-v1',
      browser: {
        name: browserName,
        node_version: process.version,
        playwright_project: testInfo.project.name,
      },
      github: {
        run_attempt: redactDiagnosticText(
          process.env.GITHUB_RUN_ATTEMPT || 'unknown',
        ),
        run_id: redactDiagnosticText(process.env.GITHUB_RUN_ID || 'unknown'),
        sha: redactDiagnosticText(process.env.GITHUB_SHA || 'unknown'),
      },
      navigation: {
        error: navigationError,
        events: recorder.snapshot(),
        target: summarizeDiagnosticURL(portal.origin),
        timeout_ms: navigationTimeoutMs,
      },
      pages: {
        first_after_failure: firstPageState,
        first_before_trace: preflightFirstPage,
        reconciliation_recheck: reconciliationRecheck,
        target: targetPageState,
      },
      service: {
        after_navigation: afterNavigationServer,
        after_probe: afterProbeServer,
        before_navigation: beforeServer,
        file_request_snapshot: fileSnapshot,
        portal_document_navigation_delta: delta,
        tls_probe: tlsProbe,
      },
      trace_start_error: traceStartError,
    };
    const artifact = await persistDiagnostics(
      context,
      diagnostic,
      testInfo,
      traceStarted,
    );
    const logPayload = {
      ...diagnostic,
      artifact,
    };
    const serialized = JSON.stringify(logPayload);
    if (!diagnosticBytesContainBearer(serialized)) {
      console.error(`ReCasaOS navigation diagnostics: ${serialized}`);
    }
    const diagnosticDelta =
      diagnostic.service.portal_document_navigation_delta;
    const deltaText =
      diagnosticDelta === null
        ? 'server document delta unavailable'
        : `server document delta started=${diagnosticDelta.started} completed=${diagnosticDelta.completed}`;
    throw new Error(
      `pre-auth cross-tab navigation failed after ${navigationTimeoutMs}ms; ` +
        `${deltaText}; diagnostic artifact preserved=${artifact.preserved}`,
    );
  }
}
