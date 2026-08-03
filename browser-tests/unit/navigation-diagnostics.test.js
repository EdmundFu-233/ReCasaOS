import assert from 'node:assert/strict';
import test from 'node:test';
import {
  diagnosticBytesContainBearer,
  diagnosticBytesContainSensitiveTraceData,
  isVerifiedFirefoxLifecycleDesynchronization,
  redactDiagnosticText,
  summarizeDiagnosticURL,
} from '../tests/navigation-diagnostics.js';

const syntheticBearer = `rc1_${'A'.repeat(43)}`;

test('diagnostic text removes ReCasaOS and generic bearer values', () => {
  const redacted = redactDiagnosticText(
    `candidate=${syntheticBearer} Authorization: Bearer abcdefghijklmnop`,
  );
  assert.equal(redacted.includes(syntheticBearer), false);
  assert.equal(redacted.includes('abcdefghijklmnop'), false);
  assert.match(redacted, /REDACTED_RECASAOS_BEARER/);
  assert.match(redacted, /Bearer \[REDACTED\]/);
});

test('diagnostic URLs retain routing shape but discard values', () => {
  assert.deepEqual(
    summarizeDiagnosticURL(
      `https://127.0.0.1:443/public-files/api/file?token=${syntheticBearer}#secret`,
    ),
    {
      valid: true,
      protocol: 'https:',
      origin: 'https://127.0.0.1',
      pathname: '/public-files/api/file',
      search_parameter_count: 1,
      has_fragment: true,
      has_userinfo: false,
    },
  );
  assert.deepEqual(
    summarizeDiagnosticURL(`not a URL ${syntheticBearer}`),
    { valid: false },
  );
});

test('diagnostic byte scanning detects an embedded bearer', () => {
  assert.equal(
    diagnosticBytesContainBearer(Buffer.from(`before${syntheticBearer}after`)),
    true,
  );
  assert.equal(
    diagnosticBytesContainBearer(Buffer.from('public pre-auth evidence')),
    false,
  );
});

test('diagnostic byte scanning rejects credential-bearing trace metadata', () => {
  for (const header of [
    'Authorization',
    'Cookie',
    'Proxy-Authorization',
    'Set-Cookie',
  ]) {
    assert.equal(
      diagnosticBytesContainSensitiveTraceData(
        Buffer.from(`{"headers":[{"name":"${header}","value":"redacted"}]}`),
      ),
      true,
    );
    assert.equal(
      diagnosticBytesContainSensitiveTraceData(
        Buffer.from(`{"headers":{"${header}":"redacted"}}`),
      ),
      true,
    );
  }
  assert.equal(
    diagnosticBytesContainSensitiveTraceData(
      Buffer.from('{"headers":[{"name":"User-Agent","value":"test"}]}'),
    ),
    false,
  );
  assert.equal(
    diagnosticBytesContainSensitiveTraceData(
      Buffer.from('{"cookies":[{"name":"session","value":"redacted"}]}'),
    ),
    true,
  );
  assert.equal(
    diagnosticBytesContainSensitiveTraceData(Buffer.from('{"cookies":[]}')),
    false,
  );
});

function portalURL() {
  return {
    valid: true,
    protocol: 'https:',
    origin: 'https://127.0.0.1',
    pathname: '/public-files/',
    search_parameter_count: 0,
    has_fragment: false,
    has_userinfo: false,
  };
}

function preAuthorizationPage(driverURL, driverURLIsAboutBlank = false) {
  return {
    ok: true,
    value: {
      browser_hidden: true,
      closed: false,
      controlled: false,
      document_ready_state: 'complete',
      document_url: portalURL(),
      driver_url_is_about_blank: driverURLIsAboutBlank,
      login_visible: true,
      secure_context: true,
      service_worker_registration_scopes: [],
      token_empty: true,
      url: driverURL,
    },
  };
}

function verifiedLifecycleDesynchronization() {
  const origin = 'https://127.0.0.1/public-files/';
  return {
    afterNavigationServer: {
      ok: true,
      value: {
        active_requests: 0,
        server_errors: 0,
        tls_handshake_errors: 0,
      },
    },
    browserName: 'firefox',
    firstPageState: preAuthorizationPage(portalURL()),
    navigationError: { name: 'TimeoutError' },
    navigationResponse: {
      from_service_worker: false,
      method: 'GET',
      redirected: false,
      resource_type: 'document',
      status: 200,
      url: origin,
    },
    portalOrigin: origin,
    serverDelta: { completed: 1, started: 1 },
    targetPageState: preAuthorizationPage(
      {
        valid: true,
        protocol: 'about:',
      },
      true,
    ),
    tlsProbe: {
      ok: true,
      value: {
        ok: true,
        status: 200,
        tls: { authorized: true, protocol: 'TLSv1.3' },
      },
    },
  };
}

test('Firefox lifecycle reconciliation requires every independent proof', () => {
  const valid = verifiedLifecycleDesynchronization();
  assert.equal(isVerifiedFirefoxLifecycleDesynchronization(valid), true);

  const mutations = [
    (value) => {
      value.browserName = 'chromium';
    },
    (value) => {
      value.navigationError.name = 'Error';
    },
    (value) => {
      value.navigationError = null;
    },
    (value) => {
      value.navigationResponse = null;
    },
    (value) => {
      value.afterNavigationServer = null;
    },
    (value) => {
      value.tlsProbe = null;
    },
    (value) => {
      value.firstPageState = null;
    },
    (value) => {
      value.targetPageState = null;
    },
    (value) => {
      value.navigationResponse.status = 401;
    },
    (value) => {
      value.navigationResponse.from_service_worker = true;
    },
    (value) => {
      value.navigationResponse.method = 'POST';
    },
    (value) => {
      value.navigationResponse.redirected = true;
    },
    (value) => {
      value.navigationResponse.resource_type = 'iframe';
    },
    (value) => {
      value.navigationResponse.url += '?unexpected=1';
    },
    (value) => {
      value.serverDelta.started = 0;
    },
    (value) => {
      value.serverDelta = null;
    },
    (value) => {
      value.serverDelta.completed = 0;
    },
    (value) => {
      value.afterNavigationServer.value.active_requests = 1;
    },
    (value) => {
      value.afterNavigationServer.ok = false;
    },
    (value) => {
      value.afterNavigationServer.value.server_errors = 1;
    },
    (value) => {
      value.afterNavigationServer.value.tls_handshake_errors = 1;
    },
    (value) => {
      value.tlsProbe.ok = false;
    },
    (value) => {
      value.tlsProbe.value.ok = false;
    },
    (value) => {
      value.tlsProbe.value.status = 500;
    },
    (value) => {
      value.tlsProbe.value.tls.authorized = false;
    },
    (value) => {
      value.tlsProbe.value.tls.protocol = 'TLSv1.2';
    },
    (value) => {
      value.firstPageState.value.token_empty = false;
    },
    (value) => {
      value.firstPageState.value.url.pathname = '/unexpected';
    },
    (value) => {
      value.firstPageState.value.document_url.has_fragment = true;
    },
    (value) => {
      value.targetPageState.ok = false;
    },
    (value) => {
      value.targetPageState.value.closed = true;
    },
    (value) => {
      value.targetPageState.value.driver_url_is_about_blank = false;
    },
    (value) => {
      value.targetPageState.value.url = portalURL();
    },
    (value) => {
      value.targetPageState.value.document_url.pathname = '/unexpected';
    },
    (value) => {
      value.targetPageState.value.controlled = true;
    },
    (value) => {
      value.targetPageState.value.browser_hidden = false;
    },
    (value) => {
      value.targetPageState.value.document_ready_state = 'loading';
    },
    (value) => {
      value.targetPageState.value.login_visible = false;
    },
    (value) => {
      value.targetPageState.value.secure_context = false;
    },
    (value) => {
      value.targetPageState.value.token_empty = false;
    },
    (value) => {
      value.targetPageState.value.service_worker_registration_scopes = [
        portalURL(),
      ];
    },
  ];
  for (const mutate of mutations) {
    const candidate = structuredClone(valid);
    mutate(candidate);
    assert.equal(isVerifiedFirefoxLifecycleDesynchronization(candidate), false);
  }
});
