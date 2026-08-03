import assert from 'node:assert/strict';
import test from 'node:test';
import {
  diagnosticBytesContainBearer,
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
