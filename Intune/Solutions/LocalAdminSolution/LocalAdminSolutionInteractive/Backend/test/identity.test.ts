import test from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig } from '../src/config.js';
import { ApiError } from '../src/errors.js';
import { recoveryOwnerKey, validateClientApplication } from '../src/identity.js';
import { validateSettings } from '../src/models.js';

test('configuration accepts an explicit wildcard but rejects non-HTTPS origins', () => {
  const wildcard = loadConfig({
    TENANT_ID: '11111111-1111-4111-8111-111111111111',
    API_CLIENT_ID: '22222222-2222-4222-8222-222222222222',
    SPA_CLIENT_ID: '44444444-4444-4444-8444-444444444444',
    GOVERNANCE_TABLE_ENDPOINT: 'https://examplegov.table.core.windows.net',
    ALLOWED_ORIGINS: '*'
  });
  assert.equal(wildcard.allowedOrigins.has('*'), true);
  assert.throws(() => loadConfig({
    TENANT_ID: '11111111-1111-4111-8111-111111111111',
    API_CLIENT_ID: '22222222-2222-4222-8222-222222222222',
    SPA_CLIENT_ID: '44444444-4444-4444-8444-444444444444',
    GOVERNANCE_TABLE_ENDPOINT: 'https://examplegov.table.core.windows.net',
    ALLOWED_ORIGINS: 'http://reports.example.com'
  }), /exact HTTPS origins/);
  assert.throws(() => loadConfig({
    TENANT_ID: '11111111-1111-4111-8111-111111111111',
    API_CLIENT_ID: '22222222-2222-4222-8222-222222222222',
    SPA_CLIENT_ID: 'not-a-guid',
    GOVERNANCE_TABLE_ENDPOINT: 'https://examplegov.table.core.windows.net'
  }), /SPA_CLIENT_ID must be a GUID/);
});

test('BFF accepts tokens only from its configured SPA client application', () => {
  const allowedClientId = '44444444-4444-4444-8444-444444444444';
  assert.doesNotThrow(() => validateClientApplication({ azp: allowedClientId.toUpperCase() }, allowedClientId));
  assert.doesNotThrow(() => validateClientApplication({ appid: allowedClientId }, allowedClientId));
  for (const payload of [
    {}, { azp: 'attacker-client' }, { appid: 'attacker-client' },
    { azp: 'attacker-client', appid: allowedClientId }, { azp: 1 }
  ]) {
    assert.throws(
      () => validateClientApplication(payload, allowedClientId),
      (error: unknown) => error instanceof ApiError && error.status === 401 && error.code === 'invalid_client_application'
    );
  }
});

test('recovery owner is deterministic without retaining the secret', () => {
  const owner = recoveryOwnerKey('A'.repeat(43));
  assert.match(owner, /^recovery:[0-9a-f]{64}$/);
  assert.equal(owner, recoveryOwnerKey('A'.repeat(43)));
  assert.throws(
    () => recoveryOwnerKey('invalid'),
    (error: unknown) => error instanceof ApiError && error.status === 401
  );
});

test('settings validation rejects additional unsafe values through field validation', () => {
  assert.throws(() => validateSettings({
    staleThresholdDays: 90,
    reviewWindowDays: 90,
    pageSize: 50,
    defaultView: 'summary',
    groupByComputer: true,
    timeDisplay: 'local',
    csvFilenamePrefix: '../escape'
  }), /csvFilenamePrefix/);
});

test('settings validation preserves ordered table layouts and bounded widths', () => {
  const settings = validateSettings({
    staleThresholdDays: 90,
    reviewWindowDays: 90,
    pageSize: 50,
    defaultView: 'summary',
    groupByComputer: true,
    timeDisplay: 'local',
    csvFilenamePrefix: 'LocalAdmin',
    tableLayouts: {
      summary: [
        { key: 'SID', label: 'ignored client label', width: 360 },
        { key: 'ComputerName', width: 180 }
      ]
    }
  });
  assert.deepEqual(settings.tableLayouts?.summary, [
    { key: 'SID', width: 360 },
    { key: 'ComputerName', width: 180 }
  ]);
  assert.throws(() => validateSettings({
    ...settings,
    tableLayouts: { summary: [{ key: 'SID', width: 5000 }] }
  }), /between 90 and 800/);
});
