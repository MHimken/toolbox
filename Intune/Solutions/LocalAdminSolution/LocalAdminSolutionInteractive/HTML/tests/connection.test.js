import test from 'node:test';
import assert from 'node:assert/strict';
import { loadRuntimeConfig, runtimeConfigDefaults } from '../connection.js';

function response(payload, ok = true) {
  return {
    ok,
    async json() {
      return payload;
    }
  };
}

test('runtime configuration accepts only public validated defaults', async () => {
  const config = await loadRuntimeConfig(async () => response({
    version: 1,
    defaults: {
      storageAccountName: 'Inventory123',
      governanceStorageAccountName: 'governance123',
      bffBaseUrl: '/localadmin-api/v1/',
      entraTenantId: '11111111-1111-4111-8111-111111111111',
      spaClientId: '22222222-2222-4222-8222-222222222222',
      apiScope: 'api://33333333-3333-4333-8333-333333333333/access_as_user',
      redirectUri: 'https://report.example.test/index.html',
      defaultView: 'review',
      lockStorageAccountName: true
    }
  }));
  assert.equal(config.storageAccountName, 'inventory123');
  assert.equal(config.bffBaseUrl, '/localadmin-api/v1');
  assert.equal(config.redirectUri, 'https://report.example.test/index.html');
  assert.equal(config.defaultView, 'review');
  assert.equal(config.lockStorageAccountName, true);
});

test('runtime configuration rejects malformed values without failing the report', async () => {
  const config = await loadRuntimeConfig(async () => response({
    version: 1,
    defaults: {
      storageAccountName: '../secret',
      governanceStorageAccountName: 'UPPER_CASE',
      bffBaseUrl: 'javascript:alert(1)',
      entraTenantId: 'not-a-guid',
      spaClientId: 'also-not-a-guid',
      apiScope: 'https://wrong.example/scope',
      redirectUri: 'javascript:alert(1)',
      defaultView: 'admin'
    }
  }));
  assert.deepEqual(config, runtimeConfigDefaults);
});

test('runtime configuration falls back when unavailable or embedded', async () => {
  assert.deepEqual(await loadRuntimeConfig(async () => response(null, false)), runtimeConfigDefaults);
  assert.deepEqual(await loadRuntimeConfig(() => { throw new Error('should not fetch'); }, true), runtimeConfigDefaults);
});
