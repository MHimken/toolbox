import test from 'node:test';
import assert from 'node:assert/strict';
import { EntraAuthClient, hasCompleteEntraConfig } from '../auth.js';

const config = {
  entraTenantId: '11111111-1111-4111-8111-111111111111',
  spaClientId: '22222222-2222-4222-8222-222222222222',
  apiScope: 'api://33333333-3333-4333-8333-333333333333/access_as_user',
  redirectUri: 'https://report.example.test/index.html'
};

test('Entra configuration requires every public identifier', () => {
  assert.equal(hasCompleteEntraConfig(config), true);
  assert.equal(hasCompleteEntraConfig({ ...config, apiScope: '' }), false);
});

test('Entra client uses memory storage and acquires scoped tokens', async () => {
  let capturedConfig;
  let activeAccount = null;
  class InteractionRequiredAuthError extends Error {}
  class PublicClientApplication {
    constructor(value) { capturedConfig = value; }
    async initialize() {}
    getActiveAccount() { return activeAccount; }
    setActiveAccount(value) { activeAccount = value; }
    async loginPopup(request) {
      assert.deepEqual(request.scopes, [config.apiScope]);
      return { account: { username: 'admin@example.test' } };
    }
    async acquireTokenSilent(request) {
      assert.equal(request.account, activeAccount);
      return { accessToken: 'access-token' };
    }
  }
  const client = new EntraAuthClient(config, { PublicClientApplication, InteractionRequiredAuthError });
  await client.initialize();
  await client.signIn();
  assert.equal(await client.getAccessToken(), 'access-token');
  assert.equal(capturedConfig.cache.cacheLocation, 'memoryStorage');
  assert.equal(capturedConfig.auth.authority, `https://login.microsoftonline.com/${config.entraTenantId}`);
  assert.equal(capturedConfig.auth.redirectUri, config.redirectUri);
  assert.deepEqual(capturedConfig.auth.clientCapabilities, ['CP1']);
});

test('Entra client answers Conditional Access claims challenges for the signed-in account', async () => {
  const account = { homeAccountId: 'home-1', username: 'admin@example.test' };
  let popupRequest;
  let popupAccount = account;
  class PublicClientApplication {
    async initialize() {}
    getActiveAccount() { return account; }
    async acquireTokenPopup(request) {
      popupRequest = request;
      return { accessToken: 'admin-token', account: popupAccount };
    }
  }
  const client = new EntraAuthClient(config, { PublicClientApplication, InteractionRequiredAuthError: Error });
  const claims = '{"access_token":{"acrs":{"essential":true,"value":"c1"}}}';
  assert.equal(await client.getClaimsChallengeToken(claims), 'admin-token');
  assert.equal(popupRequest.claims, claims);
  assert.equal(popupRequest.account, account);
  assert.deepEqual(popupRequest.scopes, [config.apiScope]);
  popupAccount = { homeAccountId: 'home-2' };
  await assert.rejects(() => client.getClaimsChallengeToken(claims), /already signed in/);
  await assert.rejects(() => client.getClaimsChallengeToken(''), /claims challenge/);
});
