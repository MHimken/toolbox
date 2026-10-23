import test from 'node:test';
import assert from 'node:assert/strict';
import { EntraAuthClient, hasCompleteEntraConfig } from '../auth.js';

const config = {
  entraTenantId: '11111111-1111-4111-8111-111111111111',
  spaClientId: '22222222-2222-4222-8222-222222222222',
  apiScope: 'api://33333333-3333-4333-8333-333333333333/access_as_user',
  redirectUri: 'https://report.example.test/index.html'
};

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((accept, fail) => { resolve = accept; reject = fail; });
  return { promise, resolve, reject };
}

function popupHarness(account = null) {
  const attempts = [];
  const changes = [];
  class InteractionRequiredAuthError extends Error {}
  class PublicClientApplication {
    getActiveAccount() { return account; }
    setActiveAccount(value) { account = value; }
    loginPopup(request) {
      const attempt = { request, ...deferred() };
      attempts.push(attempt);
      return attempt.promise;
    }
    acquireTokenPopup(request) { return this.loginPopup(request); }
    async acquireTokenSilent() { throw new InteractionRequiredAuthError(); }
  }
  const client = new EntraAuthClient(config, { PublicClientApplication, InteractionRequiredAuthError }, {
    onPopupChange: pending => changes.push(pending)
  });
  return { client, attempts, changes };
}

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

test('sign-out returns the popup to the redirect bridge without navigating the report', async () => {
  let account = { homeAccountId: 'home-1', username: 'admin@example.test' };
  const signedInAccount = account;
  const completion = deferred();
  let logoutRequest;
  class PublicClientApplication {
    getActiveAccount() { return account; }
    setActiveAccount(value) { account = value; }
    logoutPopup(request) {
      logoutRequest = request;
      return completion.promise;
    }
  }
  const client = new EntraAuthClient(config, { PublicClientApplication });
  const signOut = client.signOut();
  assert.deepEqual(logoutRequest, {
    account: signedInAccount,
    postLogoutRedirectUri: config.redirectUri
  });
  completion.resolve();
  await signOut;
  assert.equal(client.getAccount(), null);
});

test('sign-out surfaces popup failures and skips the popup when no account is active', async () => {
  let account = { username: 'admin@example.test' };
  const failure = new Error('Popup could not be opened.');
  let calls = 0;
  class PublicClientApplication {
    getActiveAccount() { return account; }
    setActiveAccount(value) { account = value; }
    async logoutPopup() {
      calls += 1;
      throw failure;
    }
  }
  const client = new EntraAuthClient(config, { PublicClientApplication });
  await assert.rejects(client.signOut(), error => error === failure);
  account = null;
  await client.signOut();
  assert.equal(calls, 1);
  assert.equal(client.getAccount(), null);
});

test('explicit popup retry supersedes cancellation without rejecting the original sign-in', async () => {
  const { client, attempts, changes } = popupHarness();
  const signIn = client.signIn();
  assert.equal(client.popupPending, true);
  assert.equal(attempts[0].request.overrideInteractionInProgress, undefined);
  await assert.rejects(() => client.signIn(), /already pending/);
  assert.equal(attempts.length, 1);

  client.retryPopup();
  assert.equal(attempts[1].request.overrideInteractionInProgress, true);
  attempts[0].reject(Object.assign(new Error('Superseded'), { errorCode: 'interaction_in_progress_cancelled' }));
  await Promise.resolve();
  assert.equal(client.popupPending, true);
  assert.deepEqual(changes, [true]);

  const account = { username: 'retry@example.test' };
  attempts[1].resolve({ account });
  assert.equal(await signIn, account);
  assert.equal(client.getAccount(), account);
  assert.equal(client.popupPending, false);
  assert.deepEqual(changes, [true, false]);
});

test('late success from an abandoned popup cannot sign in the old account', async () => {
  const { client, attempts } = popupHarness();
  const signIn = client.signIn();
  client.retryPopup();
  attempts[0].resolve({ account: { username: 'abandoned@example.test' } });
  await Promise.resolve();
  assert.equal(client.getAccount(), null);
  assert.equal(client.popupPending, true);
  const account = { username: 'chosen@example.test' };
  attempts[1].resolve({ account });
  assert.equal(await signIn, account);
  assert.equal(client.getAccount(), account);
});

test('popup timeout is explicit and permits a fresh sign-in without an override', async () => {
  const { client, attempts, changes } = popupHarness();
  const signIn = client.signIn();
  const timeout = Object.assign(new Error('timed_out'), { errorCode: 'timed_out' });
  const failure = assert.rejects(signIn, error => {
    assert.match(error.message, /closed or timed out/);
    assert.equal(error.cause, timeout);
    return true;
  });
  attempts[0].reject(timeout);
  await failure;
  assert.equal(client.getAccount(), null);
  assert.equal(client.popupPending, false);
  assert.deepEqual(changes, [true, false]);
  const next = client.signIn();
  assert.equal(attempts[1].request.overrideInteractionInProgress, undefined);
  attempts[1].resolve({ account: { username: 'next@example.test' } });
  await next;
  assert.throws(() => client.retryPopup(), /no Microsoft Entra popup/);
});

test('Admin step-up retry preserves the account, scopes and claims challenge', async () => {
  const account = { homeAccountId: 'home-1', username: 'admin@example.test' };
  const { client, attempts } = popupHarness(account);
  const claims = '{"access_token":{"acrs":{"essential":true,"value":"c2"}}}';
  const token = client.getClaimsChallengeToken(claims);
  client.retryPopup();
  assert.deepEqual(attempts[1].request, {
    ...attempts[0].request,
    overrideInteractionInProgress: true
  });
  assert.equal(attempts[1].request.claims, claims);
  assert.equal(attempts[1].request.account, account);
  attempts[0].reject(new Error('Superseded'));
  attempts[1].resolve({ accessToken: 'stepped-up', account });
  assert.equal(await token, 'stepped-up');
  assert.equal(client.getAccount(), account);
});

test('interactive token fallback can be retried without repeating the silent request', async () => {
  const { client, attempts } = popupHarness({ username: 'admin@example.test' });
  const token = client.getAccessToken();
  await Promise.resolve();
  client.retryPopup();
  assert.equal(attempts.length, 2);
  attempts[0].reject(new Error('Superseded'));
  attempts[1].resolve({ accessToken: 'profile-token' });
  assert.equal(await token, 'profile-token');
});

test('failed step-up retains the report account and surfaces cancellation or consent errors', async () => {
  for (const errorCode of ['user_cancelled', 'access_denied']) {
    const account = { homeAccountId: 'home-1', username: 'admin@example.test' };
    const { client, attempts } = popupHarness(account);
    const token = client.getClaimsChallengeToken('{"access_token":{}}');
    const error = Object.assign(new Error('Consent was denied.'), { errorCode });
    const failure = assert.rejects(token, failure => {
      if (errorCode === 'user_cancelled') {
        assert.match(failure.message, /cancelled/);
        assert.equal(failure.cause, error);
      } else {
        assert.equal(failure, error);
      }
      return true;
    });
    attempts[0].reject(error);
    await failure;
    assert.equal(client.getAccount(), account);
    assert.equal(client.popupPending, false);
  }
});
