import test from 'node:test';
import assert from 'node:assert/strict';
import { bootstrapBrowser, isAuthenticationResponse } from '../bootstrap.js';

test('authorization responses do not start the report application', () => {
  assert.equal(isAuthenticationResponse(
    { search: '', hash: '#code=authorization-code&state=request-state' }
  ), true);
  assert.equal(isAuthenticationResponse(
    { search: '?error=access_denied&error_description=cancelled', hash: '' }
  ), true);
});

test('normal report navigation starts the report application', () => {
  assert.equal(isAuthenticationResponse(
    { search: '', hash: '' }
  ), false);
  assert.equal(isAuthenticationResponse(
    { search: '', hash: '#governance' }
  ), false);
});

test('authorization responses are relayed through the MSAL redirect bridge', async () => {
  let relayed = false;
  await bootstrapBrowser(
    { search: '', hash: '#code=authorization-code&state=request-state' },
    { async broadcastResponseToMainFrame() { relayed = true; } }
  );
  assert.equal(relayed, true);
});

test('state-only sign-out callbacks are relayed instead of starting another report', async () => {
  for (const location of [
    { search: '?state=logout-request-state', hash: '' },
    { search: '', hash: '#state=logout-request-state' }
  ]) {
    assert.equal(isAuthenticationResponse(location), true);
    let relayed = false;
    await bootstrapBrowser(location, {
      async broadcastResponseToMainFrame() { relayed = true; }
    });
    assert.equal(relayed, true);
  }
});

test('sign-out callback reports a missing redirect bridge', async () => {
  await assert.rejects(
    bootstrapBrowser({ search: '?state=logout-request-state', hash: '' }, {}),
    /redirect bridge could not be loaded/
  );
});
