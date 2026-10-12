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
