import test from 'node:test';
import assert from 'node:assert/strict';
import { ProfileApiError, ProfileClient } from '../profileClient.js';

function response(status, payload, headers = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: name => headers[name.toLowerCase()] || null },
    async json() { return payload; }
  };
}

test('profile client sends bearer authentication and create precondition', async () => {
  let request;
  const client = new ProfileClient('/localadmin-api/v1', async (url, options) => {
    request = { url, options };
    return response(201, { ownerKey: 'entra:tenant:user', settings: { pageSize: 50 } }, { etag: 'W/"1"' });
  });
  const result = await client.putProfile(
    { pageSize: 50 },
    { type: 'entra', getAccessToken: async () => 'token-value' }
  );
  assert.equal(request.url, '/localadmin-api/v1/profile');
  assert.equal(request.options.headers.Authorization, 'Bearer token-value');
  assert.equal(request.options.headers['x-correlation-id'], undefined);
  assert.equal(request.options.headers['If-None-Match'], '*');
  assert.equal(result.etag, 'W/"1"');
});

test('profile client treats a missing profile as an empty cloud profile', async () => {
  const client = new ProfileClient('https://api.example.test/v1/', async () =>
    response(404, {
      code: 'profile_not_found',
      message: 'The profile was not found.',
      correlationId: 'correlation'
    })
  );
  const result = await client.getProfile({ type: 'recovery', recoveryCode: 'A'.repeat(43) });
  assert.equal(result.profile, null);
  assert.equal(result.etag, '');
});

test('profile client preserves structured API failures', async () => {
  const client = new ProfileClient('/api/v1', async () =>
    response(412, {
      code: 'etag_conflict',
      message: 'Reload the profile.',
      correlationId: 'correlation'
    })
  );
  await assert.rejects(
    client.putProfile({}, { type: 'recovery', recoveryCode: 'A'.repeat(43) }, 'W/"old"'),
    error => error instanceof ProfileApiError &&
      error.status === 412 &&
      error.code === 'etag_conflict' &&
      error.correlationId === 'correlation'
  );
});

test('profile client binds browser fetch to the global object', async () => {
  let receiver;
  function browserFetch() {
    receiver = this;
    return Promise.resolve(response(404, {
      code: 'profile_not_found',
      message: 'The profile was not found.'
    }));
  }

  const client = new ProfileClient('https://api.example.test/v1', browserFetch);
  await client.getProfile({ type: 'entra', getAccessToken: async () => 'token-value' });
  assert.equal(receiver, globalThis);
});

test('cancelled identity searches pass their abort signal through the authenticated BFF client', async () => {
  const controller = new AbortController();
  const client = new ProfileClient('/v1', async (url, options) => {
    assert.equal(options.signal, controller.signal);
    options.signal.throwIfAborted();
    return response(200, { identities: [] });
  });
  controller.abort();
  await assert.rejects(
    client.request('GET', '/identities/lookup?type=User&q=example',
      { type: 'entra', getAccessToken: async () => 'token-value' }, { signal: controller.signal }),
    error => error.name === 'AbortError'
  );
});
