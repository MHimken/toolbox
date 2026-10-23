import test from 'node:test';
import assert from 'node:assert/strict';
import { DirectoryLookupService } from '../src/directoryService.js';
import { ApiError } from '../src/errors.js';
import type { CallerIdentity } from '../src/identity.js';

const caller: CallerIdentity = {
  authenticationType: 'Entra', ownerKey: 'entra:tenant:user', roles: ['LocalAdmin.Governance.Read']
};
const credential = { getToken: async () => ({ token: 'test-token', expiresOnTimestamp: Date.now() + 60_000 }) };
const object = {
  id: '00112233-4455-6677-8899-aabbccddeeff', displayName: 'Example user',
  userPrincipalName: 'example@contoso.test', onPremisesSecurityIdentifier: 'S-1-5-21-1-2-3-1001'
};
const hasCode = (code: string) => (error: unknown) => error instanceof ApiError && error.code === code;

test('directory lookup rejects recovery callers, missing roles and malformed queries before calling Graph', async () => {
  let requests = 0;
  const service = new DirectoryLookupService(credential, async () => { requests++; return Response.json({ value: [] }); });
  await assert.rejects(() => service.lookup({ ...caller, authenticationType: 'Recovery' }, 'User', 'example'), hasCode('entra_identity_required'));
  await assert.rejects(() => service.lookup({ ...caller, roles: [] }, 'User', 'example'), hasCode('role_required'));
  for (const [type, query] of [['Device', 'example'], ['User', 'ab'], ['User', 'bad\nquery'], ['Group', 'x'.repeat(129)]]) {
    await assert.rejects(() => service.lookup(caller, type || '', query || ''), hasCode('invalid_identity_query'));
  }
  assert.equal(requests, 0);
});

test('directory search escapes filters, bounds results and returns separate Entra and AD SID choices', async () => {
  let url = '';
  const service = new DirectoryLookupService(credential, async input => {
    url = String(input);
    return Response.json({ value: [object], '@odata.nextLink': 'https://graph.microsoft.com/next' });
  });
  const result = await service.lookup(caller, 'User', "O'Brien");
  assert.equal(new URL(url).searchParams.get('$filter'), "(startsWith(userPrincipalName,'O''Brien') or startsWith(displayName,'O''Brien'))");
  assert.equal(new URL(url).searchParams.get('$top'), '20');
  assert.equal(result.truncated, true);
  assert.deepEqual(result.identities.map(item => [item.source, item.sid]), [
    ['Entra', 'S-1-12-1-1122867-1719092309-3148519816-4293844428'],
    ['AD', 'S-1-5-21-1-2-3-1001']
  ]);
  assert.equal(result.identities[0]?.userPrincipalName, object.userPrincipalName);
  assert.equal(result.identities[0]?.principalType, 'User');
});

test('directory lookup caches empty results, expires them, and rate-limits repeated requests', async () => {
  let now = 1_000_000;
  let requests = 0;
  const service = new DirectoryLookupService(credential, async () => { requests++; return Response.json({ value: [] }); }, () => now);
  await service.lookup(caller, 'Group', 'Unknown');
  await service.lookup(caller, 'Group', 'unknown');
  assert.equal(requests, 1);
  for (let index = 0; index < 8; index++) await service.lookup(caller, 'Group', 'unknown');
  await assert.rejects(() => service.lookup(caller, 'Group', 'unknown'), hasCode('directory_rate_limited'));
  now += 5 * 60_000 + 1;
  await service.lookup(caller, 'Group', 'unknown');
  assert.equal(requests, 2);
});

test('directory errors are explicit and are not cached as successful empty results', async () => {
  for (const [status, code] of [[403, 'directory_permissions_required'], [429, 'directory_rate_limited'], [500, 'directory_lookup_failed']] as const) {
    let requests = 0;
    const service = new DirectoryLookupService(credential, async () => {
      requests++;
      return Response.json({}, { status });
    });
    await assert.rejects(() => service.lookup(caller, 'User', 'example'), hasCode(code));
    await assert.rejects(() => service.lookup(caller, 'User', 'example'), hasCode(code));
    assert.equal(requests, 2);
  }
});

test('group name search only includes security groups and rejects malformed directory identities', async () => {
  const service = new DirectoryLookupService(credential, async input => {
    assert.match(new URL(String(input)).searchParams.get('$filter') || '', /^securityEnabled eq true and/);
    return Response.json({ value: [{ id: 'invalid-id' }] });
  });
  await assert.rejects(() => service.lookup(caller, 'Group', 'Helpdesk'), hasCode('invalid_directory_response'));
});

test('exact group object-ID lookup keeps the security-group restriction and caps even oversized Graph pages', async () => {
  const service = new DirectoryLookupService(credential, async input => {
    const query = new URL(String(input)).searchParams;
    assert.equal(query.get('$filter'), `securityEnabled eq true and (id eq '${object.id}')`);
    assert.equal(query.get('$select'), 'id,displayName,onPremisesSecurityIdentifier');
    return Response.json({ value: Array.from({ length: 21 }, () => object) });
  });
  const result = await service.lookup(caller, 'Group', object.id);
  assert.equal(result.identities.length, 40);
  assert.equal(result.truncated, true);
  assert.ok(result.identities.every(item => item.principalType === 'Group'));
});
