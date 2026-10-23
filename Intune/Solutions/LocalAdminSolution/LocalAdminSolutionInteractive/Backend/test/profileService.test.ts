import test from 'node:test';
import assert from 'node:assert/strict';
import { ApiError } from '../src/errors.js';
import { recoveryOwnerKey, type CallerIdentity } from '../src/identity.js';
import type { ProfileSettings } from '../src/models.js';
import { ActionService } from '../src/actionService.js';
import { ProfileService } from '../src/profileService.js';
import { loadConfig } from '../src/config.js';
import { MemoryRepository } from './memoryRepository.js';

const settings: ProfileSettings = {
  staleThresholdDays: 90,
  reviewWindowDays: 60,
  pageSize: 50,
  defaultView: 'review',
  groupByComputer: true,
  timeDisplay: 'utc',
  csvFilenamePrefix: 'LocalAdmin'
};

const config = loadConfig({
  TENANT_ID: '11111111-1111-4111-8111-111111111111',
  API_CLIENT_ID: '33333333-3333-4333-8333-333333333333',
  SPA_CLIENT_ID: '44444444-4444-4444-8444-444444444444',
  GOVERNANCE_TABLE_ENDPOINT: 'https://example.table.core.windows.net'
});

const entraIdentity: CallerIdentity = {
  authenticationType: 'Entra',
  ownerKey: 'entra:11111111-1111-4111-8111-111111111111:22222222-2222-4222-8222-222222222222',
  tenantId: '11111111-1111-4111-8111-111111111111',
  objectId: '22222222-2222-4222-8222-222222222222',
  roles: []
};

test('profile ownership is derived and isolated by owner key', async () => {
  const repository = new MemoryRepository();
  const service = new ProfileService(repository, () => new Date('2026-10-01T12:00:00.000Z'));
  const created = await service.put(entraIdentity, settings, undefined, true, 'correlation-1');
  assert.equal(created.ownerKey, entraIdentity.ownerKey);
  assert.equal(repository.audits[0]?.operation, 'ProfileCreated');
  await assert.rejects(
    () => service.get({ ...entraIdentity, ownerKey: 'entra:11111111-1111-4111-8111-111111111111:33333333-3333-4333-8333-333333333333' }),
    (error: unknown) => error instanceof ApiError && error.status === 404
  );
});

test('profile updates require the current ETag', async () => {
  const repository = new MemoryRepository();
  const service = new ProfileService(repository);
  const created = await service.put(entraIdentity, settings, undefined, true, 'correlation-1');
  await assert.rejects(
    () => service.put(entraIdentity, settings, '"stale"', false, 'correlation-2'),
    (error: unknown) => error instanceof ApiError && error.code === 'etag_conflict'
  );
  const updated = await service.put(entraIdentity, { ...settings, pageSize: 100 }, created.etag, false, 'correlation-3');
  assert.equal(updated.settings.pageSize, 100);
});

test('recovery rotation invalidates the old owner and preserves settings', async () => {
  const repository = new MemoryRepository();
  const service = new ProfileService(repository);
  const oldCode = 'A'.repeat(43);
  const newCode = 'B'.repeat(43);
  const identity: CallerIdentity = {
    authenticationType: 'Recovery',
    ownerKey: recoveryOwnerKey(oldCode),
    roles: []
  };
  const created = await service.put(identity, settings, undefined, true, 'correlation-1');
  const rotated = await service.rotateRecovery(identity, newCode, created.etag, 'correlation-2');
  assert.equal(rotated.ownerKey, recoveryOwnerKey(newCode));
  assert.equal(rotated.settings, settings);
  assert.equal(await repository.getProfile(identity.ownerKey), null);
  assert.equal(repository.audits.at(-1)?.operation, 'RecoveryRotated');
});

test('recovery revocation deletes the owner profile', async () => {
  const repository = new MemoryRepository();
  const service = new ProfileService(repository);
  const code = 'C'.repeat(43);
  const identity: CallerIdentity = {
    authenticationType: 'Recovery',
    ownerKey: recoveryOwnerKey(code),
    roles: []
  };
  const created = await service.put(identity, settings, undefined, true, 'correlation-1');
  await service.revokeRecovery(identity, created.etag, 'correlation-2');
  assert.equal(await repository.getProfile(identity.ownerKey), null);
  assert.equal(repository.audits.at(-1)?.operation, 'RecoveryRevoked');
});

test('audit failures explicitly report that the mutation committed', async () => {
  const repository = new MemoryRepository();
  repository.failAudit = true;
  const service = new ProfileService(repository);
  await assert.rejects(
    () => service.put(entraIdentity, settings, undefined, true, 'correlation-1'),
    (error: unknown) =>
      error instanceof ApiError &&
      error.code === 'audit_write_failed' &&
      (error.details as { mutationCommitted?: boolean }).mutationCommitted === true
  );
  assert.ok(await repository.getProfile(entraIdentity.ownerKey));
});

test('governance exception requests are Entra-owned, audited, and idempotent', async () => {
  const repository = new MemoryRepository();
  const service = new ActionService(repository, config, () => new Date('2026-10-11T20:00:00.000Z'));
  const payload = {
    computerSid: 's-1-5-21-10-20-30-1001',
    principalSid: 's-1-5-21-40-50-60-2001',
    justification: 'Required for approved maintenance window.',
    ticketReference: 'CHG-1234'
  };
  const { action: first, replay: firstReplay } = await service.requestGovernanceException(
    entraIdentity,
    payload,
    '00000000-0000-4000-8000-000000000001',
    'correlation-1'
  );
  const { action: replay, replay: secondReplay } = await service.requestGovernanceException(
    entraIdentity,
    payload,
    '00000000-0000-4000-8000-000000000001',
    'correlation-2'
  );

  assert.equal(first.actionId, replay.actionId);
  assert.equal(firstReplay, false);
  assert.equal(secondReplay, true);
  assert.equal(first.status, 'Requested');
  assert.equal(first.actionType, 'RequestGovernanceException');
  assert.equal(first.targetComputerSid, 'S-1-5-21-10-20-30-1001');
  assert.equal(first.targetPrincipalId, 'S-1-5-21-40-50-60-2001');
  assert.equal(repository.actions.size, 1);
  assert.equal(repository.audits.length, 1);
  assert.equal(repository.audits[0]?.operation, 'GovernanceExceptionRequested');
});

test('governance exception requests reject recovery identity, malformed targets, and changed idempotent retries', async () => {
  const repository = new MemoryRepository();
  const service = new ActionService(repository, config);
  const payload = {
    computerSid: 'S-1-5-21-10-20-30-1001',
    principalSid: 'S-1-5-21-40-50-60-2001',
    justification: 'Required for approved maintenance window.'
  };
  const idempotencyKey = '00000000-0000-4000-8000-000000000002';

  await assert.rejects(
    () => service.requestGovernanceException(
      { authenticationType: 'Recovery', ownerKey: recoveryOwnerKey('A'.repeat(43)), roles: [] },
      payload,
      idempotencyKey,
      'correlation-1'
    ),
    (error: unknown) => error instanceof ApiError && error.code === 'entra_identity_required'
  );
  await assert.rejects(
    () => service.requestGovernanceException(entraIdentity, { ...payload, computerSid: 'not-a-sid' }, idempotencyKey, 'correlation-1'),
    (error: unknown) => error instanceof ApiError && error.code === 'invalid_request'
  );

  await service.requestGovernanceException(entraIdentity, payload, idempotencyKey, 'correlation-1');
  await assert.rejects(
    () => service.requestGovernanceException(
      entraIdentity,
      { ...payload, justification: 'Different valid justification.' },
      idempotencyKey,
      'correlation-2'
    ),
    (error: unknown) => error instanceof ApiError && error.code === 'idempotency_conflict'
  );
});

test('governance exception audit failure reports that the request was recorded', async () => {
  const repository = new MemoryRepository();
  repository.failAudit = true;
  const service = new ActionService(repository, config);
  const payload = {
    computerSid: 'S-1-5-21-10-20-30-1001',
    principalSid: 'S-1-5-21-40-50-60-2001',
    justification: 'Required for approved maintenance window.'
  };
  const idempotencyKey = '00000000-0000-4000-8000-000000000003';
  await assert.rejects(
    () => service.requestGovernanceException(
      entraIdentity,
      payload,
      idempotencyKey,
      'correlation-1'
    ),
    (error: unknown) =>
      error instanceof ApiError &&
      error.code === 'audit_write_failed' &&
      (error.details as { mutationCommitted?: boolean }).mutationCommitted === true
  );
  assert.equal(repository.actions.size, 1);
  repository.failAudit = false;
  await service.requestGovernanceException(entraIdentity, payload, idempotencyKey, 'correlation-2');
  assert.equal(repository.audits.length, 1);
});
