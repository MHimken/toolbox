import test from 'node:test';
import assert from 'node:assert/strict';
import { AppRoles, requireAdminMode } from '../src/adminMode.js';
import { ActionService } from '../src/actionService.js';
import { AdminSessionService } from '../src/adminSessionService.js';
import { loadConfig } from '../src/config.js';
import { ApiError } from '../src/errors.js';
import type { CallerIdentity } from '../src/identity.js';
import { RuleService } from '../src/ruleService.js';
import { MemoryRepository } from './memoryRepository.js';

const tenantId = '11111111-1111-4111-8111-111111111111';
const config = loadConfig({
  TENANT_ID: tenantId,
  API_CLIENT_ID: '33333333-3333-4333-8333-333333333333',
  GOVERNANCE_TABLE_ENDPOINT: 'https://example.table.core.windows.net',
  ADMIN_AUTH_CONTEXT_ID: 'c1',
  ADMIN_SESSION_MAX_MINUTES: '30'
});
const now = new Date('2026-10-12T10:00:00.000Z');
const clock = () => now;
const nowSeconds = Math.floor(now.getTime() / 1000);

function identity(objectSuffix: string, roles: string[], claims: Record<string, unknown> = {}): CallerIdentity {
  const objectId = `22222222-2222-4222-8222-${objectSuffix.padStart(12, '0')}`;
  return {
    authenticationType: 'Entra',
    ownerKey: `entra:${tenantId}:${objectId}`,
    tenantId,
    objectId,
    roles,
    claims: { iat: nowSeconds - 60, exp: nowSeconds + 3600, uti: `uti-${objectSuffix}`, preferred_username: `${objectSuffix}@contoso.test`, ...claims }
  };
}

const adminClaims = { acrs: ['c1'] };
const proposer = identity('1', [AppRoles.GovernanceRead]);
const approver = identity('2', [AppRoles.GovernanceApprove], adminClaims);
const soloAdmin = identity('3', [AppRoles.GovernanceApprove, AppRoles.GovernanceSelfApprove], adminClaims);
const proposal = {
  effect: 'Allow',
  principalType: 'Group',
  principalSid: 's-1-5-21-1-2-3-1001',
  principalSource: 'AD',
  membershipScope: 'Any',
  deviceScopeType: 'ComputerPrefix',
  deviceScopeValue: 'BER-',
  allowedEntraJoined: true,
  allowedHybridJoined: true,
  allowedDomainJoined: false,
  validUntilUtc: '2027-04-01T00:00:00.000Z',
  reason: 'Helpdesk tier 2 needs local administration on Berlin devices.',
  ticketReference: 'CHG-1001'
};

function apiError(code: string, status?: number) {
  return (error: unknown) => error instanceof ApiError && error.code === code && (status === undefined || error.status === status);
}

test('configuration validates the authentication context and Admin-mode lifetime', () => {
  const base = {
    TENANT_ID: tenantId,
    API_CLIENT_ID: '33333333-3333-4333-8333-333333333333',
    GOVERNANCE_TABLE_ENDPOINT: 'https://example.table.core.windows.net'
  };
  assert.equal(loadConfig(base).adminAuthContextId, 'c1');
  assert.equal(loadConfig(base).adminSessionMaxMinutes, 30);
  assert.throws(() => loadConfig({ ...base, ADMIN_AUTH_CONTEXT_ID: 'c100' }));
  assert.throws(() => loadConfig({ ...base, ADMIN_SESSION_MAX_MINUTES: '2' }));
});

test('Admin mode requires a role, the authentication context, and a recent token', () => {
  assert.throws(() => requireAdminMode(identity('9', [], adminClaims), config, now), apiError('role_required', 403));
  assert.throws(() => requireAdminMode(identity('9', [AppRoles.GovernanceRead], adminClaims), config, now), apiError('role_required', 403));
  assert.throws(
    () => requireAdminMode({ authenticationType: 'Recovery', ownerKey: 'recovery:x', roles: [] }, config, now),
    apiError('entra_identity_required', 403)
  );

  let challenge: ApiError | undefined;
  try {
    requireAdminMode(identity('9', [AppRoles.GovernanceApprove]), config, now);
  } catch (error) {
    challenge = error as ApiError;
  }
  assert.equal(challenge?.status, 401);
  assert.equal(challenge?.code, 'admin_auth_context_required');
  assert.deepEqual(JSON.parse((challenge?.details as { claims: string }).claims), {
    access_token: { acrs: { essential: true, value: 'c1' } }
  });
  assert.match(challenge?.headers?.['WWW-Authenticate'] || '', /error="insufficient_claims", .*claims="[A-Za-z0-9+/=]+"/);

  assert.throws(
    () => requireAdminMode(identity('9', [AppRoles.GovernanceApprove], { acrs: ['c1'], iat: nowSeconds - 31 * 60 }), config, now),
    apiError('admin_session_expired', 401)
  );

  const session = requireAdminMode(identity('9', [AppRoles.GovernanceApprove, AppRoles.ActionsOperate], { acrs: ['c2', 'c1'] }), config, now);
  assert.equal(session.authContextId, 'c1');
  assert.equal(session.expiresAtUtc, new Date((nowSeconds - 60) * 1000 + 30 * 60_000).toISOString());
  assert.deepEqual(session.capabilities, { readGovernance: true, approveRules: true, selfApprove: false, operateActions: true });
  assert.match(session.sessionId, /^[0-9a-f]{32}$/);
});

test('entering Admin mode is audited once per token', async () => {
  const repository = new MemoryRepository();
  const service = new AdminSessionService(repository, config, clock);
  const first = await service.enter(approver, 'correlation-1');
  const second = await service.enter(approver, 'correlation-2');
  assert.equal(first.sessionId, second.sessionId);
  assert.equal(repository.audits.filter(audit => audit.operation === 'AdminModeEntered').length, 1);
  assert.equal(repository.audits[0]?.authContextId, 'c1');
  await service.exit(approver, 'correlation-3', 'idle');
  assert.equal(repository.audits.at(-1)?.operation, 'AdminModeExited');
  assert.equal(JSON.parse(repository.audits.at(-1)?.detailsJson || '{}').reason, 'idle');
});

test('governance proposals require a role, are idempotent, and start pending approval', async () => {
  const repository = new MemoryRepository();
  const service = new RuleService(repository, config, clock);
  const key = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

  await assert.rejects(() => service.propose(identity('8', []), proposal, key, 'c-1'), apiError('role_required', 403));
  await assert.rejects(() => service.propose(proposer, { ...proposal, principalSid: 'DOMAIN\\Helpdesk' }, key, 'c-1'), apiError('invalid_request', 400));
  await assert.rejects(() => service.propose(proposer, { ...proposal, allowedEntraJoined: false, allowedHybridJoined: false }, key, 'c-1'), apiError('invalid_request', 400));
  await assert.rejects(() => service.propose(proposer, { ...proposal, validUntilUtc: '2026-01-01T00:00:00Z' }, key, 'c-1'), apiError('invalid_request', 400));
  await assert.rejects(() => service.propose(proposer, { ...proposal, deviceScopeValue: 'BER-*' }, key, 'c-1'), apiError('invalid_request', 400));

  const created = await service.propose(proposer, proposal, key, 'c-1');
  assert.equal(created.replay, false);
  assert.equal(created.rule.PartitionKey, 'org');
  assert.equal(created.rule.RowKey, key);
  assert.equal(created.rule.Status, 'PendingApproval');
  assert.equal(created.rule.PrincipalValue, 'S-1-5-21-1-2-3-1001');
  assert.equal(created.rule.CreatedByOwnerKey, proposer.ownerKey);
  assert.equal(created.rule.CreatedBy, '1@contoso.test');

  const replay = await service.propose(proposer, proposal, key, 'c-2');
  assert.equal(replay.replay, true);
  assert.equal(replay.rule.ETag, created.rule.ETag);
  assert.equal(repository.audits.filter(audit => audit.operation === 'GovernanceRuleProposed').length, 1);
  await assert.rejects(() => service.propose(proposer, { ...proposal, effect: 'Deny' }, key, 'c-3'), apiError('idempotency_conflict', 409));
  await assert.rejects(() => service.propose(identity('7', [AppRoles.GovernanceRead]), proposal, key, 'c-3'), apiError('idempotency_conflict', 409));

  await assert.rejects(() => service.list(identity('8', []), 'governance'), apiError('role_required', 403));
  assert.equal((await service.list(proposer, 'governance')).rules.length, 1);
  assert.equal((await service.list(identity('8', []), 'mine')).rules.length, 0);
});

test('approval enforces Admin mode, ETags, transitions, and the four-eyes principle', async () => {
  const repository = new MemoryRepository();
  const service = new RuleService(repository, config, clock);
  const ownKey = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const { rule } = await service.propose(soloAdmin, proposal, ownKey, 'c-1');
  const etag = rule.ETag || '';

  await assert.rejects(
    () => service.transition({ ...approver, claims: { ...approver.claims, acrs: [] } }, ownKey, 'approve', {}, etag, 'c-2'),
    apiError('admin_auth_context_required', 401)
  );
  await assert.rejects(() => service.transition(proposer, ownKey, 'approve', {}, etag, 'c-2'), apiError('role_required', 403));
  await assert.rejects(() => service.transition(approver, ownKey, 'approve', {}, undefined, 'c-2'), apiError('etag_required', 428));
  await assert.rejects(() => service.transition(approver, ownKey, 'approve', {}, '*', 'c-2'), apiError('invalid_precondition', 400));
  await assert.rejects(() => service.transition(approver, ownKey, 'approve', {}, 'W/"stale"', 'c-2'), apiError('etag_conflict', 412));
  await assert.rejects(() => service.transition(approver, ownKey, 'reject', { reason: 'short' }, etag, 'c-2'), apiError('invalid_request', 400));

  const selfApproved = await service.transition(soloAdmin, ownKey, 'approve', { reason: 'Small tenant, documented in CHG-1001.' }, etag, 'c-3');
  assert.equal(selfApproved.Status, 'Active');
  assert.equal(selfApproved.SelfApproved, true);
  assert.equal(selfApproved.ApprovedByOwnerKey, soloAdmin.ownerKey);
  const approvalAudit = repository.audits.at(-1);
  assert.equal(approvalAudit?.operation, 'GovernanceRuleApproved');
  assert.equal(approvalAudit?.authContextId, 'c1');
  assert.match(approvalAudit?.previousState || '', /^PendingApproval:[0-9a-f]{64}$/);
  assert.equal(JSON.parse(approvalAudit?.detailsJson || '{}').selfApproved, true);

  await assert.rejects(
    () => service.transition(approver, ownKey, 'approve', {}, selfApproved.ETag, 'c-4'),
    apiError('invalid_transition', 409)
  );
  const revoked = await service.transition(approver, ownKey, 'revoke', { reason: 'Access no longer required by helpdesk.' }, selfApproved.ETag, 'c-5');
  assert.equal(revoked.Status, 'Revoked');
  assert.equal(revoked.RevocationReason, 'Access no longer required by helpdesk.');

  const fourEyesKey = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const proposedByApprover = await service.propose(approver, proposal, fourEyesKey, 'c-6');
  await assert.rejects(
    () => service.transition(approver, fourEyesKey, 'approve', {}, proposedByApprover.rule.ETag, 'c-7'),
    apiError('four_eyes_required', 403)
  );
  const approvedByOther = await service.transition(soloAdmin, fourEyesKey, 'approve', {}, proposedByApprover.rule.ETag, 'c-8');
  assert.equal(approvedByOther.Status, 'Active');
  assert.equal(approvedByOther.SelfApproved, false);

  await assert.rejects(
    () => service.transition(approver, 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', 'approve', {}, 'W/"1"', 'c-9'),
    apiError('rule_not_found', 404)
  );
});

test('action owners can cancel their own requests; operators need Admin mode for others', async () => {
  const repository = new MemoryRepository();
  const service = new ActionService(repository, config, clock);
  const requester = identity('5', []);
  const { action } = await service.requestGovernanceException(requester, {
    computerSid: 'S-1-5-21-10-20-30-1001',
    principalSid: 'S-1-5-21-40-50-60-2001',
    justification: 'Required for approved maintenance window.'
  }, 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'c-1');
  assert.ok(action.etag);

  assert.equal((await service.list(requester, 'mine')).actions.length, 1);
  await assert.rejects(() => service.list(requester, 'all'), apiError('role_required', 403));
  assert.equal((await service.list(proposer, 'all')).actions.length, 1);

  const operatorWithoutContext = identity('6', [AppRoles.ActionsOperate]);
  await assert.rejects(
    () => service.cancel(operatorWithoutContext, action.actionId, { ownerKey: requester.ownerKey, reason: 'Duplicate of an approved rule.' }, action.etag, 'c-2'),
    apiError('admin_auth_context_required', 401)
  );
  await assert.rejects(
    () => service.cancel(identity('6', [], adminClaims), action.actionId, { ownerKey: requester.ownerKey, reason: 'Duplicate of an approved rule.' }, action.etag, 'c-2'),
    apiError('role_required', 403)
  );

  const operator = identity('6', [AppRoles.ActionsOperate], adminClaims);
  const cancelled = await service.cancel(operator, action.actionId, { ownerKey: requester.ownerKey, reason: 'Duplicate of an approved rule.' }, action.etag, 'c-3');
  assert.equal(cancelled.status, 'Cancelled');
  assert.equal(repository.audits.at(-1)?.operation, 'ReviewActionCancelledByOperator');
  assert.ok(repository.audits.at(-1)?.adminSessionId);
  await assert.rejects(
    () => service.cancel(requester, action.actionId, { reason: 'No longer needed by requester.' }, cancelled.etag, 'c-4'),
    apiError('invalid_transition', 409)
  );
  await assert.rejects(
    () => service.cancel(requester, 'missing', { reason: 'No longer needed by requester.' }, 'W/"1"', 'c-5'),
    apiError('action_not_found', 404)
  );
});
