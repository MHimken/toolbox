import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AdminClient,
  AdminModeController,
  previewMatches,
  proposalFromReviewRow,
  validateProposalDraft
} from '../adminMode.js';
import { ProfileApiError, ProfileClient } from '../profileClient.js';

function response(status, payload, headers = {}) {
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: name => headers[name.toLowerCase()] || null },
    async json() { return payload; }
  };
}

function fakeTimers() {
  const timers = new Map();
  let next = 1;
  return {
    timers,
    setTimer(callback, delay) { const id = next++; timers.set(id, { callback, delay }); return id; },
    clearTimer(id) { timers.delete(id); }
  };
}

const challenge = '{"access_token":{"acrs":{"essential":true,"value":"c1"}}}';
const session = {
  sessionId: 'a'.repeat(32),
  ownerKey: 'entra:tenant:user',
  authContextId: 'c1',
  expiresAtUtc: '2026-10-12T10:30:00.000Z',
  capabilities: { readGovernance: true, approveRules: true, selfApprove: false, operateActions: false }
};

test('admin client sends idempotency keys, ETags, and operation paths', async () => {
  const requests = [];
  const client = new AdminClient(new ProfileClient('/api/v1', async (url, options) => {
    requests.push({ url, options });
    return response(requests.length === 1 ? 201 : 200, { RowKey: 'rule', Status: 'PendingApproval' }, { etag: 'W/"2"' });
  }));
  const authentication = { type: 'entra', getAccessToken: async () => 'token' };
  const proposed = await client.proposeRule(authentication, { reason: 'x' }, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
  assert.equal(proposed.replay, false);
  assert.equal(requests[0].options.headers['Idempotency-Key'], 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
  await client.transitionRule(authentication, 'rule/1', 'revoke', 'No longer required.', 'W/"2"');
  assert.equal(requests[1].url, '/api/v1/rules/rule%2F1/revoke');
  assert.equal(requests[1].options.headers['If-Match'], 'W/"2"');
  assert.equal(JSON.parse(requests[1].options.body).reason, 'No longer required.');
  await assert.rejects(() => client.transitionRule(authentication, 'rule', 'delete', '', 'W/"2"'));
});

test('Admin mode answers the claims challenge and keeps the elevated token in memory', async () => {
  const timers = fakeTimers();
  const calls = [];
  const changes = [];
  const client = {
    async enterSession(authentication) {
      const token = await authentication.getAccessToken();
      calls.push(token);
      if (token === 'base-token') {
        throw new ProfileApiError(401, 'admin_auth_context_required', 'Step-up required.', 'c', { claims: challenge, authContextId: 'c1' });
      }
      return session;
    },
    async exitSession(authentication, reason) { calls.push(`exit:${await authentication.getAccessToken()}:${reason}`); }
  };
  const auth = {
    getAccount: () => ({ homeAccountId: 'home-1', username: 'admin@example.test' }),
    getAccessToken: async () => 'base-token',
    getClaimsChallengeToken: async claims => { assert.equal(claims, challenge); return 'admin-token'; }
  };
  const controller = new AdminModeController({
    client,
    auth,
    onChange: change => changes.push(change),
    now: () => Date.parse('2026-10-12T10:05:00.000Z'),
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer
  });

  await controller.enter();
  assert.deepEqual(calls, ['base-token', 'admin-token']);
  assert.equal(controller.active, true);
  assert.equal(await controller.authentication().getAccessToken(), 'admin-token');
  const delays = [...timers.timers.values()].map(timer => timer.delay).sort((a, b) => a - b);
  assert.deepEqual(delays, [15 * 60_000, 25 * 60_000]);
  assert.equal(controller.accountChanged({ homeAccountId: 'home-2' }), true);
  assert.equal(controller.accountChanged({ homeAccountId: 'home-1' }), false);

  const idleTimer = [...timers.timers.values()].find(timer => timer.delay === 15 * 60_000);
  await idleTimer.callback();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(controller.active, false);
  assert.equal(timers.timers.size, 0);
  assert.equal(calls.at(-1), 'exit:admin-token:idle');
  assert.deepEqual(changes.map(change => change.active), [true, false]);
  assert.throws(() => controller.authentication(), /not active/);
});

test('Admin mode does not prompt for unrelated backend failures', async () => {
  let prompted = false;
  const controller = new AdminModeController({
    client: { async enterSession() { throw new ProfileApiError(403, 'role_required', 'No role.', 'c', {}); } },
    auth: {
      getAccount: () => ({ homeAccountId: 'home-1' }),
      getAccessToken: async () => 'base-token',
      getClaimsChallengeToken: async () => { prompted = true; return 'x'; }
    },
    setTimer: () => 1,
    clearTimer: () => {}
  });
  await assert.rejects(() => controller.enter(), error => error.code === 'role_required');
  assert.equal(prompted, false);
  assert.equal(controller.active, false);
});

test('rule proposals are prefilled from review rows and previewed against loaded data', () => {
  const row = {
    ComputerName: 'BER-001',
    PrincipalID: 'S-1-5-21-1-2-3-1001',
    PrincipalType: 'User',
    PrincipalSource: 'Active Directory',
    MembershipType: 'Direct',
    JoinState: 'Hybrid joined'
  };
  const draft = proposalFromReviewRow(row);
  assert.equal(draft.principalSource, 'AD');
  assert.equal(draft.deviceScopeType, 'ExactComputer');
  assert.equal(draft.deviceScopeValue, 'BER-001');
  assert.deepEqual([draft.allowedEntraJoined, draft.allowedHybridJoined, draft.allowedDomainJoined], [false, true, false]);
  assert.ok(validateProposalDraft(draft).some(error => error.includes('Reason')));
  assert.deepEqual(validateProposalDraft({ ...draft, reason: 'Approved helpdesk exception.' }), []);
  assert.ok(validateProposalDraft({ ...draft, reason: 'Approved helpdesk exception.', deviceScopeValue: 'BER-*' }).length);

  const prefix = { ...draft, deviceScopeType: 'ComputerPrefix', deviceScopeValue: 'BER-', allowedEntraJoined: true, allowedDomainJoined: true };
  const preview = previewMatches(prefix, [row, { ...row, ComputerName: 'BER-002' }, { ...row, ComputerName: 'HAM-001' }, { ...row, PrincipalID: 'S-1-5-21-9' }]);
  assert.deepEqual(preview, { rows: 2, computers: 2 });
});
