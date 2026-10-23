import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import {
  AdminClient,
  AdminModeController,
  normalizeSidInput,
  previewMatches,
  previewRuleFromProposal,
  previewRuleMatches,
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

test('admin sessions use a route outside the Functions host reserved admin namespace', async () => {
  const requests = [];
  const client = new AdminClient(new ProfileClient('/v1', async (url, options) => {
    requests.push({ url, method: options.method });
    return response(options.method === 'DELETE' ? 204 : 200, session);
  }));
  const authentication = { type: 'entra', getAccessToken: async () => 'token' };
  assert.deepEqual(await client.enterSession(authentication), session);
  await client.exitSession(authentication, 'account change');
  assert.deepEqual(requests, [
    { url: '/v1/sessions/admin', method: 'POST' },
    { url: '/v1/sessions/admin?reason=account%20change', method: 'DELETE' }
  ]);
});

test('pasted non-breaking hyphens are normalized for form submission, validation and preview', async () => {
  const principalSid = 'S-1-5-21-3623811015-3361044348-30300820-1001';
  const groupSid = 'S-1-5-21-1-2-3-2001';
  const elements = Object.fromEntries([
    ['ruleEffect', 'Allow'], ['rulePrincipalType', 'User'],
    ['rulePrincipalSid', principalSid.replaceAll('-', '\u2011')],
    ['rulePrincipalSource', 'Any'], ['ruleMembershipScope', 'Transitive'],
    ['ruleAssignedThroughGroupSid', groupSid.replaceAll('-', '\u2010')],
    ['ruleDeviceScopeType', 'Any'], ['ruleMaxDeviceAgeDays', ''],
    ['ruleValidFrom', ''], ['ruleValidUntil', ''], ['ruleTicketReference', ''],
    ['ruleReason', 'Approved helpdesk exception.']
  ].map(([id, value]) => [id, { value }]));
  for (const id of ['ruleAllowedEntraJoined', 'ruleAllowedHybridJoined', 'ruleAllowedDomainJoined']) {
    elements[id] = { checked: true };
  }
  const source = await readFile(new URL('../app.js', import.meta.url), 'utf8');
  const helper = source.match(/    function readRuleForm\(\) \{[\s\S]*?\r?\n    \}/)?.[0];
  assert.ok(helper);
  const proposal = runInNewContext(`${helper}\nreadRuleForm()`, { elements, normalizeSidInput, selectedPrincipal: null });
  assert.equal(proposal.principalSid, principalSid);
  assert.equal(proposal.assignedThroughGroupSid, groupSid);
  const selected = { sid: principalSid, principalType: 'User', displayName: 'Alice', userPrincipalName: 'alice@contoso.test' };
  const selectedProposal = runInNewContext(`${helper}\nreadRuleForm()`, { elements, normalizeSidInput, selectedPrincipal: selected });
  assert.equal(selectedProposal.principalDisplayName, 'Alice');
  assert.equal(selectedProposal.principalUserPrincipalName, 'alice@contoso.test');
  const changedSid = runInNewContext(`${helper}\nreadRuleForm()`, {
    elements, normalizeSidInput, selectedPrincipal: { ...selected, sid: 'S-1-5-99' }
  });
  assert.equal(changedSid.principalDisplayName, undefined);
  const pasted = {
    ...proposal,
    principalSid: elements.rulePrincipalSid.value,
    assignedThroughGroupSid: elements.ruleAssignedThroughGroupSid.value
  };
  assert.deepEqual(validateProposalDraft(pasted), []);
  assert.equal(previewRuleFromProposal(pasted).PrincipalValue, principalSid);
  assert.equal(previewRuleFromProposal(pasted).AssignedThroughGroupSid, groupSid);
  assert.deepEqual(previewMatches(pasted, [{
    PrincipalID: principalSid, PrincipalType: 'User', MembershipType: 'Transitive',
    AssignedThroughGroupSid: groupSid, JoinState: 'Domain joined', ComputerName: 'PC-001'
  }]), { rows: 1, computers: 1 });
  assert.ok(validateProposalDraft({ ...proposal, principalSid: 'DOMAIN\\Helpdesk' }).some(error => error.includes('Principal SID')));
  assert.ok(validateProposalDraft({ ...proposal, assignedThroughGroupSid: 'not-a-sid' }).some(error => error.includes('Assigned-through')));
});

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
  assert.deepEqual(delays, [1000, 15 * 60_000, 25 * 60_000]);
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

test('idle countdown uses elapsed time, resets on activity, and stops when Admin mode ends', async () => {
  const timers = fakeTimers();
  const countdowns = [];
  let now = Date.parse('2026-10-12T10:05:00.000Z');
  const controller = new AdminModeController({
    client: { enterSession: async () => session, exitSession: async () => {} },
    auth: {
      getAccount: () => ({ homeAccountId: 'home-1' }),
      getAccessToken: async () => 'admin-token'
    },
    now: () => now,
    onCountdown: (idle, total) => countdowns.push({ idle, total }),
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer
  });

  await controller.enter();
  assert.deepEqual(countdowns.at(-1), { idle: 15 * 60_000, total: 25 * 60_000 });
  const absoluteExpiryTimer = controller.expiryTimer;
  const tick = () => {
    const timer = timers.timers.get(controller.countdownTimer);
    timers.timers.delete(controller.countdownTimer);
    timer.callback();
  };
  now += 61_000;
  tick();
  assert.deepEqual(countdowns.at(-1), { idle: 14 * 60_000 - 1000, total: 24 * 60_000 - 1000 });

  controller.touch();
  assert.deepEqual(countdowns.at(-1), { idle: 15 * 60_000, total: 24 * 60_000 - 1000 });
  assert.equal(controller.expiryTimer, absoluteExpiryTimer);
  assert.equal(timers.timers.size, 3);

  now += 15 * 60_000 + 5000;
  tick();
  assert.deepEqual(countdowns.at(-1), { idle: 0, total: 9 * 60_000 - 6000 });
  await controller.exit('idle');
  assert.deepEqual(countdowns.at(-1), { idle: 0, total: 0 });
  assert.equal(timers.timers.size, 0);
  assert.equal(controller.active, false);
});

test('total countdown ends at the backend expiry even with idle time remaining', async () => {
  const timers = fakeTimers();
  const countdowns = [];
  let now = Date.parse(session.expiresAtUtc) - 60_000;
  const controller = new AdminModeController({
    client: { enterSession: async () => session, exitSession: async () => {} },
    auth: {
      getAccount: () => ({ homeAccountId: 'home-1' }),
      getAccessToken: async () => 'admin-token'
    },
    now: () => now,
    onCountdown: (idle, total) => countdowns.push({ idle, total }),
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer
  });

  await controller.enter();
  assert.deepEqual(countdowns.at(-1), { idle: 15 * 60_000, total: 60_000 });
  const tick = timers.timers.get(controller.countdownTimer);
  timers.timers.delete(controller.countdownTimer);
  now += 60_000;
  tick.callback();
  assert.deepEqual(countdowns.at(-1), { idle: 14 * 60_000, total: 0 });
  assert.equal(controller.countdownTimer, null);
  await timers.timers.get(controller.expiryTimer).callback();
  assert.deepEqual(countdowns.at(-1), { idle: 0, total: 0 });
  assert.equal(timers.timers.size, 0);
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

test('pending governance and proposal previews return the same constrained matching entries', () => {
  const proposal = {
    effect: 'Allow', principalType: 'User',
    principalSid: 'S-1-5-21-930000001-950000002-960000003-3301001',
    principalSource: 'AD', membershipScope: 'Transitive',
    assignedThroughGroupSid: 'S-1-5-21-1-2-3-2001',
    deviceScopeType: 'ComputerPrefix', deviceScopeValue: 'PC-',
    allowedEntraJoined: false, allowedHybridJoined: true, allowedDomainJoined: false,
    maxDeviceAgeDays: 30
  };
  const entry = {
    ComputerName: 'PC-001', PrincipalID: proposal.principalSid, PrincipalType: 'User',
    PrincipalSource: 'Active Directory', MembershipType: 'Transitive',
    AssignedThroughGroupSid: proposal.assignedThroughGroupSid,
    JoinState: 'Hybrid joined', DaysSinceLastReport: 30
  };
  const matches = [
    entry, { ...entry, PrincipalName: 'Another access path' },
    { ...entry, AssignedThroughGroupSid: undefined, _AssignedThroughGroupSID: proposal.assignedThroughGroupSid }
  ];
  const excluded = [
    { ...entry, PrincipalID: 'S-1-5-21-9' }, { ...entry, PrincipalType: 'Group' },
    { ...entry, PrincipalSource: 'Local' }, { ...entry, MembershipType: 'Direct' },
    { ...entry, AssignedThroughGroupSid: 'S-1-5-21-9' },
    { ...entry, ComputerName: 'OTHER-001' }, { ...entry, JoinState: 'Domain joined' },
    { ...entry, DaysSinceLastReport: 31 }
  ];
  const review = [...matches, ...excluded];
  const rule = { ...previewRuleFromProposal(proposal), Status: 'PendingApproval' };
  const preview = previewRuleMatches(rule, review);
  assert.equal(rule.Effect, 'Allow');
  assert.deepEqual(preview, { rows: 3, computers: 1, entries: matches });
  assert.deepEqual(previewMatches(proposal, review), { rows: 3, computers: 1 });
  assert.deepEqual(previewRuleMatches(rule, []), { rows: 0, computers: 0, entries: [] });
  assert.deepEqual(previewRuleMatches({ ...rule, DeviceScopeType: 'ExactComputer', DeviceScopeValue: 'PC-002' }, review).entries, []);
});

function previewElement(tag = '') {
  return {
    tag, children: [], listeners: {}, attributes: {}, textContent: '', value: '', open: false,
    append(...children) { this.children.push(...children); },
    appendChild(child) { this.append(child); return child; },
    replaceChildren(...children) { this.children = children; this.textContent = ''; },
    setAttribute(name, value) { this.attributes[name] = value; },
    addEventListener(name, listener) { this.listeners[name] = listener; },
    showModal() { this.open = true; },
    close() { this.open = false; },
    focus() {}
  };
}

async function previewUi(review) {
  const source = await readFile(new URL('../app.js', import.meta.url), 'utf8');
  const functions = [
    'rulePreviewSummary', 'renderRulePreview', 'openRuleMatchesDialog', 'updateRulePreview',
    'adminActionButton', 'renderAdminActionsCell', 'openReasonDialog'
  ].map(name => {
    const helper = source.match(new RegExp(`    function ${name}\\([^\\n]*\\) \\{[\\s\\S]*?\\r?\\n    \\}`))?.[0];
    assert.ok(helper, name);
    return helper;
  }).join('\n');
  const elements = Object.fromEntries([
    'rulePreview', 'ruleDeviceScopeValue', 'ruleDeviceScopeType',
    'ruleMatchesDialog', 'ruleMatchesSummary', 'ruleMatchesHead', 'ruleMatchesBody', 'ruleMatchesEmpty',
    'ruleMatchesCloseButton', 'reasonDialogTitle', 'reasonDialogSummary', 'reasonRulePreview',
    'reasonInput', 'reasonFormStatus', 'reasonSubmitButton', 'reasonDialog', 'ruleDialog'
  ].map(id => [id, previewElement()]));
  const REPORT = { review };
  const closeBinding = source.match(/    elements\.ruleMatchesCloseButton\.addEventListener[^\r\n]+/)?.[0];
  assert.ok(closeBinding);
  const ui = runInNewContext(`let pendingReasonAction;\n${functions}\n${closeBinding}
    ({ updateRulePreview, renderAdminActionsCell, renderRulePreview, getPendingAction: () => pendingReasonAction })`, {
    elements, REPORT, formatter: new Intl.NumberFormat('en-US'),
    document: { createElement: previewElement }, previewRuleMatches, previewRuleFromProposal,
    displayValue: (_key, value) => String(value || ''), text: value => String(value || ''),
    state: { view: 'governance', query: 'unrelated filter' },
    adminController: { capabilities: { approveRules: true }, session: { ownerKey: 'approver' } },
    readRuleForm: () => ({
      effect: 'Allow', principalType: 'User', principalSid: review[0]?.PrincipalID,
      allowedEntraJoined: true, allowedHybridJoined: true, allowedDomainJoined: true
    })
  });
  return { ...ui, elements, REPORT };
}

test('proposer can inspect every matching entry without losing the proposal dialog', async () => {
  const entry = {
    PrincipalID: 'S-1-5-21-930000001-950000002-960000003-3301001',
    PrincipalType: 'User', ComputerName: 'PC-001', PrincipalName: '<img src=x onerror=alert(1)>'
  };
  const { updateRulePreview, elements } = await previewUi([entry, { ...entry }, { ...entry }]);
  elements.ruleDialog.showModal();
  updateRulePreview();
  const link = elements.rulePreview.children[0];
  assert.equal(link.tag, 'button');
  assert.equal(link.type, 'button');
  assert.equal(link.attributes['aria-haspopup'], 'dialog');
  assert.equal(link.textContent, 'Preview: matches 3 loaded review entries on 1 computer.');
  link.listeners.click();
  assert.equal(elements.ruleMatchesDialog.open, true);
  assert.equal(elements.ruleMatchesBody.children.length, 3);
  assert.equal(elements.ruleMatchesBody.children[0].children[1].textContent, entry.PrincipalName);
  assert.equal(elements.ruleMatchesEmpty.hidden, true);
  assert.match(elements.ruleMatchesSummary.textContent, /^Allow User S-1-/);
  elements.ruleMatchesCloseButton.listeners.click();
  assert.equal(elements.ruleMatchesDialog.open, false);
  assert.equal(elements.ruleDialog.open, true);
});

test('approver gets clickable previews on the governance row and confirmation without submitting', async () => {
  const entry = { PrincipalID: 'S-1-5-21-1', PrincipalType: 'User', ComputerName: 'PC-001' };
  const { renderAdminActionsCell, getPendingAction, elements, REPORT } = await previewUi([entry]);
  const rule = {
    ...previewRuleFromProposal({
      effect: 'Allow', principalType: 'User', principalSid: entry.PrincipalID,
      allowedEntraJoined: true, allowedHybridJoined: true, allowedDomainJoined: true
    }),
    RuleScope: 'Governance', Status: 'PendingApproval', CreatedByOwnerKey: 'proposer',
    RowKey: 'rule-id', ETag: 'etag'
  };
  const cell = renderAdminActionsCell(rule);
  cell.children[3].children[0].listeners.click();
  assert.equal(elements.ruleMatchesBody.children.length, 1);
  elements.ruleMatchesCloseButton.listeners.click();
  assert.equal(cell.children[0].disabled, false);
  cell.children[0].listeners.click();
  assert.equal(elements.reasonDialog.open, true);
  assert.equal(elements.reasonRulePreview.hidden, false);
  assert.match(elements.reasonRulePreview.children[0].textContent, /1 loaded review entry on 1 computer/);
  const action = getPendingAction();
  elements.reasonInput.value = 'Approval comment in progress';
  REPORT.review = [{ ...entry, PrincipalID: 'S-1-5-21-9' }];
  elements.reasonRulePreview.children[0].listeners.click();
  assert.equal(elements.ruleMatchesBody.children.length, 0);
  assert.equal(elements.ruleMatchesEmpty.hidden, false);
  elements.ruleMatchesCloseButton.listeners.click();
  assert.equal(elements.reasonDialog.open, true);
  assert.equal(elements.reasonInput.value, 'Approval comment in progress');
  assert.equal(getPendingAction(), action);
});

test('both proposal and governance previews explain when inventory has not been loaded', async () => {
  const { updateRulePreview, renderRulePreview, elements } = await previewUi([]);
  updateRulePreview();
  renderRulePreview(elements.reasonRulePreview, {});
  for (const element of [elements.rulePreview, elements.reasonRulePreview]) {
    assert.match(element.textContent, /Load inventory data/);
    assert.equal(element.children.length, 0);
  }
});
