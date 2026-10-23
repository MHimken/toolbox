import test from 'node:test';
import assert from 'node:assert/strict';
import { identityUsage, LocalFirstIdentityLookup, searchLocalIdentities } from '../identityLookup.js';
import { resolveReviewData } from '../dataService.js';
import { previewRuleMatches } from '../adminMode.js';

const userSid = 'S-1-5-21-1-2-3-1001';
const groupSid = 'S-1-5-21-1-2-3-2001';
const report = {
  users: [{ UserID: userSid, SamAccountName: 'CONTOSO\\alice', UserPrincipalName: 'alice@contoso.test', LocalOrEntraOrAD: 'A' }],
  groups: [{ GroupID: groupSid, GroupName: 'Helpdesk', LocalOrEntraOrAD: 'A' }],
  summary: [
    { ComputerName: 'PC-1', PrincipalType: 'User', PrincipalID: userSid, UserName: 'CONTOSO\\alice', MembershipType: 'Transitive', _AssignedThroughGroupSID: groupSid, Removed: 0 },
    { ComputerName: 'PC-2', PrincipalType: 'Group', PrincipalID: groupSid, GroupName: 'Helpdesk', MembershipType: 'Direct', Removed: 1 }
  ],
  governance: [
    { RuleScope: 'Governance', RowKey: 'user-rule', PrincipalType: 'User', MatchType: 'SID', PrincipalValue: userSid, Status: 'PendingApproval' },
    { RuleScope: 'Governance', RowKey: 'group-rule', PrincipalType: 'Group', MatchType: 'SID', PrincipalValue: groupSid, Status: 'Revoked' },
    { RuleScope: 'Governance', RowKey: 'path-rule', PrincipalType: 'User', MatchType: 'SID', PrincipalValue: 'S-1-5-21-1-2-3-9999', AssignedThroughGroupSid: groupSid },
    { RuleScope: 'Governance', RowKey: 'other', PrincipalType: 'User', MatchType: 'SID', PrincipalValue: 'S-1-5-21-1-2-3-8888' },
    { RuleScope: 'Personal', RowKey: 'personal', PrincipalType: 'User', MatchType: 'SID', PrincipalValue: userSid }
  ]
};

function harness(remoteSearch = async () => ({ identities: [], truncated: false })) {
  const timers = new Map();
  let next = 0;
  let time = 0;
  const states = [];
  const lookup = new LocalFirstIdentityLookup({
    localSearch: (type, query) => searchLocalIdentities(report, type, query),
    remoteSearch,
    onChange: state => states.push(state),
    setTimer: (fn, delay) => { const id = ++next; timers.set(id, { fn, delay }); return id; },
    clearTimer: id => timers.delete(id),
    now: () => time
  });
  return { lookup, states, timers, advance: value => { time += value; }, run: async () => {
    const scheduled = [...timers.values()];
    timers.clear();
    await Promise.all(scheduled.map(timer => timer.fn()));
  } };
}

test('local search resolves UPN, group name and Unicode SID without mixing principal types', () => {
  assert.equal(searchLocalIdentities(report, 'User', 'ALICE@').identities[0].sid, userSid);
  assert.equal(searchLocalIdentities(report, 'User', 'ALICE@').identities[0].source, 'AD');
  assert.equal(searchLocalIdentities(report, 'Group', 'helpdesk').identities[0].sid, groupSid);
  assert.equal(searchLocalIdentities(report, 'User', userSid.replaceAll('-', '\u2011')).identities[0].sid, userSid);
  assert.equal(searchLocalIdentities(report, 'Group', 'alice').identities.length, 0);
});

test('an exact SID match is first even when many other SIDs share its prefix', () => {
  const users = Array.from({ length: 25 }, (_, i) => ({ UserID: `${userSid}${i}`, SamAccountName: `user-${i}` }));
  users.push(report.users[0]);
  const result = searchLocalIdentities({ users }, 'User', userSid);
  assert.equal(result.identities[0].sid, userSid);
  assert.equal(result.truncated, true);
  assert.equal(result.identities.length, 20);
});

test('review rows retain group SIDs and collected source codes for assigned-through previews', () => {
  const rows = resolveReviewData([{
    ...report.summary[0], DaysSinceLastReport: 1, ReportingState: 'Reporting', PrincipalSource: 'A', JoinState: 'Domain joined'
  }], [], []);
  assert.equal(rows[0].AssignedThroughGroupSid, groupSid);
  const preview = previewRuleMatches({
    PrincipalType: 'User', MatchType: 'SID', PrincipalValue: userSid, PrincipalSource: 'AD',
    MembershipScope: 'Transitive', AssignedThroughGroupSid: groupSid, AllowedDomainJoined: true
  }, rows);
  assert.equal(preview.rows, 1);
});

test('local matches, SAS-only searches, short queries and direct SIDs never schedule Entra calls', async () => {
  let calls = 0;
  const h = harness(async () => { calls++; return { identities: [] }; });
  for (const [query, account] of [['alice', 'account'], ['unknown', ''], ['ab', 'account'], ['S-1-5-99', 'account']]) {
    h.lookup.search(query, 'User', account);
    assert.equal(h.timers.size, 0);
  }
  await h.run();
  assert.equal(calls, 0);
});

test('typing defers and replaces Entra lookup; results and empty results are cached per account and type', async () => {
  const calls = [];
  const h = harness(async (type, query, account) => { calls.push({ type, query, account }); return { identities: [] }; });
  h.lookup.search('unknown', 'User', 'account-1');
  h.lookup.search('unknown person', 'User', 'account-1');
  assert.equal(calls.length, 0);
  assert.equal(h.timers.size, 1);
  assert.equal([...h.timers.values()][0].delay, 800);
  await h.run();
  assert.deepEqual(calls, [{ type: 'User', query: 'unknown person', account: 'account-1' }]);
  h.lookup.search('UNKNOWN PERSON', 'User', 'account-1');
  assert.equal(h.timers.size, 0);
  h.lookup.search('unknown person', 'User', 'account-2');
  await h.run();
  h.lookup.search('unknown person', 'Group', 'account-2');
  await h.run();
  assert.equal(calls.length, 3);
  h.advance(5 * 60_000 + 1);
  h.lookup.search('unknown person', 'User', 'account-1');
  await h.run();
  assert.equal(calls.length, 4);
  h.lookup.reset();
  h.lookup.search('unknown person', 'User', 'account-1');
  await h.run();
  assert.equal(calls.length, 5);
});

test('late results cannot replace a newer local search; reset cancels searches and clears cached results', async () => {
  let complete;
  let signal;
  const h = harness((type, query, account, requestSignal) => {
    signal = requestSignal;
    return new Promise(resolve => { complete = resolve; });
  });
  h.lookup.search('unknown', 'User', 'account');
  const pending = h.run();
  h.lookup.search('alice', 'User', 'account');
  assert.equal(signal.aborted, true);
  complete({ identities: [{ sid: 'wrong' }] });
  await pending;
  assert.equal(h.states.at(-1).identities[0].sid, userSid);
  h.lookup.search('unknown', 'User', 'account');
  h.lookup.reset();
  assert.equal(h.timers.size, 0);
});

test('directory failures are shown rather than converted into empty successful results', async () => {
  const h = harness(async () => { throw new Error('Graph permission is missing.'); });
  h.lookup.search('unknown', 'User', 'account');
  await h.run();
  assert.equal(h.states.at(-1).phase, 'error');
  assert.match(h.states.at(-1).message, /Graph permission is missing/);
  h.lookup.search('unknown', 'User', 'account');
  assert.equal(h.timers.size, 1);
});

test('identity usage includes group assignment paths, removed entries and inactive rule references', () => {
  const user = identityUsage(report, 'User', userSid);
  assert.equal(user.entries.length, 1);
  assert.deepEqual(user.rules.map(rule => rule.RowKey), ['user-rule']);
  const group = identityUsage(report, 'Group', groupSid);
  assert.equal(group.entries.length, 2);
  assert.equal(group.computers, 2);
  assert.deepEqual(group.rules.map(rule => rule.RowKey), ['user-rule', 'group-rule', 'path-rule']);
  assert.equal(identityUsage(report, 'User', 'S-1-5-99').entries.length, 0);
});

test('default timers are invoked without a receiver, as browsers require', async () => {
  const original = globalThis.setTimeout;
  globalThis.setTimeout = function (callback, delay) {
    if (this !== undefined && this !== globalThis) throw new TypeError('Illegal invocation');
    return original(callback, delay);
  };
  try {
    let calls = 0;
    const lookup = new LocalFirstIdentityLookup({
      localSearch: () => ({ identities: [], truncated: false }),
      remoteSearch: async () => { calls++; return { identities: [], truncated: false }; },
      onChange: () => {},
      delayMs: 1
    });
    lookup.search('nobody.here', 'User', 'account-1');
    await new Promise(resolve => original(resolve, 20));
    assert.equal(calls, 1);
  } finally {
    globalThis.setTimeout = original;
  }
});
