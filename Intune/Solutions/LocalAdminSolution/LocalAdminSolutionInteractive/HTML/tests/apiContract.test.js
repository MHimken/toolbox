import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildEntraOwnerKey,
  buildRecoveryOwnerKey,
  canTransitionAction,
  canTransitionRule,
  evaluateRuleSet,
  mutationHeaders,
  validateAllowRule
} from '../apiContract.js';
import { resolveAzureData } from '../dataService.js';

const now = new Date('2026-10-01T12:00:00.000Z');
const baseRule = {
  PartitionKey: 'org',
  RowKey: '8fd3ec65-e5df-4f70-9b27-8c567fac5a7f',
  RuleScope: 'Governance',
  Effect: 'Allow',
  PrincipalType: 'User',
  MatchType: 'SID',
  PrincipalValue: 'S-1-5-21-1-2-3-1001',
  PrincipalSource: 'AD',
  AllowedEntraJoined: true,
  AllowedHybridJoined: true,
  AllowedDomainJoined: true,
  MembershipScope: 'Any',
  DeviceScopeType: 'Any',
  Status: 'Active',
  Reason: 'Approved support account',
  CreatedAtUtc: '2026-01-01T00:00:00.000Z',
  CreatedBy: 'entra:11111111-1111-4111-8111-111111111111:22222222-2222-4222-8222-222222222222',
  SchemaVersion: '1',
  ValidFromUtc: '2026-01-01T00:00:00.000Z',
  ValidUntilUtc: '2026-12-31T23:59:59.000Z'
};
const row = {
  ComputerName: 'PC-001',
  PrincipalID: 'S-1-5-21-1-2-3-1001',
  PrincipalType: 'User',
  PrincipalSource: 'AD',
  PrincipalName: 'CONTOSO\\Support',
  MembershipType: 'Direct',
  JoinState: 'Hybrid joined',
  DaysSinceLastReport: 2
};

test('owner keys use immutable claims and recovery digests', () => {
  assert.equal(
    buildEntraOwnerKey('11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222'),
    'entra:11111111-1111-4111-8111-111111111111:22222222-2222-4222-8222-222222222222'
  );
  assert.equal(buildRecoveryOwnerKey('a'.repeat(64)), `recovery:${'a'.repeat(64)}`);
});

test('valid governance SID rule approves a matching row', () => {
  assert.deepEqual(validateAllowRule(baseRule), []);
  assert.equal(evaluateRuleSet([baseRule], row, now).status, 'Governance approved');
});

test('equally specific governance allow and deny rules conflict', () => {
  const deny = { ...baseRule, RowKey: '90329684-9fd3-4af5-97cf-99373ee301de', Effect: 'Deny' };
  assert.equal(evaluateRuleSet([baseRule, deny], row, now).status, 'Rule conflict');
});

test('more specific governance rule is decisive', () => {
  const exactDeviceDeny = {
    ...baseRule,
    RowKey: '90329684-9fd3-4af5-97cf-99373ee301de',
    Effect: 'Deny',
    DeviceScopeType: 'ExactComputer',
    DeviceScopeValue: 'PC-001'
  };
  assert.equal(evaluateRuleSet([baseRule, exactDeviceDeny], row, now).status, 'Governance denied');
});

test('personal rule cannot deny or use organization ownership', () => {
  const personal = { ...baseRule, RuleScope: 'Personal', Effect: 'Deny' };
  const errors = validateAllowRule(personal);
  assert.ok(errors.includes('Personal rules must use an Entra or recovery owner partition.'));
  assert.ok(errors.includes('Personal rules cannot deny or override governance.'));
});

test('action transitions and ETags are fail closed', () => {
  assert.equal(canTransitionRule('Governance', 'Draft', 'PendingApproval'), true);
  assert.equal(canTransitionRule('Personal', 'Draft', 'PendingApproval'), false);
  assert.equal(canTransitionAction('Requested', 'Queued'), true);
  assert.equal(canTransitionAction('Succeeded', 'InProgress'), false);
  assert.deepEqual(mutationHeaders('"etag-value"'), { 'If-Match': '"etag-value"' });
  assert.deepEqual(mutationHeaders('', true), { 'If-None-Match': '*' });
  assert.throws(() => mutationHeaders(''), /ETag is required/);
});

test('resolved review data preserves policy status when freshness takes priority', () => {
  const report = resolveAzureData(
    [{
      PartitionKey: 'S-1-5-21-9-8-7-1000',
      RowKey: '1',
      PrincipalID: row.PrincipalID,
      PrincipalType: 'User',
      MembershipType: 'Direct',
      Computername: 'PC-001',
      Removed: 0
    }],
    [{
      PartitionKey: row.PrincipalID,
      RowKey: 'CONTOSO\\Support',
      LocalOrEntraOrAD: 'AD',
      ResolutionState: 'Resolved'
    }],
    [],
    [
      {
        PartitionKey: 'v1',
        RowKey: 'E_33333333-3333-4333-8333-333333333333',
        ObservationType: 'Entra',
        EntraDeviceId: '33333333-3333-4333-8333-333333333333',
        EntraPresent: false
      },
      {
        PartitionKey: 'v1',
        RowKey: 'C_S-1-5-21-9-8-7-1000',
        ObservationType: 'Collector',
        EntraDeviceId: '33333333-3333-4333-8333-333333333333',
        ComputerSid: 'S-1-5-21-9-8-7-1000',
        ComputerName: 'PC-001',
        JoinState: 'Hybrid joined',
        LastReportUtc: new Date().toISOString()
      }
    ],
    [baseRule],
    [],
    90,
    90
  );
  assert.equal(report.review[0].PolicyStatus, 'Governance approved');
  assert.equal(report.review[0].ReviewStatus, 'Device missing from Entra');
});

test('review window excludes known devices outside the configured age', () => {
  const report = resolveAzureData(
    [{
      PartitionKey: 'S-1-5-21-9-8-7-1000',
      RowKey: '1',
      PrincipalID: row.PrincipalID,
      PrincipalType: 'User',
      MembershipType: 'Direct',
      Computername: 'PC-001',
      Removed: 0
    }],
    [{
      PartitionKey: row.PrincipalID,
      RowKey: 'CONTOSO\\Support',
      LocalOrEntraOrAD: 'AD',
      ResolutionState: 'Resolved'
    }],
    [],
    [{
      PartitionKey: 'v1',
      RowKey: 'C_S-1-5-21-9-8-7-1000',
      ObservationType: 'Collector',
      ComputerSid: 'S-1-5-21-9-8-7-1000',
      ComputerName: 'PC-001',
      JoinState: 'Hybrid joined',
      LastReportUtc: new Date(Date.now() - 45 * 86400000).toISOString()
    }],
    [],
    [],
    90,
    30
  );
  assert.equal(report.review.length, 0);
});
