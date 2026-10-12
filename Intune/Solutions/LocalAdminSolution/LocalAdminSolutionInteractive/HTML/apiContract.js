export const CONTRACT_VERSION = '2026-10-01';

export const ruleStatuses = Object.freeze([
  'Draft',
  'PendingApproval',
  'Active',
  'Expired',
  'Rejected',
  'Revoked'
]);

export const ruleTransitions = Object.freeze({
  Personal: Object.freeze({
    Draft: ['Active', 'Revoked'],
    PendingApproval: [],
    Active: ['Expired', 'Revoked'],
    Expired: [],
    Rejected: [],
    Revoked: []
  }),
  Governance: Object.freeze({
    Draft: ['PendingApproval', 'Revoked'],
    PendingApproval: ['Active', 'Rejected', 'Revoked'],
    Active: ['Expired', 'Revoked'],
    Expired: [],
    Rejected: [],
    Revoked: []
  })
});

export const actionStatuses = Object.freeze([
  'Requested',
  'Queued',
  'InProgress',
  'AwaitingInventory',
  'Succeeded',
  'Failed',
  'Rejected',
  'Cancelled',
  'Expired'
]);

export const actionTransitions = Object.freeze({
  Requested: ['Queued', 'Rejected', 'Cancelled', 'Expired'],
  Queued: ['InProgress', 'Rejected', 'Cancelled', 'Expired'],
  InProgress: ['AwaitingInventory', 'Failed'],
  AwaitingInventory: ['Succeeded', 'Failed', 'Expired'],
  Succeeded: [],
  Failed: [],
  Rejected: [],
  Cancelled: [],
  Expired: []
});

const guidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const sidPattern = /^S-\d(?:-\d+)+$/i;
const recoveryDigestPattern = /^[0-9a-f]{64}$/i;
const ownerKeyPattern = /^(org|entra:[0-9a-f-]{36}:[0-9a-f-]{36}|recovery:[0-9a-f]{64})$/i;

function valueText(value) {
  return value === null || value === undefined ? '' : String(value).trim();
}

function normalizedBoolean(value) {
  return value === true || value === 1 || valueText(value).toLowerCase() === 'true';
}

function parsedDate(value) {
  if (!value) return null;
  const result = new Date(value);
  return Number.isNaN(result.getTime()) ? null : result;
}

export function normalizedSource(value) {
  const source = valueText(value).toLowerCase();
  if (source.includes('entra') || source === 'azuread') return 'Entra';
  if (source === 'ad' || source.includes('active directory')) return 'AD';
  if (source === 'local') return 'Local';
  return source ? valueText(value) : '';
}

export function buildEntraOwnerKey(tenantId, objectId) {
  const tenant = valueText(tenantId).toLowerCase();
  const object = valueText(objectId).toLowerCase();
  if (!guidPattern.test(tenant) || !guidPattern.test(object)) {
    throw new Error('Entra owner keys require valid tid and oid GUID claims.');
  }
  return `entra:${tenant}:${object}`;
}

export function buildRecoveryOwnerKey(sha256Digest) {
  const digest = valueText(sha256Digest).toLowerCase();
  if (!recoveryDigestPattern.test(digest)) {
    throw new Error('Recovery owner keys require a lowercase SHA-256 hexadecimal digest.');
  }
  return `recovery:${digest}`;
}

export function isOwnerKey(value) {
  const ownerKey = valueText(value);
  if (!ownerKeyPattern.test(ownerKey)) return false;
  if (ownerKey.toLowerCase().startsWith('entra:')) {
    const [, tenantId, objectId] = ownerKey.split(':');
    return guidPattern.test(tenantId) && guidPattern.test(objectId);
  }
  return true;
}

export function validateAllowRule(rule) {
  const errors = [];
  const scope = valueText(rule.RuleScope);
  const status = valueText(rule.Status);
  const effect = valueText(rule.Effect || 'Allow');
  const matchType = valueText(rule.MatchType);
  const principalType = valueText(rule.PrincipalType);
  const source = valueText(rule.PrincipalSource || 'Any');
  const membership = valueText(rule.MembershipScope || 'Any');
  const deviceScope = valueText(rule.DeviceScopeType || 'Any');
  const ownerKey = valueText(rule.PartitionKey);
  const validFrom = parsedDate(rule.ValidFromUtc);
  const validUntil = parsedDate(rule.ValidUntilUtc);

  if (!isOwnerKey(ownerKey)) errors.push('PartitionKey must be org, entra:<tid>:<oid>, or recovery:<sha256>.');
  if (!['Personal', 'Governance'].includes(scope)) errors.push('RuleScope must be Personal or Governance.');
  if (scope === 'Governance' && ownerKey.toLowerCase() !== 'org') errors.push('Governance rules must use the org partition.');
  if (scope === 'Personal' && ownerKey.toLowerCase() === 'org') errors.push('Personal rules must use an Entra or recovery owner partition.');
  if (!ruleStatuses.includes(status)) errors.push('Status is not supported by the contract.');
  if (!valueText(rule.Effect)) errors.push('Effect is required.');
  if (!['Allow', 'Deny'].includes(effect)) errors.push('Effect must be Allow or Deny.');
  if (scope === 'Personal' && effect === 'Deny') errors.push('Personal rules cannot deny or override governance.');
  if (!['User', 'Group'].includes(principalType)) errors.push('PrincipalType must be User or Group.');
  if (!['SID', 'ExactName'].includes(matchType)) errors.push('MatchType must be SID or ExactName.');
  if (matchType === 'SID' && !sidPattern.test(valueText(rule.PrincipalValue))) errors.push('SID rules require a valid SID.');
  if (matchType === 'ExactName' && (!valueText(rule.PrincipalValue) || /[*?]/.test(valueText(rule.PrincipalValue)))) {
    errors.push('ExactName rules require a non-wildcard principal name.');
  }
  if (!valueText(rule.PrincipalSource)) errors.push('PrincipalSource is required.');
  if (!['Local', 'Entra', 'AD', 'Any'].includes(source)) errors.push('PrincipalSource is not supported.');
  if (!valueText(rule.MembershipScope)) errors.push('MembershipScope is required.');
  if (!['Direct', 'Transitive', 'Any'].includes(membership)) errors.push('MembershipScope is not supported.');
  if (valueText(rule.AssignedThroughGroupSid) && !sidPattern.test(valueText(rule.AssignedThroughGroupSid))) {
    errors.push('AssignedThroughGroupSid must be a valid SID.');
  }
  if (valueText(rule.AssignedThroughGroupSid) && membership !== 'Transitive') {
    errors.push('AssignedThroughGroupSid requires Transitive membership.');
  }
  if (!valueText(rule.DeviceScopeType)) errors.push('DeviceScopeType is required.');
  if (!['Any', 'ExactComputer', 'ComputerPrefix'].includes(deviceScope)) errors.push('DeviceScopeType is not supported.');
  if (deviceScope !== 'Any' && !valueText(rule.DeviceScopeValue)) errors.push('A scoped device rule requires DeviceScopeValue.');
  if (/[*?]/.test(valueText(rule.DeviceScopeValue))) errors.push('DeviceScopeValue does not support wildcards.');
  if (rule.ValidFromUtc && !validFrom) errors.push('ValidFromUtc is invalid.');
  if (rule.ValidUntilUtc && !validUntil) errors.push('ValidUntilUtc is invalid.');
  if (validFrom && validUntil && validUntil < validFrom) errors.push('ValidUntilUtc cannot be earlier than ValidFromUtc.');
  if (rule.MaxDeviceAgeDays !== undefined && rule.MaxDeviceAgeDays !== null &&
      (!Number.isInteger(Number(rule.MaxDeviceAgeDays)) || Number(rule.MaxDeviceAgeDays) < 1)) {
    errors.push('MaxDeviceAgeDays must be a positive integer.');
  }
  if (!valueText(rule.RowKey)) errors.push('RowKey must contain a cryptographically random rule UUID.');
  if (valueText(rule.RowKey) && !guidPattern.test(valueText(rule.RowKey))) errors.push('RowKey must be a UUID.');
  for (const property of ['AllowedEntraJoined', 'AllowedHybridJoined', 'AllowedDomainJoined']) {
    if (![true, false].includes(rule[property])) errors.push(`${property} must be an explicit boolean.`);
  }
  if (!valueText(rule.Reason)) errors.push('Reason is required.');
  if (!parsedDate(rule.CreatedAtUtc)) errors.push('CreatedAtUtc is required and must be valid.');
  if (!valueText(rule.CreatedBy)) errors.push('CreatedBy is required.');
  if (!valueText(rule.SchemaVersion)) errors.push('SchemaVersion is required.');
  return errors;
}

function ruleSpecificity(rule) {
  let score = valueText(rule.MatchType) === 'SID' ? 100 : 50;
  if (valueText(rule.PrincipalSource || 'Any') !== 'Any') score += 10;
  if (valueText(rule.MembershipScope || 'Any') !== 'Any') score += 10;
  if (valueText(rule.AssignedThroughGroupSid)) score += 20;
  if (valueText(rule.DeviceScopeType) === 'ExactComputer') score += 30;
  if (valueText(rule.DeviceScopeType) === 'ComputerPrefix') score += 15;
  if (rule.MaxDeviceAgeDays !== undefined && rule.MaxDeviceAgeDays !== null) score += 5;
  return score;
}

export function ruleMatches(rule, row) {
  if (valueText(rule.PrincipalType) !== valueText(row.PrincipalType)) return false;
  if (valueText(rule.MatchType) === 'SID' &&
      valueText(rule.PrincipalValue).toUpperCase() !== valueText(row.PrincipalID).toUpperCase()) return false;
  if (valueText(rule.MatchType) === 'ExactName' &&
      valueText(rule.PrincipalValue).toLowerCase() !== valueText(row.PrincipalName || row.UserName || row.GroupName).toLowerCase()) return false;
  const source = valueText(rule.PrincipalSource || 'Any');
  if (source !== 'Any' && source !== normalizedSource(row.PrincipalSource)) return false;
  const membership = valueText(rule.MembershipScope || 'Any');
  if (membership !== 'Any' && membership !== valueText(row.MembershipType)) return false;
  if (valueText(rule.AssignedThroughGroupSid) &&
      valueText(rule.AssignedThroughGroupSid).toUpperCase() !== valueText(row.AssignedThroughGroupSid || row._AssignedThroughGroupSID).toUpperCase()) return false;
  const deviceScope = valueText(rule.DeviceScopeType || 'Any');
  const computerName = valueText(row.ComputerName).toLowerCase();
  const deviceValue = valueText(rule.DeviceScopeValue).toLowerCase();
  if (deviceScope === 'ExactComputer' && computerName !== deviceValue) return false;
  if (deviceScope === 'ComputerPrefix' && !computerName.startsWith(deviceValue)) return false;
  const joinField = {
    'Entra joined': 'AllowedEntraJoined',
    'Hybrid joined': 'AllowedHybridJoined',
    'Domain joined': 'AllowedDomainJoined'
  }[valueText(row.JoinState)];
  if (joinField && !normalizedBoolean(rule[joinField])) return false;
  if (rule.MaxDeviceAgeDays !== undefined && rule.MaxDeviceAgeDays !== null) {
    if (!Number.isFinite(Number(row.DaysSinceLastReport)) || Number(row.DaysSinceLastReport) > Number(rule.MaxDeviceAgeDays)) return false;
  }
  return true;
}

function temporalState(rule, now) {
  const validFrom = parsedDate(rule.ValidFromUtc);
  const validUntil = parsedDate(rule.ValidUntilUtc);
  if (validFrom && validFrom > now) return 'future';
  if (validUntil && validUntil < now) return 'expired';
  return 'current';
}

export function evaluateRuleSet(rules, row, now = new Date()) {
  const validRules = rules.filter(rule => validateAllowRule(rule).length === 0);
  const matching = validRules.filter(rule => ruleMatches(rule, row));
  const active = matching.filter(rule => valueText(rule.Status) === 'Active' && temporalState(rule, now) === 'current');
  const governance = active.filter(rule => valueText(rule.RuleScope) === 'Governance');
  const personal = active.filter(rule => valueText(rule.RuleScope) === 'Personal' && valueText(rule.Effect || 'Allow') === 'Allow');
  const matchingRuleIds = active.map(rule => valueText(rule.RowKey));

  if (governance.length) {
    const highestSpecificity = Math.max(...governance.map(ruleSpecificity));
    const decisiveRules = governance.filter(rule => ruleSpecificity(rule) === highestSpecificity);
    const effects = new Set(decisiveRules.map(rule => valueText(rule.Effect || 'Allow')));
    if (effects.size > 1) {
      return { status: 'Rule conflict', matchingRuleIds, decisiveRuleIds: decisiveRules.map(rule => valueText(rule.RowKey)) };
    }
    return {
      status: effects.has('Deny') ? 'Governance denied' : 'Governance approved',
      matchingRuleIds,
      decisiveRuleIds: decisiveRules.map(rule => valueText(rule.RowKey))
    };
  }
  if (personal.length) {
    return { status: 'Personal acknowledgement', matchingRuleIds, decisiveRuleIds: personal.map(rule => valueText(rule.RowKey)) };
  }
  if (matching.some(rule => valueText(rule.Status) === 'PendingApproval' && temporalState(rule, now) !== 'expired')) {
    return { status: 'Pending approval', matchingRuleIds: [], decisiveRuleIds: [] };
  }
  if (matching.some(rule => valueText(rule.Status) === 'Expired' || temporalState(rule, now) === 'expired')) {
    return { status: 'Expired approval', matchingRuleIds: [], decisiveRuleIds: [] };
  }
  return { status: 'No matching rule', matchingRuleIds: [], decisiveRuleIds: [] };
}

export function canTransitionAction(currentStatus, nextStatus) {
  return Boolean(actionTransitions[valueText(currentStatus)]?.includes(valueText(nextStatus)));
}

export function canTransitionRule(scope, currentStatus, nextStatus) {
  return Boolean(ruleTransitions[valueText(scope)]?.[valueText(currentStatus)]?.includes(valueText(nextStatus)));
}

export function validateReviewAction(action) {
  const errors = [];
  if (!guidPattern.test(valueText(action.RowKey))) errors.push('RowKey must be a UUID action ID.');
  if (!guidPattern.test(valueText(action.CorrelationId))) errors.push('CorrelationId must be a UUID.');
  if (!valueText(action.IdempotencyKey)) errors.push('IdempotencyKey is required.');
  if (!actionStatuses.includes(valueText(action.Status))) errors.push('Status is not supported by the contract.');
  if (!valueText(action.ActionType)) errors.push('ActionType is required.');
  if (!valueText(action.TargetComputerSid) && !valueText(action.TargetEntraDeviceId)) errors.push('A device target is required.');
  if (!valueText(action.TargetPrincipalId)) errors.push('TargetPrincipalId is required.');
  if (!valueText(action.Justification)) errors.push('Justification is required.');
  if (!isOwnerKey(action.RequestedByOwnerKey) || valueText(action.RequestedByOwnerKey).toLowerCase() === 'org') {
    errors.push('RequestedByOwnerKey must identify an Entra or recovery profile.');
  }
  if (!parsedDate(action.CreatedAtUtc)) errors.push('CreatedAtUtc is required and must be valid.');
  if (!valueText(action.SchemaVersion)) errors.push('SchemaVersion is required.');
  return errors;
}

export function findLatestAction(actions, row) {
  return actions
    .filter(action =>
      valueText(action.TargetPrincipalId).toUpperCase() === valueText(row.PrincipalID).toUpperCase() &&
      valueText(action.TargetComputerSid).toUpperCase() === valueText(row.SID || row.ComputerSid).toUpperCase())
    .sort((left, right) => {
      const leftTime = parsedDate(left.UpdatedAtUtc || left.CreatedAtUtc)?.getTime() || 0;
      const rightTime = parsedDate(right.UpdatedAtUtc || right.CreatedAtUtc)?.getTime() || 0;
      return rightTime - leftTime;
    })[0] || null;
}

export function mutationHeaders(etag, createOnly = false) {
  if (createOnly) return { 'If-None-Match': '*' };
  const normalizedEtag = valueText(etag);
  if (!normalizedEtag) throw new Error('An ETag is required for update or delete operations.');
  return { 'If-Match': normalizedEtag };
}
