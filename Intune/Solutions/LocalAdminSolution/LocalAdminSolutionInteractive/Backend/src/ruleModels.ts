export const ruleStatuses = ['Draft', 'PendingApproval', 'Active', 'Expired', 'Rejected', 'Revoked'] as const;
export type RuleStatus = typeof ruleStatuses[number];
export type RuleTransition = 'approve' | 'reject' | 'revoke';
export const governancePartition = 'org';
export const ruleSchemaVersion = 1;

/**
 * Allow-rule entity in the Azure Table column shape used by the report. Unknown columns written by other
 * tooling are preserved so the API does not silently drop data the report can display.
 */
export interface AllowRule {
  PartitionKey: string;
  RowKey: string;
  RuleScope: string;
  Status: string;
  ETag?: string;
  [column: string]: unknown;
}

export interface GovernanceProposal {
  Effect: 'Allow' | 'Deny';
  PrincipalType: 'User' | 'Group';
  MatchType: 'SID';
  PrincipalValue: string;
  PrincipalSource: 'Local' | 'Entra' | 'AD' | 'Any';
  MembershipScope: 'Direct' | 'Transitive' | 'Any';
  AssignedThroughGroupSid?: string;
  DeviceScopeType: 'Any' | 'ExactComputer' | 'ComputerPrefix';
  DeviceScopeValue: string;
  AllowedEntraJoined: boolean;
  AllowedHybridJoined: boolean;
  AllowedDomainJoined: boolean;
  MaxDeviceAgeDays?: number;
  ValidFromUtc?: string;
  ValidUntilUtc?: string;
  Reason: string;
  TicketReference?: string;
  Owner?: string;
}

const sidPattern = /^S-\d(?:-\d+)+$/i;
const controlCharacters = /[\u0000-\u001f\u007f]/;

function optionalText(value: unknown, name: string, maximum: number): string {
  if (value === undefined || value === null) return '';
  if (typeof value !== 'string') throw new Error(`${name} must be a string.`);
  const trimmed = value.trim();
  if (trimmed.length > maximum || controlCharacters.test(trimmed)) {
    throw new Error(`${name} must be at most ${maximum} characters and contain no control characters.`);
  }
  return trimmed;
}

function choice<T extends string>(value: unknown, name: string, allowed: readonly T[], fallback?: T): T {
  const candidate = value === undefined && fallback !== undefined ? fallback : value;
  if (typeof candidate !== 'string' || !allowed.includes(candidate as T)) {
    throw new Error(`${name} must be one of: ${allowed.join(', ')}.`);
  }
  return candidate as T;
}

function optionalDate(value: unknown, name: string): Date | null {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string') throw new Error(`${name} must be an ISO 8601 UTC timestamp.`);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) throw new Error(`${name} must be an ISO 8601 UTC timestamp.`);
  return parsed;
}

export function validateGovernanceProposal(value: unknown, now: Date): GovernanceProposal {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Request body must be an object.');
  const input = value as Record<string, unknown>;
  const principalValue = typeof input.principalSid === 'string' ? input.principalSid.trim().toUpperCase() : '';
  if (!sidPattern.test(principalValue)) {
    throw new Error('principalSid must be a valid SID. Governance rules match immutable SIDs only.');
  }
  const membershipScope = choice(input.membershipScope, 'membershipScope', ['Direct', 'Transitive', 'Any'] as const, 'Any');
  const assignedThroughGroupSid = optionalText(input.assignedThroughGroupSid, 'assignedThroughGroupSid', 184).toUpperCase();
  if (assignedThroughGroupSid && !sidPattern.test(assignedThroughGroupSid)) throw new Error('assignedThroughGroupSid must be a valid SID.');
  if (assignedThroughGroupSid && membershipScope !== 'Transitive') {
    throw new Error('assignedThroughGroupSid requires Transitive membership.');
  }
  const deviceScopeType = choice(input.deviceScopeType, 'deviceScopeType', ['Any', 'ExactComputer', 'ComputerPrefix'] as const, 'Any');
  const deviceScopeValue = optionalText(input.deviceScopeValue, 'deviceScopeValue', 64);
  if (deviceScopeType === 'Any' && deviceScopeValue) throw new Error('deviceScopeValue requires a scoped deviceScopeType.');
  if (deviceScopeType !== 'Any' && !/^[A-Za-z0-9._-]{1,64}$/.test(deviceScopeValue)) {
    throw new Error('deviceScopeValue must contain 1 to 64 letters, numbers, periods, underscores, or hyphens. Wildcards are not supported.');
  }
  const joinStates = ['allowedEntraJoined', 'allowedHybridJoined', 'allowedDomainJoined'] as const;
  for (const name of joinStates) {
    if (typeof input[name] !== 'boolean') throw new Error(`${name} must be an explicit boolean.`);
  }
  if (!joinStates.some(name => input[name] === true)) throw new Error('At least one join state must be allowed.');
  let maxDeviceAgeDays: number | undefined;
  if (input.maxDeviceAgeDays !== undefined && input.maxDeviceAgeDays !== null && input.maxDeviceAgeDays !== '') {
    maxDeviceAgeDays = Number(input.maxDeviceAgeDays);
    if (!Number.isInteger(maxDeviceAgeDays) || maxDeviceAgeDays < 1 || maxDeviceAgeDays > 3650) {
      throw new Error('maxDeviceAgeDays must be a whole number from 1 to 3650.');
    }
  }
  const validFrom = optionalDate(input.validFromUtc, 'validFromUtc');
  const validUntil = optionalDate(input.validUntilUtc, 'validUntilUtc');
  if (validUntil && validUntil <= now) throw new Error('validUntilUtc must be in the future.');
  if (validFrom && validUntil && validUntil <= validFrom) throw new Error('validUntilUtc must be later than validFromUtc.');
  const reason = typeof input.reason === 'string' ? input.reason.trim() : '';
  if (reason.length < 10 || reason.length > 2000) throw new Error('reason must contain between 10 and 2000 characters.');
  const ticketReference = optionalText(input.ticketReference, 'ticketReference', 100);
  const owner = optionalText(input.owner, 'owner', 200);
  return {
    Effect: choice(input.effect, 'effect', ['Allow', 'Deny'] as const),
    PrincipalType: choice(input.principalType, 'principalType', ['User', 'Group'] as const),
    MatchType: 'SID',
    PrincipalValue: principalValue,
    PrincipalSource: choice(input.principalSource, 'principalSource', ['Local', 'Entra', 'AD', 'Any'] as const, 'Any'),
    MembershipScope: membershipScope,
    ...(assignedThroughGroupSid ? { AssignedThroughGroupSid: assignedThroughGroupSid } : {}),
    DeviceScopeType: deviceScopeType,
    DeviceScopeValue: deviceScopeValue,
    AllowedEntraJoined: input.allowedEntraJoined as boolean,
    AllowedHybridJoined: input.allowedHybridJoined as boolean,
    AllowedDomainJoined: input.allowedDomainJoined as boolean,
    ...(maxDeviceAgeDays !== undefined ? { MaxDeviceAgeDays: maxDeviceAgeDays } : {}),
    ...(validFrom ? { ValidFromUtc: validFrom.toISOString() } : {}),
    ...(validUntil ? { ValidUntilUtc: validUntil.toISOString() } : {}),
    Reason: reason,
    ...(ticketReference ? { TicketReference: ticketReference } : {}),
    ...(owner ? { Owner: owner } : {})
  };
}

export function validateTransitionNote(value: unknown, transition: RuleTransition): string {
  const body = value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
  const note = typeof body.reason === 'string' ? body.reason.trim() : '';
  if (controlCharacters.test(note.replace(/[\r\n\t]/g, ''))) throw new Error('reason must not contain control characters.');
  if (transition === 'approve') {
    if (note.length > 2000) throw new Error('reason must be at most 2000 characters.');
    return note;
  }
  if (note.length < 10 || note.length > 2000) throw new Error('reason must contain between 10 and 2000 characters.');
  return note;
}
