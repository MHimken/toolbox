import { normalizedSource, ruleMatches } from './apiContract.js';
import { ProfileApiError } from './profileClient.js';

export const adminIdleTimeoutMinutes = 15;
export const adminSessionExpiryCodes = Object.freeze(['admin_auth_context_required', 'admin_session_expired']);

const sidPattern = /^S-\d(?:-\d+)+$/i;
const deviceValuePattern = /^[A-Za-z0-9._-]{1,64}$/;

export function normalizeSidInput(value) {
  return String(value || '').trim().replace(/[\u2010\u2011]/g, '-').toUpperCase();
}

function newIdempotencyKey() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  throw new Error('This browser cannot create a secure request identifier.');
}

export class AdminClient {
  constructor(profileClient) {
    if (!profileClient?.request) throw new Error('Admin mode requires the protected BFF client.');
    this.client = profileClient;
  }

  async enterSession(authentication) {
    return (await this.client.request('POST', '/sessions/admin', authentication, { body: {} })).payload;
  }

  async exitSession(authentication, reason = 'user') {
    await this.client.request('DELETE', `/sessions/admin?reason=${encodeURIComponent(reason)}`, authentication);
  }

  async listRules(authentication, scope = 'governance') {
    return (await this.client.request('GET', `/rules?scope=${encodeURIComponent(scope)}`, authentication)).payload;
  }

  async proposeRule(authentication, proposal, idempotencyKey = newIdempotencyKey()) {
    const result = await this.client.request('POST', '/rules', authentication, { body: proposal, idempotencyKey });
    return { rule: result.payload, replay: result.status === 200 };
  }

  async transitionRule(authentication, ruleId, operation, reason, etag) {
    if (!['approve', 'reject', 'revoke'].includes(operation)) throw new Error('Unsupported rule operation.');
    const result = await this.client.request(
      'POST',
      `/rules/${encodeURIComponent(ruleId)}/${operation}`,
      authentication,
      { body: reason ? { reason } : {}, etag }
    );
    return result.payload;
  }

  async listActions(authentication, scope = 'mine') {
    return (await this.client.request('GET', `/actions?scope=${encodeURIComponent(scope)}`, authentication)).payload;
  }

  async cancelAction(authentication, actionId, { ownerKey, reason }, etag) {
    const result = await this.client.request(
      'POST',
      `/actions/${encodeURIComponent(actionId)}/cancel`,
      authentication,
      { body: { reason, ...(ownerKey ? { ownerKey } : {}) }, etag }
    );
    return result.payload;
  }
}

export function isAdminSessionError(error) {
  return error instanceof ProfileApiError && error.status === 401 && adminSessionExpiryCodes.includes(error.code);
}

export class AdminModeController {
  constructor({
    client,
    auth,
    onChange = () => {},
    onCountdown = () => {},
    now = () => Date.now(),
    setTimer = globalThis.setTimeout?.bind(globalThis),
    clearTimer = globalThis.clearTimeout?.bind(globalThis),
    idleTimeoutMs = adminIdleTimeoutMinutes * 60_000
  }) {
    this.client = client;
    this.auth = auth;
    this.onChange = onChange;
    this.onCountdown = onCountdown;
    this.now = now;
    this.setTimer = setTimer;
    this.clearTimer = clearTimer;
    this.idleTimeoutMs = idleTimeoutMs;
    this.session = null;
    this.token = '';
    this.accountId = '';
    this.idleTimer = null;
    this.expiryTimer = null;
    this.countdownTimer = null;
    this.idleExpiresAt = 0;
  }

  get active() {
    return Boolean(this.session && this.token && Date.parse(this.session.expiresAtUtc) > this.now());
  }

  get capabilities() {
    return this.active ? { ...this.session.capabilities } : { readGovernance: false, approveRules: false, selfApprove: false, operateActions: false };
  }

  authentication() {
    if (!this.active) throw new Error('Admin mode is not active.');
    this.touch();
    const token = this.token;
    return { type: 'entra', getAccessToken: async () => token };
  }

  async enter() {
    const account = this.auth?.getAccount?.();
    if (!account) throw new Error('Sign in with Microsoft Entra before entering Admin mode.');
    let token = await this.auth.getAccessToken();
    let session;
    try {
      session = await this.client.enterSession({ type: 'entra', getAccessToken: async () => token });
    } catch (error) {
      if (!isAdminSessionError(error) || typeof error.details?.claims !== 'string') throw error;
      token = await this.auth.getClaimsChallengeToken(error.details.claims);
      session = await this.client.enterSession({ type: 'entra', getAccessToken: async () => token });
    }
    if (!session?.sessionId || !session.expiresAtUtc || Number.isNaN(Date.parse(session.expiresAtUtc))) {
      throw new Error('The backend returned an invalid Admin-mode session.');
    }
    this.session = session;
    this.token = token;
    this.accountId = account.homeAccountId || account.username || '';
    this.scheduleExpiry();
    this.touch();
    this.onChange({ active: true, session });
    return session;
  }

  touch() {
    if (!this.session) return;
    if (this.idleTimer) this.clearTimer(this.idleTimer);
    this.idleExpiresAt = this.now() + this.idleTimeoutMs;
    this.idleTimer = this.setTimer(() => { void this.exit('idle'); }, this.idleTimeoutMs);
    this.updateCountdown();
  }

  updateCountdown() {
    if (this.countdownTimer) this.clearTimer(this.countdownTimer);
    this.countdownTimer = null;
    const now = this.now();
    const remaining = Math.max(0, this.idleExpiresAt - now);
    const totalRemaining = this.session ? Math.max(0, Date.parse(this.session.expiresAtUtc) - now) : 0;
    this.onCountdown(remaining, totalRemaining);
    if (this.session && remaining > 0 && totalRemaining > 0) {
      this.countdownTimer = this.setTimer(() => this.updateCountdown(), Math.min(1000, remaining, totalRemaining));
    }
  }

  scheduleExpiry() {
    if (this.expiryTimer) this.clearTimer(this.expiryTimer);
    const remaining = Math.max(0, Date.parse(this.session.expiresAtUtc) - this.now());
    this.expiryTimer = this.setTimer(() => { void this.exit('expired'); }, remaining);
  }

  accountChanged(account) {
    const id = account?.homeAccountId || account?.username || '';
    return Boolean(this.session) && id !== this.accountId;
  }

  async exit(reason = 'user') {
    if (!this.session) return;
    const token = this.token;
    const session = this.session;
    if (this.idleTimer) this.clearTimer(this.idleTimer);
    if (this.expiryTimer) this.clearTimer(this.expiryTimer);
    if (this.countdownTimer) this.clearTimer(this.countdownTimer);
    this.idleTimer = this.expiryTimer = null;
    this.countdownTimer = null;
    this.idleExpiresAt = 0;
    this.session = null;
    this.token = '';
    this.accountId = '';
    this.onCountdown(0, 0);
    this.onChange({ active: false, reason, session });
    try {
      await this.client.exitSession({ type: 'entra', getAccessToken: async () => token }, reason);
    } catch {
      // The session already ended locally; the backend audit of the exit is best effort.
    }
  }
}

function joinFlags(joinState) {
  const value = String(joinState || '');
  return {
    allowedEntraJoined: value === 'Entra joined',
    allowedHybridJoined: value === 'Hybrid joined',
    allowedDomainJoined: value === 'Domain joined'
  };
}

export function proposalFromReviewRow(row) {
  const flags = joinFlags(row?.JoinState);
  const anyJoin = !flags.allowedEntraJoined && !flags.allowedHybridJoined && !flags.allowedDomainJoined;
  const source = normalizedSource(row?.PrincipalSource);
  const membership = String(row?.MembershipType || '');
  const groupSid = String(row?.AssignedThroughGroupSid || row?._AssignedThroughGroupSID || '');
  return {
    effect: 'Allow',
    principalType: row?.PrincipalType === 'Group' ? 'Group' : 'User',
    principalSid: String(row?.PrincipalID || row?.SID || ''),
    principalDisplayName: String(row?.PrincipalName || row?.UserName || row?.GroupName || ''),
    principalUserPrincipalName: String(row?.UserPrincipalName || ''),
    principalSource: ['Local', 'Entra', 'AD'].includes(source) ? source : 'Any',
    membershipScope: groupSid ? 'Transitive' : (['Direct', 'Transitive'].includes(membership) ? membership : 'Any'),
    ...(groupSid ? { assignedThroughGroupSid: groupSid } : {}),
    deviceScopeType: row?.ComputerName ? 'ExactComputer' : 'Any',
    ...(row?.ComputerName ? { deviceScopeValue: String(row.ComputerName) } : {}),
    allowedEntraJoined: anyJoin || flags.allowedEntraJoined,
    allowedHybridJoined: anyJoin || flags.allowedHybridJoined,
    allowedDomainJoined: anyJoin || flags.allowedDomainJoined,
    reason: ''
  };
}

export function validateProposalDraft(proposal, now = new Date()) {
  const errors = [];
  if (!['Allow', 'Deny'].includes(proposal.effect)) errors.push('Choose Allow or Deny.');
  if (!['User', 'Group'].includes(proposal.principalType)) errors.push('Choose a principal type.');
  if (!sidPattern.test(normalizeSidInput(proposal.principalSid))) errors.push('Principal SID must be a valid SID (S-1-...).');
  if (proposal.assignedThroughGroupSid && !sidPattern.test(normalizeSidInput(proposal.assignedThroughGroupSid))) errors.push('Assigned-through group must be a valid SID.');
  if (proposal.assignedThroughGroupSid && proposal.membershipScope !== 'Transitive') errors.push('An assigned-through group requires Transitive membership.');
  if (proposal.deviceScopeType !== 'Any' && !deviceValuePattern.test(String(proposal.deviceScopeValue || ''))) {
    errors.push('Device value must contain 1 to 64 letters, numbers, dots, underscores, or hyphens (no wildcards).');
  }
  if (!proposal.allowedEntraJoined && !proposal.allowedHybridJoined && !proposal.allowedDomainJoined) errors.push('Allow at least one join state.');
  if (proposal.maxDeviceAgeDays !== undefined && (!Number.isInteger(proposal.maxDeviceAgeDays) || proposal.maxDeviceAgeDays < 1 || proposal.maxDeviceAgeDays > 3650)) {
    errors.push('Maximum device age must be between 1 and 3650 days.');
  }
  const validFrom = proposal.validFromUtc ? new Date(proposal.validFromUtc) : null;
  const validUntil = proposal.validUntilUtc ? new Date(proposal.validUntilUtc) : null;
  if (validFrom && Number.isNaN(validFrom.getTime())) errors.push('Valid from is not a valid date.');
  if (validUntil && Number.isNaN(validUntil.getTime())) errors.push('Valid until is not a valid date.');
  if (validUntil && validUntil <= now) errors.push('Valid until must be in the future.');
  if (validFrom && validUntil && validUntil <= validFrom) errors.push('Valid until must be after valid from.');
  const reason = String(proposal.reason || '').trim();
  if (reason.length < 10 || reason.length > 2000) errors.push('Reason must contain 10 to 2000 characters.');
  if (String(proposal.ticketReference || '').length > 100) errors.push('Ticket reference may contain at most 100 characters.');
  return errors;
}

export function previewRuleFromProposal(proposal) {
  return {
    Effect: proposal.effect,
    PrincipalType: proposal.principalType,
    MatchType: 'SID',
    PrincipalValue: normalizeSidInput(proposal.principalSid),
    PrincipalSource: proposal.principalSource || 'Any',
    MembershipScope: proposal.membershipScope || 'Any',
    AssignedThroughGroupSid: normalizeSidInput(proposal.assignedThroughGroupSid),
    DeviceScopeType: proposal.deviceScopeType || 'Any',
    DeviceScopeValue: proposal.deviceScopeValue || '',
    AllowedEntraJoined: proposal.allowedEntraJoined === true,
    AllowedHybridJoined: proposal.allowedHybridJoined === true,
    AllowedDomainJoined: proposal.allowedDomainJoined === true,
    ...(proposal.maxDeviceAgeDays !== undefined ? { MaxDeviceAgeDays: proposal.maxDeviceAgeDays } : {})
  };
}

export function previewMatches(proposal, reviewRows) {
  const { rows, computers } = previewRuleMatches(previewRuleFromProposal(proposal), reviewRows);
  return { rows, computers };
}

export function previewRuleMatches(rule, reviewRows) {
  const entries = (reviewRows || []).filter(row => ruleMatches(rule, row));
  return {
    rows: entries.length,
    computers: new Set(entries.map(row => String(row.ComputerName || '').toLowerCase())).size,
    entries
  };
}
