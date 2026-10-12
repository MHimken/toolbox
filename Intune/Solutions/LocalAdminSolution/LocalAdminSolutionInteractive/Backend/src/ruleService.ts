import { createHash, randomUUID } from 'node:crypto';
import {
  AppRoles,
  effectiveRoles,
  governanceReaderRoles,
  hasRole,
  requireAdminMode,
  requireAnyRole,
  type AdminSession
} from './adminMode.js';
import type { AppConfig } from './config.js';
import { ApiError, isTableStatus } from './errors.js';
import type { CallerIdentity } from './identity.js';
import type { AuditRecord } from './models.js';
import type { EntityPatch, GovernanceRepository } from './repositories.js';
import {
  governancePartition,
  ruleSchemaVersion,
  validateGovernanceProposal,
  validateTransitionNote,
  type AllowRule,
  type RuleTransition
} from './ruleModels.js';

const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const proposerRoles = [AppRoles.GovernanceRead, AppRoles.GovernanceApprove, AppRoles.GovernanceSelfApprove] as const;

const transitions: Record<RuleTransition, { from: readonly string[]; to: string; prefix: string; operation: string }> = {
  approve: { from: ['PendingApproval'], to: 'Active', prefix: 'Approved', operation: 'GovernanceRuleApproved' },
  reject: { from: ['PendingApproval'], to: 'Rejected', prefix: 'Rejected', operation: 'GovernanceRuleRejected' },
  revoke: { from: ['Active', 'PendingApproval'], to: 'Revoked', prefix: 'Revoked', operation: 'GovernanceRuleRevoked' }
};

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export function actorDisplayName(identity: CallerIdentity): string {
  for (const claim of ['preferred_username', 'upn', 'name']) {
    const value = identity.claims?.[claim];
    if (typeof value === 'string' && value.trim()) return value.trim().slice(0, 200);
  }
  return identity.ownerKey;
}

/** Hash of the security-relevant fields so audit records can prove what changed without copying the entity. */
export function ruleStateHash(rule: AllowRule): string {
  const fields = [
    'RuleScope', 'Effect', 'PrincipalType', 'MatchType', 'PrincipalValue', 'PrincipalSource', 'MembershipScope',
    'AssignedThroughGroupSid', 'DeviceScopeType', 'DeviceScopeValue', 'AllowedEntraJoined', 'AllowedHybridJoined',
    'AllowedDomainJoined', 'MaxDeviceAgeDays', 'ValidFromUtc', 'ValidUntilUtc', 'Status'
  ];
  return digest(JSON.stringify(fields.map(field => [field, rule[field] ?? null])));
}

function safeMetadata(rule: AllowRule) {
  return {
    ruleId: rule.RowKey,
    status: rule.Status,
    etag: rule.ETag || '',
    updatedAtUtc: typeof rule.UpdatedAtUtc === 'string' ? rule.UpdatedAtUtc : ''
  };
}

export class RuleService {
  constructor(
    private readonly repository: GovernanceRepository,
    private readonly config: AppConfig,
    private readonly now: () => Date = () => new Date()
  ) {}

  async list(identity: CallerIdentity, scope: string): Promise<{ scope: string; rules: AllowRule[] }> {
    if (scope === 'mine') {
      return { scope, rules: await this.repository.listRules(identity.ownerKey) };
    }
    if (scope !== 'governance') throw new ApiError(400, 'invalid_scope', 'scope must be mine or governance.');
    requireAnyRole(identity, governanceReaderRoles, 'A governance API role is required to read organization rules.');
    return { scope, rules: await this.repository.listRules(governancePartition) };
  }

  async propose(
    identity: CallerIdentity,
    payload: unknown,
    idempotencyKey: string,
    correlationId: string
  ): Promise<{ rule: AllowRule; replay: boolean }> {
    requireAnyRole(identity, proposerRoles, 'A governance API role is required to propose organization rules.');
    if (!uuidPattern.test(idempotencyKey)) {
      throw new ApiError(400, 'invalid_idempotency_key', 'Idempotency-Key must be a random UUID.');
    }
    const now = this.now();
    let proposal: ReturnType<typeof validateGovernanceProposal>;
    try {
      proposal = validateGovernanceProposal(payload, now);
    } catch (error) {
      throw new ApiError(400, 'invalid_request', error instanceof Error ? error.message : 'The rule proposal is invalid.');
    }
    const ruleId = idempotencyKey.toLowerCase();
    const fingerprint = digest(JSON.stringify(proposal));
    const createdAtUtc = now.toISOString();
    const rule: AllowRule = {
      PartitionKey: governancePartition,
      RowKey: ruleId,
      RuleScope: 'Governance',
      Status: 'PendingApproval',
      ...proposal,
      CreatedAtUtc: createdAtUtc,
      CreatedBy: actorDisplayName(identity),
      CreatedByOwnerKey: identity.ownerKey,
      UpdatedAtUtc: createdAtUtc,
      CorrelationId: correlationId,
      ProposalFingerprint: fingerprint,
      SchemaVersion: ruleSchemaVersion
    };

    let stored: AllowRule;
    let replay = false;
    try {
      stored = await this.repository.createRule(rule);
    } catch (error) {
      if (!isTableStatus(error, 409)) throw error;
      const existing = await this.repository.getRule(governancePartition, ruleId);
      if (!existing || existing.CreatedByOwnerKey !== identity.ownerKey || existing.ProposalFingerprint !== fingerprint) {
        throw new ApiError(409, 'idempotency_conflict', 'This Idempotency-Key was already used for a different request.');
      }
      stored = existing;
      replay = true;
    }

    await this.audit({
      eventId: `rule-proposed-${ruleId}`,
      correlationId: typeof stored.CorrelationId === 'string' ? stored.CorrelationId : correlationId,
      occurredAtUtc: typeof stored.CreatedAtUtc === 'string' ? stored.CreatedAtUtc : createdAtUtc,
      actorOwnerKey: identity.ownerKey,
      authenticationType: 'Entra',
      operation: 'GovernanceRuleProposed',
      entityType: 'AllowRule',
      entityId: `${governancePartition}/${ruleId}`,
      outcome: 'Succeeded',
      resultingState: `PendingApproval:${ruleStateHash(stored)}`,
      actorRoles: effectiveRoles(identity).join(','),
      detailsJson: JSON.stringify({
        idempotencyKey: ruleId,
        effect: stored.Effect,
        principalSid: stored.PrincipalValue,
        reason: stored.Reason,
        ticketReference: stored.TicketReference ?? null
      }),
      schemaVersion: 1
    }, stored.RowKey);
    return { rule: stored, replay };
  }

  async transition(
    identity: CallerIdentity,
    ruleId: string,
    transition: RuleTransition,
    payload: unknown,
    ifMatch: string | undefined,
    correlationId: string
  ): Promise<AllowRule> {
    const definition = transitions[transition];
    const session = requireAdminMode(identity, this.config, this.now(), [AppRoles.GovernanceApprove]);
    if (!ifMatch) throw new ApiError(428, 'etag_required', 'If-Match is required.');
    if (ifMatch.trim() === '*') throw new ApiError(400, 'invalid_precondition', 'Wildcard If-Match is not accepted.');
    let note: string;
    try {
      note = validateTransitionNote(payload, transition);
    } catch (error) {
      throw new ApiError(400, 'invalid_request', error instanceof Error ? error.message : 'The request is invalid.');
    }
    if (!uuidPattern.test(ruleId)) throw new ApiError(404, 'rule_not_found', 'The rule was not found.');
    const current = await this.repository.getRule(governancePartition, ruleId);
    if (!current || current.RuleScope !== 'Governance') throw new ApiError(404, 'rule_not_found', 'The rule was not found.');
    if (current.ETag !== ifMatch) {
      throw new ApiError(412, 'etag_conflict', 'The rule changed. Reload it before continuing.', safeMetadata(current));
    }
    if (!definition.from.includes(current.Status)) {
      throw new ApiError(409, 'invalid_transition', `A ${current.Status} rule cannot be ${definition.to.toLowerCase()}.`, safeMetadata(current));
    }

    const now = this.now();
    let selfApproved = false;
    if (transition === 'approve') {
      const validUntil = typeof current.ValidUntilUtc === 'string' ? new Date(current.ValidUntilUtc) : null;
      if (validUntil && !Number.isNaN(validUntil.getTime()) && validUntil <= now) {
        throw new ApiError(409, 'rule_expired', 'The proposal validity already ended. Reject it and submit a new proposal.', safeMetadata(current));
      }
      if (current.CreatedByOwnerKey === identity.ownerKey) {
        if (!hasRole(identity, AppRoles.GovernanceSelfApprove)) {
          throw new ApiError(
            403,
            'four_eyes_required',
            'You proposed this rule. Another approver must approve it, or the LocalAdmin.Governance.SelfApprove role must be assigned to you.'
          );
        }
        selfApproved = true;
      }
    }

    const occurredAtUtc = now.toISOString();
    const patch: EntityPatch = {
      Status: definition.to,
      UpdatedAtUtc: occurredAtUtc,
      [`${definition.prefix}By`]: actorDisplayName(identity),
      [`${definition.prefix}ByOwnerKey`]: identity.ownerKey,
      [`${definition.prefix}AtUtc`]: occurredAtUtc,
      [`${definition.prefix}AdminSessionId`]: session.sessionId,
      ...(note ? { [transition === 'approve' ? 'ApprovalComment' : `${transition === 'reject' ? 'Rejection' : 'Revocation'}Reason`]: note } : {}),
      ...(transition === 'approve' ? { SelfApproved: selfApproved } : {})
    };

    let updated: AllowRule;
    try {
      updated = await this.repository.updateRule(governancePartition, ruleId, patch, ifMatch);
    } catch (error) {
      if (isTableStatus(error, 404)) throw new ApiError(404, 'rule_not_found', 'The rule was not found.');
      if (isTableStatus(error, 412)) {
        const latest = await this.repository.getRule(governancePartition, ruleId);
        throw new ApiError(412, 'etag_conflict', 'The rule changed. Reload it before continuing.', latest ? safeMetadata(latest) : undefined);
      }
      throw error;
    }

    await this.audit({
      eventId: randomUUID(),
      correlationId,
      occurredAtUtc,
      actorOwnerKey: identity.ownerKey,
      authenticationType: 'Entra',
      operation: definition.operation,
      entityType: 'AllowRule',
      entityId: `${governancePartition}/${ruleId}`,
      outcome: 'Succeeded',
      previousState: `${current.Status}:${ruleStateHash(current)}`,
      resultingState: `${updated.Status}:${ruleStateHash(updated)}`,
      ...this.sessionAudit(identity, session),
      detailsJson: JSON.stringify({
        reason: note || null,
        selfApproved,
        proposedByOwnerKey: current.CreatedByOwnerKey ?? null,
        ticketReference: current.TicketReference ?? null
      }),
      schemaVersion: 1
    }, ruleId);
    return updated;
  }

  private sessionAudit(identity: CallerIdentity, session: AdminSession) {
    return {
      actorRoles: effectiveRoles(identity).join(','),
      adminSessionId: session.sessionId,
      authContextId: session.authContextId
    };
  }

  private async audit(record: AuditRecord, ruleId: string): Promise<void> {
    try {
      await this.repository.writeAudit(record);
    } catch (error) {
      if (isTableStatus(error, 409)) return;
      throw new ApiError(
        503,
        'audit_write_failed',
        'The rule changed, but its audit record could not be written. Reload the rules before retrying.',
        { mutationCommitted: true, ruleId }
      );
    }
  }
}
