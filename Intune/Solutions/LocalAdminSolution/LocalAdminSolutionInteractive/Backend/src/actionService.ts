import { createHash, randomUUID } from 'node:crypto';
import { AppRoles, effectiveRoles, governanceReaderRoles, requireAdminMode, requireAnyRole } from './adminMode.js';
import type { AppConfig } from './config.js';
import { ApiError, isTableStatus } from './errors.js';
import type { CallerIdentity } from './identity.js';
import type { AuditRecord, ReviewActionRecord } from './models.js';
import { cancellableActionStatuses, validateGovernanceExceptionRequest } from './models.js';
import type { GovernanceRepository } from './repositories.js';
import { actorDisplayName } from './ruleService.js';

const schemaVersion = 1;
const personalActionLimit = 500;
const organizationActionLimit = 2000;

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function requestFingerprint(
  request: ReturnType<typeof validateGovernanceExceptionRequest>
): string {
  return digest(JSON.stringify(request));
}

export class ActionService {
  constructor(
    private readonly repository: GovernanceRepository,
    private readonly config: AppConfig,
    private readonly now: () => Date = () => new Date()
  ) {}

  async list(identity: CallerIdentity, scope: string): Promise<{ scope: string; actions: ReviewActionRecord[]; truncated: boolean }> {
    if (scope === 'mine') {
      return { scope, ...(await this.repository.listReviewActions(identity.ownerKey, personalActionLimit)) };
    }
    if (scope !== 'all') throw new ApiError(400, 'invalid_scope', 'scope must be mine or all.');
    requireAnyRole(identity, governanceReaderRoles, 'A governance API role is required to read the organization action queue.');
    return { scope, ...(await this.repository.listReviewActions(null, organizationActionLimit)) };
  }

  async cancel(
    identity: CallerIdentity,
    actionId: string,
    payload: unknown,
    ifMatch: string | undefined,
    correlationId: string
  ): Promise<ReviewActionRecord> {
    const body = payload && typeof payload === 'object' && !Array.isArray(payload) ? payload as Record<string, unknown> : {};
    const targetOwner = typeof body.ownerKey === 'string' && body.ownerKey.trim() ? body.ownerKey.trim() : identity.ownerKey;
    const operatorCancel = targetOwner !== identity.ownerKey;
    const session = operatorCancel
      ? requireAdminMode(identity, this.config, this.now(), [AppRoles.ActionsOperate])
      : null;
    if (!ifMatch) throw new ApiError(428, 'etag_required', 'If-Match is required.');
    if (ifMatch.trim() === '*') throw new ApiError(400, 'invalid_precondition', 'Wildcard If-Match is not accepted.');
    const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
    if (reason.length < 10 || reason.length > 2000) {
      throw new ApiError(400, 'invalid_request', 'reason must contain between 10 and 2000 characters.');
    }
    if (!/^[A-Za-z0-9-]{1,64}$/.test(actionId)) throw new ApiError(404, 'action_not_found', 'The action was not found.');
    const current = await this.repository.getReviewAction(targetOwner, actionId);
    if (!current) throw new ApiError(404, 'action_not_found', 'The action was not found.');
    const metadata = { actionId, status: current.status, etag: current.etag || '' };
    if (current.etag !== ifMatch) throw new ApiError(412, 'etag_conflict', 'The action changed. Reload it before continuing.', metadata);
    if (!cancellableActionStatuses.includes(current.status)) {
      throw new ApiError(409, 'invalid_transition', `A ${current.status} action can no longer be cancelled.`, metadata);
    }
    const occurredAtUtc = this.now().toISOString();
    let updated: ReviewActionRecord;
    try {
      updated = await this.repository.updateReviewAction(targetOwner, actionId, {
        Status: 'Cancelled',
        UpdatedAtUtc: occurredAtUtc,
        CancelledBy: actorDisplayName(identity),
        CancelledByOwnerKey: identity.ownerKey,
        CancelledAtUtc: occurredAtUtc,
        CancellationReason: reason,
        ...(session ? { CancelledByAdminSessionId: session.sessionId } : {})
      }, ifMatch);
    } catch (error) {
      if (isTableStatus(error, 404)) throw new ApiError(404, 'action_not_found', 'The action was not found.');
      if (isTableStatus(error, 412)) throw new ApiError(412, 'etag_conflict', 'The action changed. Reload it before continuing.', metadata);
      throw error;
    }
    try {
      await this.repository.writeAudit({
        eventId: randomUUID(),
        correlationId,
        occurredAtUtc,
        actorOwnerKey: identity.ownerKey,
        authenticationType: identity.authenticationType,
        operation: operatorCancel ? 'ReviewActionCancelledByOperator' : 'ReviewActionCancelled',
        entityType: 'ReviewAction',
        entityId: `${targetOwner}/${actionId}`,
        outcome: 'Succeeded',
        previousState: current.status,
        resultingState: 'Cancelled',
        actorRoles: effectiveRoles(identity).join(','),
        ...(session ? { adminSessionId: session.sessionId, authContextId: session.authContextId } : {}),
        detailsJson: JSON.stringify({ reason, actionType: current.actionType }),
        schemaVersion
      });
    } catch {
      throw new ApiError(
        503,
        'audit_write_failed',
        'The action was cancelled, but its audit record could not be written. Reload the queue before retrying.',
        { mutationCommitted: true, actionId }
      );
    }
    return updated;
  }

  async requestGovernanceException(
    identity: CallerIdentity,
    payload: unknown,
    idempotencyKey: string,
    correlationId: string
  ): Promise<{ action: ReviewActionRecord; replay: boolean }> {
    if (identity.authenticationType !== 'Entra') {
      throw new ApiError(403, 'entra_identity_required', 'An authenticated Microsoft Entra identity is required to submit a governance request.');
    }
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(idempotencyKey)) {
      throw new ApiError(400, 'invalid_idempotency_key', 'Idempotency-Key must be a UUID.');
    }

    let request: ReturnType<typeof validateGovernanceExceptionRequest>;
    try {
      request = validateGovernanceExceptionRequest(payload);
    } catch (error) {
      throw new ApiError(400, 'invalid_request', error instanceof Error ? error.message : 'The request is invalid.');
    }

    const keyDigest = digest(`${identity.ownerKey}\0${idempotencyKey.toLowerCase()}`);
    const fingerprint = requestFingerprint(request);
    const existing = await this.repository.getReviewAction(identity.ownerKey, keyDigest);
    if (existing) {
      const replay = this.resolveReplay(existing, fingerprint);
      await this.ensureAudit(replay, fingerprint);
      return { action: replay, replay: true };
    }

    const record: ReviewActionRecord = {
      actionId: keyDigest,
      idempotencyKey: keyDigest,
      actionType: 'RequestGovernanceException',
      status: 'Requested',
      ...request,
      expectedChange: 'Governance exception review requested; no endpoint or directory change will be performed.',
      requestedByOwnerKey: identity.ownerKey,
      correlationId,
      createdAtUtc: this.now().toISOString(),
      schemaVersion
    };

    try {
      await this.repository.createReviewAction(identity.ownerKey, record);
    } catch (error) {
      if (!isTableStatus(error, 409)) throw error;
      const concurrent = await this.repository.getReviewAction(identity.ownerKey, keyDigest);
      if (!concurrent) throw error;
      const replay = this.resolveReplay(concurrent, fingerprint);
      await this.ensureAudit(replay, fingerprint);
      return { action: replay, replay: true };
    }

    await this.ensureAudit(record, fingerprint);
    return { action: (await this.repository.getReviewAction(identity.ownerKey, keyDigest)) || record, replay: false };
  }

  private async ensureAudit(record: ReviewActionRecord, fingerprint: string): Promise<void> {
    const audit: AuditRecord = {
      eventId: record.actionId,
      correlationId: record.correlationId,
      occurredAtUtc: record.createdAtUtc,
      actorOwnerKey: record.requestedByOwnerKey,
      authenticationType: 'Entra',
      operation: 'GovernanceExceptionRequested',
      entityType: 'ReviewAction',
      entityId: record.actionId,
      outcome: 'Succeeded',
      resultingState: fingerprint,
      schemaVersion
    };
    try {
      await this.repository.writeAudit(audit);
    } catch (error) {
      if (isTableStatus(error, 409)) return;
      throw new ApiError(
        503,
        'audit_write_failed',
        'The request was recorded, but its audit record could not be written. Reload the request before retrying.',
        { mutationCommitted: true, actionId: record.actionId }
      );
    }
  }

  private resolveReplay(record: ReviewActionRecord, fingerprint: string): ReviewActionRecord {
    if (requestFingerprint({
      targetComputerSid: record.targetComputerSid,
      targetPrincipalId: record.targetPrincipalId,
      justification: record.justification,
      ...(record.ticketReference ? { ticketReference: record.ticketReference } : {})
    }) !== fingerprint) {
      throw new ApiError(409, 'idempotency_conflict', 'This Idempotency-Key was already used for a different request.');
    }
    return record;
  }
}
