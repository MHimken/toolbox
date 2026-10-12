import { randomUUID } from 'node:crypto';
import { adminModeRoles, effectiveRoles, requireAdminMode, requireEntra, type AdminSession } from './adminMode.js';
import type { AppConfig } from './config.js';
import { ApiError, isTableStatus } from './errors.js';
import type { CallerIdentity } from './identity.js';
import type { GovernanceRepository } from './repositories.js';

export class AdminSessionService {
  constructor(
    private readonly repository: GovernanceRepository,
    private readonly config: AppConfig,
    private readonly now: () => Date = () => new Date()
  ) {}

  async enter(identity: CallerIdentity, correlationId: string): Promise<AdminSession> {
    const session = requireAdminMode(identity, this.config, this.now(), adminModeRoles);
    try {
      // Deterministic event ID: repeated enter calls with the same token produce one audit record.
      await this.repository.writeAudit({
        eventId: `admin-session-${session.sessionId}`,
        correlationId,
        occurredAtUtc: session.issuedAtUtc,
        actorOwnerKey: identity.ownerKey,
        authenticationType: 'Entra',
        operation: 'AdminModeEntered',
        entityType: 'AdminSession',
        entityId: session.sessionId,
        outcome: 'Succeeded',
        resultingState: 'Active',
        actorRoles: effectiveRoles(identity).join(','),
        adminSessionId: session.sessionId,
        authContextId: session.authContextId,
        detailsJson: JSON.stringify({ expiresAtUtc: session.expiresAtUtc }),
        schemaVersion: 1
      });
    } catch (error) {
      if (!isTableStatus(error, 409)) {
        throw new ApiError(503, 'audit_write_failed', 'Admin mode could not be audited and was not established.');
      }
    }
    return session;
  }

  async exit(identity: CallerIdentity, correlationId: string, reason: string): Promise<void> {
    requireEntra(identity, 'Admin mode applies only to Microsoft Entra identities.');
    let session: AdminSession | null = null;
    try {
      session = requireAdminMode(identity, this.config, this.now(), adminModeRoles);
    } catch {
      // Exiting must always succeed; an expired or unprivileged token is recorded without a session ID.
    }
    const normalizedReason = ['user', 'idle', 'expired', 'signout', 'account_changed'].includes(reason) ? reason : 'user';
    try {
      await this.repository.writeAudit({
        eventId: randomUUID(),
        correlationId,
        occurredAtUtc: this.now().toISOString(),
        actorOwnerKey: identity.ownerKey,
        authenticationType: 'Entra',
        operation: 'AdminModeExited',
        entityType: 'AdminSession',
        entityId: session?.sessionId || 'unknown',
        outcome: 'Succeeded',
        resultingState: 'Ended',
        actorRoles: effectiveRoles(identity).join(','),
        ...(session ? { adminSessionId: session.sessionId, authContextId: session.authContextId } : {}),
        detailsJson: JSON.stringify({ reason: normalizedReason }),
        schemaVersion: 1
      });
    } catch {
      throw new ApiError(503, 'audit_write_failed', 'Admin mode ended locally, but the exit could not be audited.', {
        mutationCommitted: true
      });
    }
  }
}
