import { createHash, randomUUID } from 'node:crypto';
import { ApiError } from './errors.js';
import { recoveryOwnerKey, type CallerIdentity } from './identity.js';
import {
  profileSchemaVersion,
  type AuditRecord,
  type ProfileRecord,
  type ProfileSettings
} from './models.js';
import type { GovernanceRepository } from './repositories.js';

export interface ProfileEnvelope {
  ownerKey: string;
  settings: ProfileSettings;
  createdAtUtc: string;
  updatedAtUtc: string;
  schemaVersion: number;
  etag?: string;
}

function stateHash(profile: ProfileRecord | null): string | undefined {
  return profile
    ? createHash('sha256').update(JSON.stringify({
        ownerKey: profile.ownerKey,
        settings: profile.settings,
        schemaVersion: profile.schemaVersion
      })).digest('hex')
    : undefined;
}

export class ProfileService {
  constructor(
    private readonly repository: GovernanceRepository,
    private readonly now: () => Date = () => new Date()
  ) {}

  async get(identity: CallerIdentity): Promise<ProfileEnvelope> {
    const profile = await this.repository.getProfile(identity.ownerKey);
    if (!profile) throw new ApiError(404, 'profile_not_found', 'The profile was not found.');
    return profile;
  }

  async put(
    identity: CallerIdentity,
    settings: ProfileSettings,
    etag: string | undefined,
    createOnly: boolean,
    correlationId: string
  ): Promise<ProfileEnvelope> {
    const existing = await this.repository.getProfile(identity.ownerKey);
    const timestamp = this.now().toISOString();
    if (createOnly) {
      if (existing) throw new ApiError(412, 'etag_conflict', 'The profile already exists.');
      const created = await this.repository.createProfile({
        ownerKey: identity.ownerKey,
        settings,
        createdAtUtc: timestamp,
        updatedAtUtc: timestamp,
        schemaVersion: profileSchemaVersion
      });
      await this.audit(identity, correlationId, 'ProfileCreated', created, null);
      return created;
    }
    if (!existing) throw new ApiError(404, 'profile_not_found', 'The profile was not found.');
    if (!etag) throw new ApiError(428, 'etag_required', 'If-Match is required when replacing a profile.');
    const updated = await this.repository.updateProfile(identity.ownerKey, settings, etag, timestamp);
    await this.audit(identity, correlationId, 'ProfileUpdated', updated, existing);
    return updated;
  }

  async rotateRecovery(
    identity: CallerIdentity,
    newRecoveryCode: string,
    etag: string | undefined,
    correlationId: string
  ): Promise<ProfileEnvelope> {
    if (identity.authenticationType !== 'Recovery') {
      throw new ApiError(400, 'recovery_identity_required', 'Recovery rotation requires the current recovery credential.');
    }
    if (!etag) throw new ApiError(428, 'etag_required', 'If-Match is required when rotating a recovery profile.');
    const source = await this.repository.getProfile(identity.ownerKey);
    if (!source) throw new ApiError(404, 'profile_not_found', 'The profile was not found.');
    const targetOwnerKey = recoveryOwnerKey(newRecoveryCode);
    if (targetOwnerKey === identity.ownerKey) throw new ApiError(400, 'recovery_credential_unchanged', 'The new recovery credential must differ.');
    if (await this.repository.getProfile(targetOwnerKey)) {
      throw new ApiError(409, 'recovery_owner_exists', 'The new recovery owner already exists.');
    }
    const timestamp = this.now().toISOString();
    const { etag: _sourceEtag, ...sourceWithoutEtag } = source;
    const target = await this.repository.createProfile({
      ...sourceWithoutEtag,
      ownerKey: targetOwnerKey,
      createdAtUtc: timestamp,
      updatedAtUtc: timestamp
    });
    try {
      await this.repository.deleteProfile(identity.ownerKey, etag);
    } catch (error) {
      try {
        if (target.etag) await this.repository.deleteProfile(targetOwnerKey, target.etag);
      } catch {
        throw new ApiError(
          503,
          'recovery_rotation_partial_failure',
          'Recovery rotation could not remove the old owner or roll back the new owner. Administrative reconciliation is required.'
        );
      }
      throw error;
    }
    await this.audit(identity, correlationId, 'RecoveryRotated', target, source);
    return target;
  }

  async revokeRecovery(identity: CallerIdentity, etag: string | undefined, correlationId: string): Promise<void> {
    if (identity.authenticationType !== 'Recovery') {
      throw new ApiError(400, 'recovery_identity_required', 'Recovery revocation requires the recovery credential.');
    }
    if (!etag) throw new ApiError(428, 'etag_required', 'If-Match is required when revoking a recovery profile.');
    const source = await this.repository.getProfile(identity.ownerKey);
    if (!source) throw new ApiError(404, 'profile_not_found', 'The profile was not found.');
    await this.repository.deleteProfile(identity.ownerKey, etag);
    await this.audit(identity, correlationId, 'RecoveryRevoked', null, source);
  }

  private async audit(
    identity: CallerIdentity,
    correlationId: string,
    operation: string,
    resulting: ProfileRecord | null,
    previous: ProfileRecord | null
  ): Promise<void> {
    const occurredAtUtc = this.now().toISOString();
    const record: AuditRecord = {
      eventId: randomUUID(),
      correlationId,
      occurredAtUtc,
      actorOwnerKey: identity.ownerKey,
      authenticationType: identity.authenticationType,
      operation,
      entityType: 'Profile',
      entityId: resulting?.ownerKey || previous?.ownerKey || identity.ownerKey,
      outcome: 'Succeeded',
      schemaVersion: 1,
      ...(stateHash(previous) ? { previousState: stateHash(previous)! } : {}),
      ...(stateHash(resulting) ? { resultingState: stateHash(resulting)! } : {})
    };
    try {
      await this.repository.writeAudit(record);
    } catch {
      throw new ApiError(
        503,
        'audit_write_failed',
        'The profile mutation completed, but its audit record could not be written. Reload the profile before retrying.',
        { mutationCommitted: true, operation }
      );
    }
  }
}
