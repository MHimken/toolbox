import { ApiError } from '../src/errors.js';
import type { AuditRecord, ProfileRecord, ProfileSettings, ReviewActionRecord } from '../src/models.js';
import type { EntityPatch, GovernanceRepository } from '../src/repositories.js';
import type { AllowRule } from '../src/ruleModels.js';

function tableError(statusCode: number): Error {
  return Object.assign(new Error(`table ${statusCode}`), { statusCode });
}

const actionPatchFields: Record<string, keyof ReviewActionRecord> = {
  Status: 'status',
  UpdatedAtUtc: 'updatedAtUtc',
  CancelledByOwnerKey: 'cancelledByOwnerKey',
  CancelledAtUtc: 'cancelledAtUtc',
  CancellationReason: 'cancellationReason'
};

export class MemoryRepository implements GovernanceRepository {
  readonly profiles = new Map<string, ProfileRecord>();
  readonly actions = new Map<string, ReviewActionRecord>();
  readonly rules = new Map<string, AllowRule>();
  readonly audits: AuditRecord[] = [];
  private version = 0;
  failAudit = false;

  private nextEtag(): string {
    return `W/"${++this.version}"`;
  }

  async getProfile(ownerKey: string) {
    return this.profiles.get(ownerKey) || null;
  }

  async createProfile(profile: ProfileRecord) {
    if (this.profiles.has(profile.ownerKey)) throw new ApiError(412, 'etag_conflict', 'exists');
    const saved = { ...profile, etag: this.nextEtag() };
    this.profiles.set(profile.ownerKey, saved);
    return saved;
  }

  async updateProfile(ownerKey: string, newSettings: ProfileSettings, etag: string, updatedAtUtc: string) {
    const existing = this.profiles.get(ownerKey);
    if (!existing) throw new ApiError(404, 'profile_not_found', 'missing');
    if (existing.etag !== etag) throw new ApiError(412, 'etag_conflict', 'changed');
    const saved = { ...existing, settings: newSettings, updatedAtUtc, etag: this.nextEtag() };
    this.profiles.set(ownerKey, saved);
    return saved;
  }

  async deleteProfile(ownerKey: string, etag: string) {
    const existing = this.profiles.get(ownerKey);
    if (!existing) throw new ApiError(404, 'profile_not_found', 'missing');
    if (existing.etag !== etag) throw new ApiError(412, 'etag_conflict', 'changed');
    this.profiles.delete(ownerKey);
  }

  async getReviewAction(ownerKey: string, actionId: string) {
    const action = this.actions.get(`${ownerKey}:${actionId}`);
    return action ? { ...action } : null;
  }

  async createReviewAction(ownerKey: string, action: ReviewActionRecord) {
    const key = `${ownerKey}:${action.actionId}`;
    if (this.actions.has(key)) throw tableError(409);
    this.actions.set(key, { ...action, ownerKey, etag: this.nextEtag() });
  }

  async listReviewActions(ownerKey: string | null, limit: number) {
    const all = [...this.actions.values()].filter(action => !ownerKey || action.ownerKey === ownerKey);
    return { actions: all.slice(0, limit), truncated: all.length > limit };
  }

  async updateReviewAction(ownerKey: string, actionId: string, patch: EntityPatch, etag: string) {
    const key = `${ownerKey}:${actionId}`;
    const existing = this.actions.get(key);
    if (!existing) throw tableError(404);
    if (existing.etag !== etag) throw tableError(412);
    const updated: Record<string, unknown> = { ...existing, etag: this.nextEtag() };
    for (const [field, value] of Object.entries(patch)) {
      const mapped = actionPatchFields[field];
      if (mapped) updated[mapped] = value;
    }
    this.actions.set(key, updated as unknown as ReviewActionRecord);
    return { ...(updated as unknown as ReviewActionRecord) };
  }

  async listRules(partitionKey: string) {
    return [...this.rules.values()].filter(rule => rule.PartitionKey === partitionKey).map(rule => ({ ...rule }));
  }

  async getRule(partitionKey: string, ruleId: string) {
    const rule = this.rules.get(`${partitionKey}:${ruleId}`);
    return rule ? { ...rule } : null;
  }

  async createRule(rule: AllowRule) {
    const key = `${rule.PartitionKey}:${rule.RowKey}`;
    if (this.rules.has(key)) throw tableError(409);
    const saved = { ...rule, ETag: this.nextEtag() };
    this.rules.set(key, saved);
    return { ...saved };
  }

  async updateRule(partitionKey: string, ruleId: string, patch: EntityPatch, etag: string) {
    const key = `${partitionKey}:${ruleId}`;
    const existing = this.rules.get(key);
    if (!existing) throw tableError(404);
    if (existing.ETag !== etag) throw tableError(412);
    const saved = { ...existing, ...patch, ETag: this.nextEtag() };
    this.rules.set(key, saved);
    return { ...saved };
  }

  async writeAudit(record: AuditRecord) {
    if (this.failAudit) throw new Error('audit unavailable');
    if (this.audits.some(existing => existing.eventId === record.eventId)) throw tableError(409);
    this.audits.push(record);
  }
}
