import { randomUUID } from 'node:crypto';
import { DefaultAzureCredential } from '@azure/identity';
import { TableClient, odata, type TableEntity } from '@azure/data-tables';
import type { AppConfig } from './config.js';
import { ApiError, isTableStatus } from './errors.js';
import type { AllowRule } from './ruleModels.js';
import {
  profileRowKey,
  type AuditRecord,
  type ProfileRecord,
  type ProfileSettings,
  type ReviewActionRecord
} from './models.js';

interface ProfileEntity extends TableEntity {
  SettingsJson: string;
  CreatedAtUtc: string;
  UpdatedAtUtc: string;
  SchemaVersion: number;
}

interface AuditEntity extends TableEntity {
  CorrelationId: string;
  OccurredAtUtc: string;
  ActorOwnerKey: string;
  AuthenticationType: string;
  Operation: string;
  EntityType: string;
  EntityId: string;
  Outcome: string;
  PreviousState?: string;
  ResultingState?: string;
  ErrorCode?: string;
  ActorRoles?: string;
  AdminSessionId?: string;
  AuthContextId?: string;
  DetailsJson?: string;
  SchemaVersion: number;
}

interface ReviewActionEntity extends TableEntity {
  IdempotencyKey: string;
  ActionType: string;
  Status: string;
  TargetComputerSid: string;
  TargetPrincipalId: string;
  ExpectedChange: string;
  Justification: string;
  TicketReference?: string;
  RequestedByOwnerKey: string;
  CorrelationId: string;
  CreatedAtUtc: string;
  SchemaVersion: number;
}

export type EntityPatch = Record<string, string | number | boolean>;

export interface GovernanceRepository {
  getProfile(ownerKey: string): Promise<ProfileRecord | null>;
  createProfile(profile: ProfileRecord): Promise<ProfileRecord>;
  updateProfile(ownerKey: string, settings: ProfileSettings, etag: string, updatedAtUtc: string): Promise<ProfileRecord>;
  deleteProfile(ownerKey: string, etag: string): Promise<void>;
  getReviewAction(ownerKey: string, actionId: string): Promise<ReviewActionRecord | null>;
  createReviewAction(ownerKey: string, action: ReviewActionRecord): Promise<void>;
  listReviewActions(ownerKey: string | null, limit: number): Promise<{ actions: ReviewActionRecord[]; truncated: boolean }>;
  /** Merges the patch using the supplied ETag; throws the raw table error on 404/412. */
  updateReviewAction(ownerKey: string, actionId: string, patch: EntityPatch, etag: string): Promise<ReviewActionRecord>;
  listRules(partitionKey: string): Promise<AllowRule[]>;
  getRule(partitionKey: string, ruleId: string): Promise<AllowRule | null>;
  /** Throws the raw table error on 409 when the rule ID already exists. */
  createRule(rule: AllowRule): Promise<AllowRule>;
  /** Merges the patch using the supplied ETag; throws the raw table error on 404/412. */
  updateRule(partitionKey: string, ruleId: string, patch: EntityPatch, etag: string): Promise<AllowRule>;
  writeAudit(record: AuditRecord): Promise<void>;
}

function tableValue(value: unknown): unknown {
  return value instanceof Date ? value.toISOString() : value;
}

function textValue(value: unknown): string {
  const normalized = tableValue(value);
  return normalized === undefined || normalized === null ? '' : String(normalized);
}

export function ruleFromEntity(entity: Record<string, unknown>): AllowRule {
  const rule: AllowRule = {
    PartitionKey: textValue(entity.partitionKey),
    RowKey: textValue(entity.rowKey),
    RuleScope: textValue(entity.RuleScope),
    Status: textValue(entity.Status)
  };
  for (const [key, value] of Object.entries(entity)) {
    if (['partitionKey', 'rowKey', 'etag', 'timestamp', 'odata.metadata'].includes(key) || key.endsWith('@odata.type')) continue;
    rule[key] = tableValue(value);
  }
  if (entity.timestamp) rule.Timestamp = tableValue(entity.timestamp);
  if (entity.etag) rule.ETag = String(entity.etag);
  return rule;
}

export function actionFromEntity(entity: Record<string, unknown>): ReviewActionRecord {
  const optional = (name: string, key: keyof ReviewActionRecord) =>
    entity[name] !== undefined && entity[name] !== null && entity[name] !== '' ? { [key]: textValue(entity[name]) } : {};
  return {
    actionId: textValue(entity.rowKey),
    ownerKey: textValue(entity.partitionKey),
    idempotencyKey: textValue(entity.IdempotencyKey),
    actionType: textValue(entity.ActionType),
    status: textValue(entity.Status),
    targetComputerSid: textValue(entity.TargetComputerSid),
    targetPrincipalId: textValue(entity.TargetPrincipalId),
    expectedChange: textValue(entity.ExpectedChange),
    justification: textValue(entity.Justification),
    requestedByOwnerKey: textValue(entity.RequestedByOwnerKey),
    correlationId: textValue(entity.CorrelationId),
    createdAtUtc: textValue(entity.CreatedAtUtc),
    schemaVersion: Number(entity.SchemaVersion) || 1,
    ...optional('TicketReference', 'ticketReference'),
    ...optional('UpdatedAtUtc', 'updatedAtUtc'),
    ...optional('CancelledByOwnerKey', 'cancelledByOwnerKey'),
    ...optional('CancelledAtUtc', 'cancelledAtUtc'),
    ...optional('CancellationReason', 'cancellationReason'),
    ...(entity.etag ? { etag: String(entity.etag) } : {})
  } as ReviewActionRecord;
}

function profileFromEntity(entity: ProfileEntity): ProfileRecord {
  return {
    ownerKey: entity.partitionKey,
    settings: JSON.parse(entity.SettingsJson) as ProfileSettings,
    createdAtUtc: entity.CreatedAtUtc,
    updatedAtUtc: entity.UpdatedAtUtc,
    schemaVersion: entity.SchemaVersion,
    ...(entity.etag ? { etag: String(entity.etag) } : {})
  };
}

export class AzureTableGovernanceRepository implements GovernanceRepository {
  private readonly profiles: TableClient;
  private readonly actions: TableClient;
  private readonly rules: TableClient;
  private readonly audits: TableClient;

  constructor(config: AppConfig) {
    const credential = new DefaultAzureCredential();
    this.profiles = new TableClient(config.governanceTableEndpoint, 'LocalAdminUserSettings', credential);
    this.actions = new TableClient(config.governanceTableEndpoint, 'LocalAdminReviewActions', credential);
    this.rules = new TableClient(config.governanceTableEndpoint, 'LocalAdminAllowRules', credential);
    this.audits = new TableClient(config.governanceTableEndpoint, 'LocalAdminAuditRecords', credential);
  }

  async getProfile(ownerKey: string): Promise<ProfileRecord | null> {
    try {
      return profileFromEntity(await this.profiles.getEntity<ProfileEntity>(ownerKey, profileRowKey));
    } catch (error) {
      if (isTableStatus(error, 404)) return null;
      throw error;
    }
  }

  async createProfile(profile: ProfileRecord): Promise<ProfileRecord> {
    const entity: ProfileEntity = {
      partitionKey: profile.ownerKey,
      rowKey: profileRowKey,
      SettingsJson: JSON.stringify(profile.settings),
      CreatedAtUtc: profile.createdAtUtc,
      UpdatedAtUtc: profile.updatedAtUtc,
      SchemaVersion: profile.schemaVersion
    };
    try {
      await this.profiles.createEntity(entity);
      return (await this.getProfile(profile.ownerKey))!;
    } catch (error) {
      if (isTableStatus(error, 409)) throw new ApiError(412, 'etag_conflict', 'The profile already exists.');
      throw error;
    }
  }

  async updateProfile(ownerKey: string, settings: ProfileSettings, etag: string, updatedAtUtc: string): Promise<ProfileRecord> {
    try {
      await this.profiles.updateEntity({
        partitionKey: ownerKey,
        rowKey: profileRowKey,
        SettingsJson: JSON.stringify(settings),
        UpdatedAtUtc: updatedAtUtc
      }, 'Merge', { etag });
      return (await this.getProfile(ownerKey))!;
    } catch (error) {
      if (isTableStatus(error, 404)) throw new ApiError(404, 'profile_not_found', 'The profile was not found.');
      if (isTableStatus(error, 412)) throw new ApiError(412, 'etag_conflict', 'The profile changed. Reload it before saving.');
      throw error;
    }
  }

  async deleteProfile(ownerKey: string, etag: string): Promise<void> {
    try {
      await this.profiles.deleteEntity(ownerKey, profileRowKey, { etag });
    } catch (error) {
      if (isTableStatus(error, 404)) throw new ApiError(404, 'profile_not_found', 'The profile was not found.');
      if (isTableStatus(error, 412)) throw new ApiError(412, 'etag_conflict', 'The profile changed. Reload it before deleting.');
      throw error;
    }
  }

  async getReviewAction(ownerKey: string, actionId: string): Promise<ReviewActionRecord | null> {
    try {
      return actionFromEntity(await this.actions.getEntity<ReviewActionEntity>(ownerKey, actionId));
    } catch (error) {
      if (isTableStatus(error, 404)) return null;
      throw error;
    }
  }

  async createReviewAction(ownerKey: string, action: ReviewActionRecord): Promise<void> {
    const entity: ReviewActionEntity = {
      partitionKey: ownerKey,
      rowKey: action.actionId,
      IdempotencyKey: action.idempotencyKey,
      ActionType: action.actionType,
      Status: action.status,
      TargetComputerSid: action.targetComputerSid,
      TargetPrincipalId: action.targetPrincipalId,
      ExpectedChange: action.expectedChange,
      Justification: action.justification,
      RequestedByOwnerKey: action.requestedByOwnerKey,
      CorrelationId: action.correlationId,
      CreatedAtUtc: action.createdAtUtc,
      SchemaVersion: action.schemaVersion,
      ...(action.ticketReference ? { TicketReference: action.ticketReference } : {})
    };
    await this.actions.createEntity(entity);
  }

  async listReviewActions(ownerKey: string | null, limit: number): Promise<{ actions: ReviewActionRecord[]; truncated: boolean }> {
    const actions: ReviewActionRecord[] = [];
    const entities = this.actions.listEntities<Record<string, unknown>>(
      ownerKey ? { queryOptions: { filter: odata`PartitionKey eq ${ownerKey}` } } : {}
    );
    for await (const entity of entities) {
      if (actions.length >= limit) return { actions, truncated: true };
      actions.push(actionFromEntity(entity));
    }
    return { actions, truncated: false };
  }

  async updateReviewAction(ownerKey: string, actionId: string, patch: EntityPatch, etag: string): Promise<ReviewActionRecord> {
    await this.actions.updateEntity({ partitionKey: ownerKey, rowKey: actionId, ...patch }, 'Merge', { etag });
    return (await this.getReviewAction(ownerKey, actionId))!;
  }

  async listRules(partitionKey: string): Promise<AllowRule[]> {
    const rules: AllowRule[] = [];
    for await (const entity of this.rules.listEntities<Record<string, unknown>>({
      queryOptions: { filter: odata`PartitionKey eq ${partitionKey}` }
    })) {
      rules.push(ruleFromEntity(entity));
    }
    return rules;
  }

  async getRule(partitionKey: string, ruleId: string): Promise<AllowRule | null> {
    try {
      return ruleFromEntity(await this.rules.getEntity<Record<string, unknown>>(partitionKey, ruleId));
    } catch (error) {
      if (isTableStatus(error, 404)) return null;
      throw error;
    }
  }

  async createRule(rule: AllowRule): Promise<AllowRule> {
    const { PartitionKey, RowKey, ETag: _etag, ...columns } = rule;
    const entity: Record<string, unknown> = { partitionKey: PartitionKey, rowKey: RowKey };
    for (const [key, value] of Object.entries(columns)) {
      if (value !== undefined && value !== null && key !== 'Timestamp') entity[key] = value;
    }
    await this.rules.createEntity(entity as TableEntity);
    return (await this.getRule(PartitionKey, RowKey))!;
  }

  async updateRule(partitionKey: string, ruleId: string, patch: EntityPatch, etag: string): Promise<AllowRule> {
    await this.rules.updateEntity({ partitionKey, rowKey: ruleId, ...patch }, 'Merge', { etag });
    return (await this.getRule(partitionKey, ruleId))!;
  }

  async writeAudit(record: AuditRecord): Promise<void> {
    const entity: AuditEntity = {
      partitionKey: record.occurredAtUtc.slice(0, 10),
      rowKey: `${record.occurredAtUtc}_${record.eventId || randomUUID()}`,
      CorrelationId: record.correlationId,
      OccurredAtUtc: record.occurredAtUtc,
      ActorOwnerKey: record.actorOwnerKey,
      AuthenticationType: record.authenticationType,
      Operation: record.operation,
      EntityType: record.entityType,
      EntityId: record.entityId,
      Outcome: record.outcome,
      SchemaVersion: record.schemaVersion,
      ...(record.previousState ? { PreviousState: record.previousState } : {}),
      ...(record.resultingState ? { ResultingState: record.resultingState } : {}),
      ...(record.errorCode ? { ErrorCode: record.errorCode } : {}),
      ...(record.actorRoles ? { ActorRoles: record.actorRoles } : {}),
      ...(record.adminSessionId ? { AdminSessionId: record.adminSessionId } : {}),
      ...(record.authContextId ? { AuthContextId: record.authContextId } : {}),
      ...(record.detailsJson ? { DetailsJson: record.detailsJson } : {})
    };
    await this.audits.createEntity(entity);
  }
}
