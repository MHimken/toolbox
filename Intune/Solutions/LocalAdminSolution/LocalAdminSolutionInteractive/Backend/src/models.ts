export const profileRowKey = 'profile';
export const profileSchemaVersion = 1;

export type TableView = 'summary' | 'users' | 'groups' | 'devices' | 'review' | 'governance';

export interface TableColumnLayout {
  key: string;
  width: number;
}

export type TableLayouts = Partial<Record<TableView, TableColumnLayout[]>>;

export interface ProfileSettings {
  staleThresholdDays: number;
  reviewWindowDays: number;
  pageSize: 25 | 50 | 100 | 250;
  defaultView: 'summary' | 'devices' | 'review' | 'governance';
  groupByComputer: boolean;
  timeDisplay: 'local' | 'utc';
  csvFilenamePrefix: string;
  tableLayouts?: TableLayouts;
}

export interface ProfileRecord {
  ownerKey: string;
  settings: ProfileSettings;
  createdAtUtc: string;
  updatedAtUtc: string;
  schemaVersion: number;
  etag?: string;
}

export interface AuditRecord {
  eventId: string;
  correlationId: string;
  occurredAtUtc: string;
  actorOwnerKey: string;
  authenticationType: 'Entra' | 'Recovery';
  operation: string;
  entityType: string;
  entityId: string;
  outcome: 'Succeeded' | 'Failed';
  previousState?: string;
  resultingState?: string;
  errorCode?: string;
  actorRoles?: string;
  adminSessionId?: string;
  authContextId?: string;
  detailsJson?: string;
  schemaVersion: number;
}

export const actionStatuses = [
  'Requested', 'Queued', 'InProgress', 'AwaitingInventory', 'Succeeded', 'Failed', 'Rejected', 'Cancelled', 'Expired'
] as const;
export const cancellableActionStatuses: readonly string[] = ['Requested', 'Queued'];

export interface ReviewActionRecord {
  actionId: string;
  ownerKey?: string;
  idempotencyKey: string;
  actionType: string;
  status: string;
  targetComputerSid: string;
  targetPrincipalId: string;
  expectedChange: string;
  justification: string;
  ticketReference?: string;
  requestedByOwnerKey: string;
  correlationId: string;
  createdAtUtc: string;
  updatedAtUtc?: string;
  cancelledByOwnerKey?: string;
  cancelledAtUtc?: string;
  cancellationReason?: string;
  schemaVersion: number;
  etag?: string;
}

export function validateSettings(value: unknown): ProfileSettings {
  if (!value || typeof value !== 'object') throw new Error('settings must be an object.');
  const settings = value as Record<string, unknown>;
  const positiveInteger = (name: string): number => {
    const number = Number(settings[name]);
    if (!Number.isInteger(number) || number < 1) throw new Error(`${name} must be a positive integer.`);
    return number;
  };
  const pageSize = Number(settings.pageSize);
  if (![25, 50, 100, 250].includes(pageSize)) throw new Error('pageSize is not supported.');
  const defaultView = String(settings.defaultView || '');
  if (!['summary', 'devices', 'review', 'governance'].includes(defaultView)) throw new Error('defaultView is not supported.');
  const timeDisplay = String(settings.timeDisplay || '');
  if (!['local', 'utc'].includes(timeDisplay)) throw new Error('timeDisplay is not supported.');
  const csvFilenamePrefix = String(settings.csvFilenamePrefix || '');
  if (!/^[A-Za-z0-9_-]{1,40}$/.test(csvFilenamePrefix)) throw new Error('csvFilenamePrefix is invalid.');
  if (typeof settings.groupByComputer !== 'boolean') throw new Error('groupByComputer must be boolean.');
  const tableLayouts: TableLayouts = {};
  if (settings.tableLayouts !== undefined) {
    if (!settings.tableLayouts || typeof settings.tableLayouts !== 'object' || Array.isArray(settings.tableLayouts)) {
      throw new Error('tableLayouts must be an object.');
    }

    const allowedViews = new Set<TableView>(['summary', 'users', 'groups', 'devices', 'review', 'governance']);
    for (const [viewName, columns] of Object.entries(settings.tableLayouts)) {
      if (!allowedViews.has(viewName as TableView)) throw new Error(`tableLayouts.${viewName} is not supported.`);
      if (!Array.isArray(columns) || columns.length > 64) {
        throw new Error(`tableLayouts.${viewName} must contain no more than 64 columns.`);
      }
      const seenKeys = new Set<string>();
      tableLayouts[viewName as TableView] = columns.map((column, index) => {
        if (!column || typeof column !== 'object' || Array.isArray(column)) {
          throw new Error(`tableLayouts.${viewName}[${index}] must be an object.`);
        }
        const record = column as Record<string, unknown>;
        const key = String(record.key || '');
        const width = Number(record.width);
        if (!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(key)) {
          throw new Error(`tableLayouts.${viewName}[${index}].key is invalid.`);
        }
        if (seenKeys.has(key)) throw new Error(`tableLayouts.${viewName} contains duplicate column keys.`);
        if (!Number.isInteger(width) || width < 90 || width > 800) {
          throw new Error(`tableLayouts.${viewName}[${index}].width must be between 90 and 800.`);
        }
        seenKeys.add(key);
        return { key, width };
      });
    }
  }
  return {
    staleThresholdDays: positiveInteger('staleThresholdDays'),
    reviewWindowDays: positiveInteger('reviewWindowDays'),
    pageSize: pageSize as ProfileSettings['pageSize'],
    defaultView: defaultView as ProfileSettings['defaultView'],
    groupByComputer: settings.groupByComputer,
    timeDisplay: timeDisplay as ProfileSettings['timeDisplay'],
    csvFilenamePrefix,
    tableLayouts
  };
}

export function validateGovernanceExceptionRequest(value: unknown): Omit<
  ReviewActionRecord,
  'actionId' | 'idempotencyKey' | 'actionType' | 'status' | 'expectedChange' |
  'requestedByOwnerKey' | 'correlationId' | 'createdAtUtc' | 'schemaVersion'
> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Request body must be an object.');
  }
  const request = value as Record<string, unknown>;
  const computerSid = typeof request.computerSid === 'string' ? request.computerSid.trim() : '';
  const principalSid = typeof request.principalSid === 'string' ? request.principalSid.trim() : '';
  const justification = typeof request.justification === 'string' ? request.justification.trim() : '';
  const ticketReference = typeof request.ticketReference === 'string' ? request.ticketReference.trim() : '';
  if (!/^S-\d(?:-\d+)+$/i.test(computerSid)) throw new Error('computerSid must be a valid SID.');
  if (!/^S-\d(?:-\d+)+$/i.test(principalSid)) throw new Error('principalSid must be a valid SID.');
  if (justification.length < 10 || justification.length > 2000) {
    throw new Error('justification must contain between 10 and 2000 characters.');
  }
  if (ticketReference.length > 100 || /[\u0000-\u001f\u007f]/.test(ticketReference)) {
    throw new Error('ticketReference must be at most 100 characters and contain no control characters.');
  }
  return {
    targetComputerSid: computerSid.toUpperCase(),
    targetPrincipalId: principalSid.toUpperCase(),
    justification,
    ...(ticketReference ? { ticketReference } : {})
  };
}
