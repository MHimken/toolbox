import { evaluateRuleSet, findLatestAction } from './apiContract.js';

export function text(value) {
  return value === null || value === undefined ? '' : String(value);
}

// Endpoint- and proposer-supplied strings must not become spreadsheet formulas (OWASP CSV injection).
export function csvCell(value) {
  let cell = text(value);
  if (typeof value !== 'number' && /^[=+\-@\t\r]/.test(cell)) cell = `'${cell}`;
  return `"${cell.replaceAll('"', '""')}"`;
}

export function buildCsv(columns, rows, formatValue = (key, value) => value) {
  const lines = [
    columns.map(([, label]) => csvCell(label)).join(','),
    ...rows.map(row => columns.map(([key]) => csvCell(formatValue(key, row[key]))).join(','))
  ];
  return '\uFEFF' + lines.join('\r\n');
}

export async function getAzureTableEntities(tableName, accountUrl, token) {
  const rows = [];
  let nextPartitionKey = '';
  let nextRowKey = '';
  do {
    const requestUrl = new URL(`${accountUrl}/${tableName}()`);
    const sasParameters = new URLSearchParams(token.replace(/^\?/, ''));
    sasParameters.forEach((value, key) => requestUrl.searchParams.set(key, value));
    if (nextPartitionKey) requestUrl.searchParams.set('NextPartitionKey', nextPartitionKey);
    if (nextRowKey) requestUrl.searchParams.set('NextRowKey', nextRowKey);
    const response = await fetch(requestUrl, {
      headers: { Accept: 'application/json;odata=nometadata', 'x-ms-version': '2023-11-03' },
      cache: 'no-store'
    });
    if (!response.ok) {
      throw new Error(`${tableName} returned HTTP ${response.status} ${response.statusText}.`);
    }
    const payload = await response.json();
    rows.push(...(payload.value || []));
    nextPartitionKey = response.headers.get('x-ms-continuation-NextPartitionKey') || '';
    nextRowKey = response.headers.get('x-ms-continuation-NextRowKey') || '';
  } while (nextPartitionKey);
  return rows;
}

export function canonicalLookupRows(entities) {
  const compare = (left, right) => {
    const resolvedDifference = Number(text(right.ResolutionState) === 'Resolved') - Number(text(left.ResolutionState) === 'Resolved');
    if (resolvedDifference) return resolvedDifference;
    const leftTime = Date.parse(left.ObservedAt || left.Timestamp) || 0;
    const rightTime = Date.parse(right.ObservedAt || right.Timestamp) || 0;
    if (leftTime !== rightTime) return rightTime - leftTime;
    return text(left.RowKey).localeCompare(text(right.RowKey)) * -1;
  };
  const bySid = new Map();
  entities.forEach(entity => {
    const sid = text(entity.PartitionKey);
    const current = bySid.get(sid);
    if (!current || compare(entity, current) < 0) bySid.set(sid, entity);
  });
  return [...bySid.values()];
}

export function calculateReportingState(lastReportUtc, thresholdDays, now = new Date()) {
  if (!lastReportUtc) return { state: 'Never reported', days: null };
  const parsed = new Date(lastReportUtc);
  if (Number.isNaN(parsed.getTime())) return { state: 'Unknown freshness', days: null };
  const days = Math.max(0, Math.floor((now.getTime() - parsed.getTime()) / 86400000));
  return { state: days > thresholdDays ? 'Stale' : 'Reporting', days };
}

function normalizeBoolean(value) {
  return value === true || value === 1 || text(value).toLowerCase() === 'true';
}

function normalizedGuid(value) {
  return text(value).trim().toLowerCase();
}

function presenceState(value, presentLabel, missingLabel, unknownLabel) {
  if (value === true || text(value).toLowerCase() === 'true') return presentLabel;
  if (value === false || text(value).toLowerCase() === 'false') return missingLabel;
  return unknownLabel;
}

function correlateDeviceObservations(entities) {
  const devices = new Map();
  const getDevice = key => {
    if (!devices.has(key)) {
      devices.set(key, {
        CorrelationKey: key,
        EntraPresent: null,
        IntunePresent: null,
        CollectorPresent: null,
        IntuneRecordCount: 0
      });
    }
    return devices.get(key);
  };

  entities.filter(entity => text(entity.ObservationType) === 'Entra' || text(entity.RowKey).startsWith('E_')).forEach(entity => {
    const entraDeviceId = normalizedGuid(entity.EntraDeviceId || text(entity.RowKey).slice(2));
    if (!entraDeviceId) return;
    const device = getDevice(`entra:${entraDeviceId}`);
    Object.assign(device, {
      EntraDeviceId: entraDeviceId,
      EntraObjectId: text(entity.EntraObjectId),
      EntraDisplayName: text(entity.EntraDisplayName),
      EntraOperatingSystem: text(entity.OperatingSystem),
      AccountEnabled: entity.AccountEnabled,
      EntraObservedUtc: entity.EntraObservedUtc,
      EntraPresent: entity.EntraPresent
    });
  });

  entities.filter(entity => text(entity.ObservationType) === 'Intune' || text(entity.RowKey).startsWith('I_')).forEach(entity => {
    const entraDeviceId = normalizedGuid(entity.EntraDeviceId);
    const managedDeviceId = normalizedGuid(entity.IntuneManagedDeviceId || text(entity.RowKey).slice(2));
    const device = getDevice(entraDeviceId ? `entra:${entraDeviceId}` : `intune:${managedDeviceId}`);
    const candidateTime = Date.parse(entity.IntuneLastSyncUtc || entity.IntuneObservedUtc) || 0;
    const currentTime = Date.parse(device.IntuneLastSyncUtc || device.IntuneObservedUtc) || 0;
    const currentPresent = device.IntunePresent;
    const candidatePresent = entity.IntunePresent;
    device.IntuneRecordCount++;
    if (candidateTime >= currentTime) {
      Object.assign(device, {
        EntraDeviceId: entraDeviceId || device.EntraDeviceId,
        IntuneManagedDeviceId: managedDeviceId,
        IntuneDeviceName: text(entity.IntuneDeviceName),
        IntuneOperatingSystem: text(entity.OperatingSystem),
        IntuneLastSyncUtc: entity.IntuneLastSyncUtc,
        IntuneObservedUtc: entity.IntuneObservedUtc,
        ComplianceState: text(entity.ComplianceState),
        ManagementAgent: text(entity.ManagementAgent),
        Ownership: text(entity.Ownership)
      });
    }
    device.IntunePresent = normalizeBoolean(currentPresent) || normalizeBoolean(candidatePresent)
      ? true
      : (currentPresent === false || text(currentPresent).toLowerCase() === 'false' ||
          candidatePresent === false || text(candidatePresent).toLowerCase() === 'false' ? false : null);
  });

  entities.filter(entity => text(entity.ObservationType) === 'Collector' || text(entity.RowKey).startsWith('C_')).forEach(entity => {
    const entraDeviceId = normalizedGuid(entity.EntraDeviceId);
    const computerSid = text(entity.ComputerSid);
    const device = getDevice(entraDeviceId ? `entra:${entraDeviceId}` : `collector:${computerSid || entity.RowKey}`);
    const candidateTime = Date.parse(entity.LastReportUtc) || 0;
    const currentTime = Date.parse(device.LastReportUtc) || 0;
    if (candidateTime >= currentTime) {
      Object.assign(device, {
        EntraDeviceId: entraDeviceId || device.EntraDeviceId,
        ComputerName: text(entity.ComputerName),
        ComputerSid: computerSid,
        JoinState: text(entity.JoinState),
        CollectorVersion: text(entity.CollectorVersion),
        CollectorPresent: entity.CollectorPresent,
        LastReportUtc: entity.LastReportUtc,
        LastInventoryChangeUtc: entity.LastInventoryChangeUtc
      });
    }
  });

  return [...devices.values()].map(device => ({
    ...device,
    ComputerName: text(device.ComputerName || device.IntuneDeviceName || device.EntraDisplayName),
    OperatingSystem: text(device.IntuneOperatingSystem || device.EntraOperatingSystem),
    EntraState: presenceState(device.EntraPresent, 'Present', 'Missing', 'Unknown'),
    IntuneState: presenceState(device.IntunePresent, 'Managed', 'Missing', 'Not observed')
  }));
}

export function resolveAzureData(mainEntities, userEntities, groupEntities, deviceEntities, allowRules, reviewActions, staleThresholdDays = 90, reviewWindowDays = 90) {
  const canonicalUsers = canonicalLookupRows(userEntities);
  const canonicalGroups = canonicalLookupRows(groupEntities);
  const usersBySid = new Map(canonicalUsers.map(user => [text(user.PartitionKey), user]));
  const groupsBySid = new Map(canonicalGroups.map(group => [text(group.PartitionKey), group]));
  const canonicalDevices = correlateDeviceObservations(deviceEntities);
  const devicesByComputerSid = new Map(canonicalDevices.filter(device => device.ComputerSid).map(device => [text(device.ComputerSid), device]));
  const joinStates = { '1': 'Entra joined', '2': 'Hybrid joined', '3': 'Domain joined' };
  const now = new Date();

  const summary = mainEntities.map(entity => {
    const principalSid = text(entity.PrincipalID);
    const principalType = text(entity.PrincipalType);
    const userSid = principalType === 'User' ? principalSid : '';
    const groupSid = principalType === 'Group' ? principalSid : '';
    const assignedThroughGroupSid = text(entity.AssignedThroughGroupID);
    const device = devicesByComputerSid.get(text(entity.PartitionKey));
    const freshness = calculateReportingState(device?.LastReportUtc, staleThresholdDays, now);
    const principal = principalType === 'User' ? usersBySid.get(userSid) : groupsBySid.get(groupSid);
    return {
      ComputerName: text(device?.ComputerName || entity.Computername),
      SID: text(entity.PartitionKey),
      RowKey: Number(entity.RowKey),
      JoinState: text(device?.JoinState) || (entity.EntraOrHybrid == null ? '' : (joinStates[text(entity.EntraOrHybrid)] || `Unknown (${entity.EntraOrHybrid})`)),
      LastReportUtc: device?.LastReportUtc || null,
      ReportingState: freshness.state,
      DaysSinceLastReport: freshness.days,
      EntraState: text(device?.EntraState || 'Unknown'),
      IntuneState: text(device?.IntuneState || 'Not observed'),
      LocalAdminGroupName: text(entity.LocalAdminGroupName),
      Removed: Number(entity.Removed),
      PrincipalID: principalSid,
      PrincipalType: principalType,
      PrincipalSource: text(principal?.LocalOrEntraOrAD),
      UserName: userSid && usersBySid.has(userSid) ? text(usersBySid.get(userSid).RowKey) : userSid,
      GroupName: groupSid && groupsBySid.has(groupSid) ? text(groupsBySid.get(groupSid).RowKey) : groupSid,
      MembershipType: text(entity.MembershipType),
      AddedThroughGroupName: assignedThroughGroupSid && groupsBySid.has(assignedThroughGroupSid) ? text(groupsBySid.get(assignedThroughGroupSid).RowKey) : assignedThroughGroupSid,
      LocalAccountLastPasswordChange: entity.LocalAccountLastPasswordChange,
      Timestamp: entity.Timestamp,
      _UserSID: userSid,
      _GroupSID: groupSid,
      _AssignedThroughGroupSID: assignedThroughGroupSid
    };
  }).sort((left, right) => left.RowKey - right.RowKey);

  const deviceCounts = new Map();
  summary.forEach(row => {
    const counts = deviceCounts.get(row.SID) || { active: 0, removed: 0 };
    if (row.Removed === 1) counts.removed++;
    else counts.active++;
    deviceCounts.set(row.SID, counts);
  });
  const devices = canonicalDevices.map(device => {
    const freshness = calculateReportingState(device.LastReportUtc, staleThresholdDays, now);
    const counts = deviceCounts.get(text(device.ComputerSid)) || { active: 0, removed: 0 };
    return {
      ComputerName: text(device.ComputerName || device.EntraDisplayName),
      EntraDisplayName: text(device.EntraDisplayName),
      EntraDeviceId: text(device.EntraDeviceId),
      ComputerSid: text(device.ComputerSid),
      LastReportUtc: device.LastReportUtc || null,
      DaysSinceLastReport: freshness.days,
      ReportingState: freshness.state,
      EntraState: device.EntraState,
      EntraPresent: device.EntraPresent,
      AccountEnabled: device.AccountEnabled,
      IntuneState: device.IntuneState,
      IntunePresent: device.IntunePresent,
      IntuneManagedDeviceId: text(device.IntuneManagedDeviceId),
      IntuneLastSyncUtc: device.IntuneLastSyncUtc || null,
      ComplianceState: text(device.ComplianceState),
      IntuneRecordCount: device.IntuneRecordCount,
      OperatingSystem: text(device.OperatingSystem),
      JoinState: text(device.JoinState),
      ActiveAdminEntries: counts.active,
      RemovedEntries: counts.removed,
      ReviewStatus: 'Not evaluated'
    };
  });

  const review = resolveReviewData(summary, allowRules, reviewActions, reviewWindowDays, now);

  return {
    generatedAt: new Date().toISOString(),
    summary,
    users: canonicalUsers.map(user => ({
      UserID: text(user.PartitionKey), SamAccountName: text(user.RowKey), UserPrincipalName: text(user.UserPrincipalName),
      LocalOrEntraOrAD: text(user.LocalOrEntraOrAD), ObservedAt: user.ObservedAt, ResolutionState: text(user.ResolutionState), Timestamp: user.Timestamp
    })),
    groups: canonicalGroups.map(group => ({
      GroupID: text(group.PartitionKey), GroupName: text(group.RowKey), LocalOrEntraOrAD: text(group.LocalOrEntraOrAD),
      ObservedAt: group.ObservedAt, ResolutionState: text(group.ResolutionState), Timestamp: group.Timestamp
    })),
    devices,
    review,
    governance: allowRules,
    actions: reviewActions
  };
}

export function resolveReviewData(summary, allowRules, reviewActions, reviewWindowDays = 90, now = new Date()) {
  return summary.filter(row =>
    row.Removed === 0 &&
    (row.DaysSinceLastReport === null || row.DaysSinceLastReport <= reviewWindowDays)
  ).map(row => {
    const evaluation = evaluateRuleSet(allowRules, {
      ...row,
      PrincipalName: row.UserName || row.GroupName,
      AssignedThroughGroupSid: row._AssignedThroughGroupSID
    }, now);
    let reviewStatus = evaluation.status;
    if (row.EntraState === 'Missing') {
      reviewStatus = 'Device missing from Entra';
    } else if (row.ReportingState === 'Unknown freshness' || row.ReportingState === 'Never reported') {
      reviewStatus = 'Unknown freshness';
    }
    return {
      ComputerName: row.ComputerName,
      PrincipalID: row.PrincipalID,
      PrincipalType: row.PrincipalType,
      PrincipalName: row.UserName || row.GroupName,
      PrincipalSource: row.PrincipalSource,
      MembershipType: row.MembershipType,
      AddedThroughGroupName: row.AddedThroughGroupName,
      AssignedThroughGroupSid: row._AssignedThroughGroupSID || row.AssignedThroughGroupSid || '',
      JoinState: row.JoinState,
      EntraState: row.EntraState,
      IntuneState: row.IntuneState,
      LastReportUtc: row.LastReportUtc,
      PolicyStatus: evaluation.status,
      ReviewStatus: reviewStatus,
      MatchingRuleIds: evaluation.matchingRuleIds.join('; '),
      DecisiveRuleIds: evaluation.decisiveRuleIds.join('; '),
      CorrelationId: text(findLatestAction(reviewActions, row)?.CorrelationId)
    };
  }).filter(row => !['Governance approved', 'Unknown freshness'].includes(row.ReviewStatus));
}
