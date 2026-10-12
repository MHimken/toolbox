const keys = Object.freeze({
  connection: 'localAdminAzureConnection.v1',
  preferences: 'localAdminUserPreferences.v1',
  recoveryProfile: 'localAdminRecoveryProfile.v1',
  lastSuccessfulRun: 'localAdminLastSuccessfulRun.v1'
});

const defaultPreferences = Object.freeze({
  version: 1,
  staleThresholdDays: 90,
  reviewWindowDays: 90,
  pageSize: 50,
  defaultView: 'summary',
  groupByComputer: true,
  timeDisplay: 'local',
  csvFilenamePrefix: 'LocalAdmin',
  tableLayouts: {}
});

function readJson(key) {
  try {
    const serialized = localStorage.getItem(key);
    return serialized ? JSON.parse(serialized) : null;
  } catch {
    localStorage.removeItem(key);
    return null;
  }
}

function writeJson(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

export function loadConnection() {
  const value = readJson(keys.connection);
  return value?.version === 1 ? value : null;
}

export function saveConnection(accountName, token, governanceAccountName = '', governanceToken = '') {
  return writeJson(keys.connection, { version: 1, accountName, token, governanceAccountName, governanceToken });
}

export function removeConnection() {
  try {
    localStorage.removeItem(keys.connection);
    return true;
  } catch {
    return false;
  }
}

export function loadPreferences() {
  const value = readJson(keys.preferences);
  if (value?.version !== 1) {
    return { ...defaultPreferences };
  }
  return {
    version: 1,
    staleThresholdDays: Number.isInteger(value.staleThresholdDays) && value.staleThresholdDays > 0 ? value.staleThresholdDays : 90,
    reviewWindowDays: Number.isInteger(value.reviewWindowDays) && value.reviewWindowDays > 0 ? value.reviewWindowDays : 90,
    pageSize: [25, 50, 100, 250].includes(value.pageSize) ? value.pageSize : 50,
    defaultView: ['summary', 'devices', 'review', 'governance'].includes(value.defaultView) ? value.defaultView : 'summary',
    groupByComputer: value.groupByComputer !== false,
    timeDisplay: value.timeDisplay === 'utc' ? 'utc' : 'local',
    csvFilenamePrefix: /^[A-Za-z0-9_-]{1,40}$/.test(value.csvFilenamePrefix) ? value.csvFilenamePrefix : 'LocalAdmin',
    tableLayouts: value.tableLayouts && typeof value.tableLayouts === 'object' ? value.tableLayouts : {}
  };
}

export function savePreferences(preferences) {
  return writeJson(keys.preferences, { version: 1, ...preferences });
}

function encodeBase64Url(bytes) {
  let binary = '';
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function decodeRecoveryCode(recoveryCode) {
  const normalized = String(recoveryCode || '').trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(normalized)) {
    throw new Error('Recovery codes must be a 256-bit base64url value.');
  }
  const padded = normalized.replaceAll('-', '+').replaceAll('_', '/') + '=';
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new Error('The recovery code is not valid base64url.');
  }
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  if (bytes.length !== 32) throw new Error('Recovery codes must contain exactly 32 bytes.');
  return { normalized, bytes };
}

async function createRecoveryRecord(recoveryCode) {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Recovery profiles require Web Crypto in a secure browser context.');
  }
  const decoded = decodeRecoveryCode(recoveryCode);
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', decoded.bytes));
  return {
    version: 1,
    ownerKey: `recovery:${[...digest].map(byte => byte.toString(16).padStart(2, '0')).join('')}`,
    recoveryCode: decoded.normalized,
    createdAtUtc: new Date().toISOString()
  };
}

function isRecoveryProfile(value) {
  return value?.version === 1 &&
    /^recovery:[0-9a-f]{64}$/.test(value.ownerKey || '') &&
    /^[A-Za-z0-9_-]{43}$/.test(value.recoveryCode || '') &&
    !Number.isNaN(Date.parse(value.createdAtUtc));
}

export function saveRecoveryProfile(profile) {
  return isRecoveryProfile(profile) && writeJson(keys.recoveryProfile, profile);
}

export async function generateRecoveryProfile(rememberOnDevice = false) {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error('Recovery profiles require Web Crypto.');
  }
  const secret = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const profile = await createRecoveryRecord(encodeBase64Url(secret));
  return { profile, stored: rememberOnDevice ? saveRecoveryProfile(profile) : false };
}

export async function importRecoveryProfile(recoveryCode, rememberOnDevice = false) {
  const profile = await createRecoveryRecord(recoveryCode);
  return { profile, stored: rememberOnDevice ? saveRecoveryProfile(profile) : false };
}

export function loadRecoveryProfile() {
  const value = readJson(keys.recoveryProfile);
  if (!isRecoveryProfile(value)) {
    if (value) removeRecoveryProfile();
    return null;
  }
  return value;
}

export function removeRecoveryProfile() {
  try {
    localStorage.removeItem(keys.recoveryProfile);
    return true;
  } catch {
    return false;
  }
}

export function saveLastSuccessfulRun(metadata) {
  return writeJson(keys.lastSuccessfulRun, { version: 1, ...metadata });
}

export function loadLastSuccessfulRun() {
  const value = readJson(keys.lastSuccessfulRun);
  return value?.version === 1 ? value : null;
}
