import { text } from './dataService.js';

export const runtimeConfigDefaults = Object.freeze({
  version: 1,
  storageAccountName: '',
  governanceStorageAccountName: '',
  bffBaseUrl: '',
  entraTenantId: '',
  spaClientId: '',
  apiScope: '',
  redirectUri: '',
  defaultView: '',
  lockStorageAccountName: false,
  lockGovernanceStorageAccountName: false
});

function configuredString(value, fallback = '') {
  return typeof value === 'string' ? value.trim() : fallback;
}

function configuredAccount(value) {
  const accountName = configuredString(value).toLowerCase();
  return /^[a-z0-9]{3,24}$/.test(accountName) ? accountName : '';
}

function configuredGuid(value) {
  const guid = configuredString(value).toLowerCase();
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(guid) ? guid : '';
}

function configuredBffUrl(value) {
  const url = configuredString(value).replace(/\/+$/, '');
  return /^https:\/\/[^/]+(?:\/.*)?$/i.test(url) || /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$/.test(url) ? url : '';
}

function configuredApiScope(value) {
  const scope = configuredString(value);
  return /^api:\/\/[^/\s]+\/[A-Za-z0-9._-]+$/.test(scope) ? scope : '';
}

function configuredRedirectUri(value) {
  const redirectUri = configuredString(value);
  try {
    const parsed = new URL(redirectUri);
    return parsed.protocol === 'https:' ? parsed.href : '';
  } catch {
    return '';
  }
}

export async function loadRuntimeConfig(fetchImplementation = globalThis.fetch, embedded = false) {
  if (embedded || typeof fetchImplementation !== 'function') return { ...runtimeConfigDefaults };
  try {
    const response = await fetchImplementation('./config.json', { cache: 'no-store' });
    if (!response.ok) return { ...runtimeConfigDefaults };
    const payload = await response.json();
    if (!payload || typeof payload !== 'object' || Number(payload.version) !== 1) {
      return { ...runtimeConfigDefaults };
    }
    const defaults = payload.defaults && typeof payload.defaults === 'object' ? payload.defaults : payload;
    return {
      version: 1,
      storageAccountName: configuredAccount(defaults.storageAccountName),
      governanceStorageAccountName: configuredAccount(defaults.governanceStorageAccountName),
      bffBaseUrl: configuredBffUrl(defaults.bffBaseUrl),
      entraTenantId: configuredGuid(defaults.entraTenantId),
      spaClientId: configuredGuid(defaults.spaClientId),
      apiScope: configuredApiScope(defaults.apiScope),
      redirectUri: configuredRedirectUri(defaults.redirectUri),
      defaultView: ['summary', 'devices', 'review', 'governance'].includes(configuredString(defaults.defaultView))
        ? configuredString(defaults.defaultView)
        : '',
      lockStorageAccountName: Boolean(defaults.lockStorageAccountName),
      lockGovernanceStorageAccountName: Boolean(defaults.lockGovernanceStorageAccountName)
    };
  } catch {
    return { ...runtimeConfigDefaults };
  }
}

export function validateSasConnection(accountName, token) {
  if (!/^[a-z0-9]{3,24}$/.test(accountName)) {
    return 'Account names contain 3 to 24 lowercase letters or numbers.';
  }

  const parameters = new URLSearchParams(token.replace(/^\?/, ''));
  if (!parameters.get('sig') || !parameters.get('se')) {
    return 'The SAS token is incomplete.';
  }
  if (!text(parameters.get('ss')).includes('t') ||
      !text(parameters.get('srt')).includes('o') ||
      !text(parameters.get('sp')).includes('r')) {
    return 'Use an account SAS with Table, Object, and Read access.';
  }
  if (parameters.has('spr') && parameters.get('spr') !== 'https') {
    return 'Use a SAS token restricted to HTTPS only.';
  }

  const expiry = new Date(parameters.get('se'));
  if (Number.isNaN(expiry.getTime()) || expiry <= new Date()) {
    return 'The SAS token is expired or has an invalid expiry.';
  }
  return '';
}
