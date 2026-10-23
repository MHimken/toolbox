import { DefaultAzureCredential } from '@azure/identity';
import { governanceReaderRoles, requireAnyRole } from './adminMode.js';
import { ApiError } from './errors.js';
import type { CallerIdentity } from './identity.js';

export interface DirectoryIdentity {
  sid: string;
  principalType: 'User' | 'Group';
  displayName: string;
  userPrincipalName: string;
  objectId: string;
  source: 'Entra' | 'AD';
  origin: 'directory';
}

export interface DirectoryLookupResult {
  identities: DirectoryIdentity[];
  truncated: boolean;
}

const guidPattern = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const sidPattern = /^S-\d(?:-\d+)+$/i;

function directoryIdentities(value: unknown, principalType: 'User' | 'Group'): DirectoryIdentity[] {
  if (!value || typeof value !== 'object') throw new ApiError(502, 'invalid_directory_response', 'Entra returned an invalid identity.');
  const item = value as Record<string, unknown>;
  if (typeof item.id !== 'string' || !guidPattern.test(item.id)) {
    throw new ApiError(502, 'invalid_directory_response', 'Entra returned an invalid object ID.');
  }
  const bytes = Buffer.from(item.id.replaceAll('-', ''), 'hex');
  // Windows GUID byte order reverses the first three GUID components only.
  const cloudSid = `S-1-12-1-${[
    bytes.readUInt32BE(0),
    bytes.readUInt16BE(4) + bytes.readUInt16BE(6) * 65536,
    bytes.readUInt32LE(8),
    bytes.readUInt32LE(12)
  ].join('-')}`;
  const identity: DirectoryIdentity = {
    sid: cloudSid,
    principalType,
    displayName: typeof item.displayName === 'string' ? item.displayName : item.id,
    userPrincipalName: typeof item.userPrincipalName === 'string' ? item.userPrincipalName : '',
    objectId: item.id,
    source: 'Entra',
    origin: 'directory'
  };
  const onPremisesSid = item.onPremisesSecurityIdentifier;
  if (typeof onPremisesSid === 'string' && sidPattern.test(onPremisesSid) && onPremisesSid.toUpperCase() !== identity.sid) {
    return [identity, { ...identity, sid: onPremisesSid.toUpperCase(), source: 'AD' }];
  }
  return [identity];
}

export class DirectoryLookupService {
  private readonly cache = new Map<string, { expires: number; result: DirectoryLookupResult }>();
  private readonly requests = new Map<string, { expires: number; count: number }>();

  constructor(
    private readonly credential: Pick<DefaultAzureCredential, 'getToken'> = new DefaultAzureCredential(),
    private readonly fetchImplementation: typeof fetch = fetch,
    private readonly now: () => number = Date.now
  ) {}

  async lookup(identity: CallerIdentity, type: string, rawQuery: string): Promise<DirectoryLookupResult> {
    requireAnyRole(identity, governanceReaderRoles, 'A governance API role is required for Entra identity lookup.');
    const query = rawQuery.trim();
    if ((type !== 'User' && type !== 'Group') || query.length < 3 || query.length > 128 || /[\u0000-\u001f\u007f]/.test(query)) {
      throw new ApiError(400, 'invalid_identity_query', 'Choose User or Group and enter 3 to 128 characters without control characters.');
    }
    const now = this.now();
    for (const [key, value] of this.requests) if (value.expires <= now) this.requests.delete(key);
    const usage = this.requests.get(identity.ownerKey);
    if ((usage?.count || 0) >= 10 || (!usage && this.requests.size >= 1000)) {
      throw new ApiError(429, 'directory_rate_limited', 'Too many directory searches. Wait a minute before trying again.', undefined, { 'Retry-After': '60' });
    }
    this.requests.set(identity.ownerKey, { expires: usage?.expires || now + 60_000, count: (usage?.count || 0) + 1 });
    for (const [key, value] of this.cache) if (value.expires <= now) this.cache.delete(key);
    const key = `${type}:${query.toLowerCase()}`;
    const cached = this.cache.get(key);
    if (cached) return cached.result;

    const token = await this.credential.getToken('https://graph.microsoft.com/.default');
    if (!token) throw new ApiError(503, 'directory_authentication_failed', 'The backend could not authenticate to Microsoft Graph.');
    const literal = query.replaceAll("'", "''");
    const identityFilter = guidPattern.test(query)
      ? `id eq '${literal}'`
      : type === 'User'
        ? `(startsWith(userPrincipalName,'${literal}') or startsWith(displayName,'${literal}'))`
        : `(startsWith(displayName,'${literal}') or startsWith(mail,'${literal}'))`;
    const filter = type === 'Group' ? `securityEnabled eq true and (${identityFilter})` : identityFilter;
    const parameters = new URLSearchParams({
      '$filter': filter,
      '$select': type === 'User' ? 'id,displayName,userPrincipalName,onPremisesSecurityIdentifier' : 'id,displayName,onPremisesSecurityIdentifier',
      '$top': '20'
    });
    const response = await this.fetchImplementation(`https://graph.microsoft.com/v1.0/${type === 'User' ? 'users' : 'groups'}?${parameters}`, {
      headers: { Authorization: `Bearer ${token.token}`, Accept: 'application/json' },
      signal: AbortSignal.timeout(10_000)
    });
    if (response.status === 403) {
      throw new ApiError(503, 'directory_permissions_required', 'The Function managed identity requires Microsoft Graph User.Read.All and Group.Read.All application permissions.');
    }
    if (response.status === 429) {
      throw new ApiError(429, 'directory_rate_limited', 'Microsoft Graph is throttling searches. Wait before trying again.', undefined, { 'Retry-After': '60' });
    }
    if (!response.ok) throw new ApiError(502, 'directory_lookup_failed', 'Microsoft Graph could not complete the identity search.');
    const payload: unknown = await response.json();
    if (!payload || typeof payload !== 'object' || !('value' in payload) || !Array.isArray(payload.value)) {
      throw new ApiError(502, 'invalid_directory_response', 'Microsoft Graph returned an invalid search response.');
    }
    const result = {
      identities: payload.value.slice(0, 20).flatMap(value => directoryIdentities(value, type)),
      truncated: payload.value.length > 20 || '@odata.nextLink' in payload
    };
    const oldest = this.cache.keys().next().value;
    if (this.cache.size >= 100 && oldest !== undefined) this.cache.delete(oldest);
    this.cache.set(key, { expires: now + 5 * 60_000, result });
    return result;
  }
}
