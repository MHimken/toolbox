import { createHash, timingSafeEqual } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { AppConfig } from './config.js';
import { ApiError } from './errors.js';

export interface CallerIdentity {
  authenticationType: 'Entra' | 'Recovery';
  ownerKey: string;
  tenantId?: string;
  objectId?: string;
  roles: readonly string[];
  claims?: JWTPayload;
}

export interface TokenVerifier {
  verify(token: string): Promise<CallerIdentity>;
}

export function recoveryOwnerKey(recoveryCode: string): string {
  const normalized = recoveryCode.trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(normalized)) {
    throw new ApiError(401, 'invalid_recovery_credential', 'The recovery credential is invalid.');
  }
  const bytes = Buffer.from(normalized.replaceAll('-', '+').replaceAll('_', '/') + '=', 'base64');
  if (bytes.length !== 32) throw new ApiError(401, 'invalid_recovery_credential', 'The recovery credential is invalid.');
  return `recovery:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function equalOwnerKeys(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export class EntraTokenVerifier implements TokenVerifier {
  private readonly jwks;

  constructor(private readonly config: AppConfig) {
    this.jwks = createRemoteJWKSet(
      new URL(`https://login.microsoftonline.com/${config.tenantId}/discovery/v2.0/keys`)
    );
  }

  async verify(token: string): Promise<CallerIdentity> {
    try {
      const { payload } = await jwtVerify(token, this.jwks, {
        audience: this.config.clientId,
        issuer: `https://login.microsoftonline.com/${this.config.tenantId}/v2.0`,
        algorithms: ['RS256']
      });
      const tenantId = typeof payload.tid === 'string' ? payload.tid.toLowerCase() : '';
      const objectId = typeof payload.oid === 'string' ? payload.oid.toLowerCase() : '';
      if (tenantId !== this.config.tenantId || !objectId) {
        throw new ApiError(401, 'invalid_identity_claims', 'The token is missing valid tid or oid claims.');
      }
      const roles = Array.isArray(payload.roles) ? payload.roles.filter((role): role is string => typeof role === 'string') : [];
      return {
        authenticationType: 'Entra',
        ownerKey: `entra:${tenantId}:${objectId}`,
        tenantId,
        objectId,
        roles,
        claims: payload
      };
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError(401, 'invalid_access_token', 'The access token could not be validated.');
    }
  }
}
