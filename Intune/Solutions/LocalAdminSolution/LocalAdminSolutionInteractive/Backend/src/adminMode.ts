import { createHash } from 'node:crypto';
import type { AppConfig } from './config.js';
import { ApiError } from './errors.js';
import type { CallerIdentity } from './identity.js';

export const AppRoles = Object.freeze({
  GovernanceRead: 'LocalAdmin.Governance.Read',
  GovernanceApprove: 'LocalAdmin.Governance.Approve',
  GovernanceSelfApprove: 'LocalAdmin.Governance.SelfApprove',
  ActionsOperate: 'LocalAdmin.Actions.Operate'
});

export type AppRole = typeof AppRoles[keyof typeof AppRoles];

export const knownRoles: readonly AppRole[] = Object.values(AppRoles);
export const governanceReaderRoles: readonly AppRole[] = [
  AppRoles.GovernanceRead,
  AppRoles.GovernanceApprove,
  AppRoles.GovernanceSelfApprove,
  AppRoles.ActionsOperate
];
export const adminModeRoles: readonly AppRole[] = [AppRoles.GovernanceApprove, AppRoles.ActionsOperate];

export interface AdminSession {
  sessionId: string;
  ownerKey: string;
  authContextId: string;
  issuedAtUtc: string;
  expiresAtUtc: string;
  roles: AppRole[];
  capabilities: {
    readGovernance: boolean;
    approveRules: boolean;
    selfApprove: boolean;
    operateActions: boolean;
  };
}

export function hasRole(identity: CallerIdentity, role: AppRole): boolean {
  return identity.roles.includes(role);
}

export function effectiveRoles(identity: CallerIdentity): AppRole[] {
  return knownRoles.filter(role => identity.roles.includes(role));
}

export function requireEntra(identity: CallerIdentity, message: string): void {
  if (identity.authenticationType !== 'Entra') throw new ApiError(403, 'entra_identity_required', message);
}

export function requireAnyRole(identity: CallerIdentity, roles: readonly AppRole[], message: string): void {
  requireEntra(identity, message);
  if (!roles.some(role => identity.roles.includes(role))) {
    throw new ApiError(403, 'role_required', message, { requiredRoles: roles });
  }
}

export function claimsChallenge(authContextId: string): string {
  return JSON.stringify({ access_token: { acrs: { essential: true, value: authContextId } } });
}

function challengeError(code: string, message: string, authContextId: string): ApiError {
  const claims = claimsChallenge(authContextId);
  return new ApiError(401, code, message, { claims, authContextId }, {
    'WWW-Authenticate': `Bearer realm="", error="insufficient_claims", error_description="${message.replaceAll('"', "'")}", claims="${Buffer.from(claims).toString('base64')}"`
  });
}

function tokenAuthContexts(identity: CallerIdentity): string[] {
  const acrs = identity.claims?.acrs;
  if (Array.isArray(acrs)) return acrs.filter((value): value is string => typeof value === 'string').map(value => value.toLowerCase());
  return typeof acrs === 'string' ? acrs.split(/[\s,]+/).filter(Boolean).map(value => value.toLowerCase()) : [];
}

/**
 * Admin mode is stateless: every privileged request must present an access token that carries the configured
 * Conditional Access authentication context and that was issued within the configured absolute session lifetime.
 */
export function requireAdminMode(
  identity: CallerIdentity,
  config: AppConfig,
  now: Date,
  requiredRoles: readonly AppRole[] = adminModeRoles
): AdminSession {
  requireAnyRole(identity, requiredRoles, 'An assigned Admin-mode API role is required for this operation.');
  if (!tokenAuthContexts(identity).includes(config.adminAuthContextId)) {
    throw challengeError(
      'admin_auth_context_required',
      'Admin mode requires a fresh sign-in that satisfies the Conditional Access authentication context.',
      config.adminAuthContextId
    );
  }
  const issuedAt = Number(identity.claims?.iat);
  const expiresAt = Number(identity.claims?.exp);
  const maximumAgeMs = config.adminSessionMaxMinutes * 60_000;
  if (!Number.isFinite(issuedAt) || now.getTime() - issuedAt * 1000 > maximumAgeMs || issuedAt * 1000 - now.getTime() > 300_000) {
    throw challengeError(
      'admin_session_expired',
      'The Admin-mode session expired. Sign in again to continue.',
      config.adminAuthContextId
    );
  }
  const tokenId = typeof identity.claims?.uti === 'string' ? identity.claims.uti : `${identity.ownerKey}:${issuedAt}`;
  const sessionExpiry = Math.min(
    issuedAt * 1000 + maximumAgeMs,
    Number.isFinite(expiresAt) ? expiresAt * 1000 : Number.POSITIVE_INFINITY
  );
  return {
    sessionId: createHash('sha256').update(`admin-session\0${tokenId}`).digest('hex').slice(0, 32),
    ownerKey: identity.ownerKey,
    authContextId: config.adminAuthContextId,
    issuedAtUtc: new Date(issuedAt * 1000).toISOString(),
    expiresAtUtc: new Date(sessionExpiry).toISOString(),
    roles: effectiveRoles(identity),
    capabilities: {
      readGovernance: governanceReaderRoles.some(role => identity.roles.includes(role)),
      approveRules: hasRole(identity, AppRoles.GovernanceApprove),
      selfApprove: hasRole(identity, AppRoles.GovernanceApprove) && hasRole(identity, AppRoles.GovernanceSelfApprove),
      operateActions: hasRole(identity, AppRoles.ActionsOperate)
    }
  };
}
