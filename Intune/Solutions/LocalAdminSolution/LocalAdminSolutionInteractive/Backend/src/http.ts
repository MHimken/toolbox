import { randomUUID } from 'node:crypto';
import type { HttpRequest, HttpResponseInit, InvocationContext } from '@azure/functions';
import type { AppConfig } from './config.js';
import { ApiError } from './errors.js';
import { recoveryOwnerKey, type CallerIdentity, type TokenVerifier } from './identity.js';

export function correlationId(request: HttpRequest): string {
  const supplied = request.headers.get('x-correlation-id')?.trim();
  return supplied && /^[A-Za-z0-9._:-]{1,100}$/.test(supplied) ? supplied : randomUUID();
}

export async function authenticate(request: HttpRequest, verifier: TokenVerifier): Promise<CallerIdentity> {
  const authorization = request.headers.get('authorization')?.trim() || '';
  const recoveryCode = request.headers.get('x-recovery-code')?.trim() || '';
  if (authorization && recoveryCode) {
    throw new ApiError(400, 'ambiguous_authentication', 'Use either a bearer token or a recovery credential, not both.');
  }
  if (authorization) {
    const match = /^Bearer (.+)$/i.exec(authorization);
    if (!match?.[1]) throw new ApiError(401, 'invalid_authorization_header', 'The Authorization header is invalid.');
    return verifier.verify(match[1]);
  }
  if (recoveryCode) {
    return { authenticationType: 'Recovery', ownerKey: recoveryOwnerKey(recoveryCode), roles: [] };
  }
  throw new ApiError(401, 'authentication_required', 'Authentication is required.');
}

export function corsHeaders(request: HttpRequest, config: AppConfig): Record<string, string> {
  const origin = request.headers.get('origin');
  if (!origin) return {};
  const allowAnyOrigin = config.allowedOrigins.has('*');
  if (!allowAnyOrigin && !config.allowedOrigins.has(origin)) throw new ApiError(403, 'origin_not_allowed', 'The request origin is not allowed.');
  return {
    'Access-Control-Allow-Origin': allowAnyOrigin ? '*' : origin,
    'Access-Control-Allow-Headers': 'authorization,content-type,idempotency-key,if-match,if-none-match,x-correlation-id,x-recovery-code',
    'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,OPTIONS',
    'Access-Control-Expose-Headers': 'etag,www-authenticate,x-correlation-id',
    ...(allowAnyOrigin ? {} : { Vary: 'Origin' })
  };
}

export function response(
  status: number,
  body: unknown,
  request: HttpRequest,
  config: AppConfig,
  correlation: string,
  extraHeaders: Record<string, string> = {}
): HttpResponseInit {
  return {
    status,
    jsonBody: body,
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'application/json',
      'x-correlation-id': correlation,
      ...corsHeaders(request, config),
      ...extraHeaders
    }
  };
}

export function errorResponse(
  error: unknown,
  request: HttpRequest,
  config: AppConfig,
  correlation: string,
  context: InvocationContext
): HttpResponseInit {
  const apiError = error instanceof ApiError
    ? error
    : new ApiError(500, 'internal_error', 'The request could not be completed.');
  if (apiError.status >= 500) context.error(error);
  let cors: Record<string, string> = {};
  try {
    cors = corsHeaders(request, config);
  } catch {
    // Do not reflect an unapproved origin on an error response.
  }
  return {
    status: apiError.status,
    jsonBody: {
      code: apiError.code,
      message: apiError.message,
      correlationId: correlation,
      ...(apiError.details !== undefined ? { details: apiError.details } : {})
    },
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'application/json',
      'x-correlation-id': correlation,
      ...cors,
      ...(apiError.headers || {})
    }
  };
}
