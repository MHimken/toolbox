import type { HttpRequest, HttpResponseInit, InvocationContext } from '@azure/functions';
import type { AppConfig } from './config.js';
import { ApiError } from './errors.js';
import { authenticate, correlationId, errorResponse, response } from './http.js';
import type { TokenVerifier } from './identity.js';
import { validateSettings } from './models.js';
import { ProfileService } from './profileService.js';
import { ActionService } from './actionService.js';
import { AdminSessionService } from './adminSessionService.js';
import { RuleService } from './ruleService.js';
import type { RuleTransition } from './ruleModels.js';

export interface AppDependencies {
  config: AppConfig;
  verifier: TokenVerifier;
  profiles: ProfileService;
  actions: ActionService;
  rules: RuleService;
  adminSessions: AdminSessionService;
}

async function jsonBody(request: HttpRequest, optional = false): Promise<unknown> {
  const raw = await request.text();
  if (!raw.trim()) {
    if (optional) return {};
    throw new ApiError(400, 'invalid_json', 'The request body must be valid JSON.');
  }
  try {
    return JSON.parse(raw) as unknown;
  } catch {
    throw new ApiError(400, 'invalid_json', 'The request body must be valid JSON.');
  }
}

export function createProfileHandlers(dependencies: AppDependencies) {
  const execute = async (
    request: HttpRequest,
    context: InvocationContext,
    operation: (correlation: string) => Promise<HttpResponseInit>
  ): Promise<HttpResponseInit> => {
    const id = correlationId(request);
    try {
      return await operation(id);
    } catch (error) {
      return errorResponse(error, request, dependencies.config, id, context);
    }
  };

  return {
    options: async (request: HttpRequest, context: InvocationContext) =>
      execute(request, context, async id => response(204, null, request, dependencies.config, id)),

    get: async (request: HttpRequest, context: InvocationContext) =>
      execute(request, context, async id => {
        const identity = await authenticate(request, dependencies.verifier);
        const profile = await dependencies.profiles.get(identity);
        return response(200, profile, request, dependencies.config, id, profile.etag ? { etag: profile.etag } : {});
      }),

    put: async (request: HttpRequest, context: InvocationContext) =>
      execute(request, context, async id => {
        const identity = await authenticate(request, dependencies.verifier);
        const settings = validateSettings((await request.json() as { settings?: unknown }).settings);
        const ifNoneMatch = request.headers.get('if-none-match');
        const ifMatch = request.headers.get('if-match') || undefined;
        if (ifNoneMatch && ifNoneMatch !== '*') throw new ApiError(400, 'invalid_precondition', 'If-None-Match must be *.');
        if (ifNoneMatch && ifMatch) throw new ApiError(400, 'ambiguous_precondition', 'Use If-Match or If-None-Match, not both.');
        if (!ifNoneMatch && !ifMatch) throw new ApiError(428, 'etag_required', 'If-Match or If-None-Match is required.');
        const profile = await dependencies.profiles.put(identity, settings, ifMatch, ifNoneMatch === '*', id);
        return response(ifNoneMatch ? 201 : 200, profile, request, dependencies.config, id, profile.etag ? { etag: profile.etag } : {});
      }),

    rotate: async (request: HttpRequest, context: InvocationContext) =>
      execute(request, context, async id => {
        const identity = await authenticate(request, dependencies.verifier);
        const body = await request.json() as { newRecoveryCode?: unknown };
        if (typeof body.newRecoveryCode !== 'string') throw new ApiError(400, 'invalid_request', 'newRecoveryCode is required.');
        const profile = await dependencies.profiles.rotateRecovery(
          identity,
          body.newRecoveryCode,
          request.headers.get('if-match') || undefined,
          id
        );
        return response(200, profile, request, dependencies.config, id, profile.etag ? { etag: profile.etag } : {});
      }),

    revoke: async (request: HttpRequest, context: InvocationContext) =>
      execute(request, context, async id => {
        const identity = await authenticate(request, dependencies.verifier);
        await dependencies.profiles.revokeRecovery(identity, request.headers.get('if-match') || undefined, id);
        return response(204, null, request, dependencies.config, id);
      }),

    requestGovernanceException: async (request: HttpRequest, context: InvocationContext) =>
      execute(request, context, async id => {
        const identity = await authenticate(request, dependencies.verifier);
        const payload = await jsonBody(request);
        const result = await dependencies.actions.requestGovernanceException(
          identity,
          payload,
          request.headers.get('idempotency-key')?.trim() || '',
          id
        );
        return response(result.replay ? 200 : 202, result.action, request, dependencies.config, id,
          result.action.etag ? { etag: result.action.etag } : {});
      }),

    listActions: async (request: HttpRequest, context: InvocationContext) =>
      execute(request, context, async id => {
        const identity = await authenticate(request, dependencies.verifier);
        const result = await dependencies.actions.list(identity, request.query.get('scope') || 'mine');
        return response(200, result, request, dependencies.config, id);
      }),

    cancelAction: async (request: HttpRequest, context: InvocationContext) =>
      execute(request, context, async id => {
        const identity = await authenticate(request, dependencies.verifier);
        const action = await dependencies.actions.cancel(
          identity,
          request.params.actionId || '',
          await jsonBody(request),
          request.headers.get('if-match') || undefined,
          id
        );
        return response(200, action, request, dependencies.config, id, action.etag ? { etag: action.etag } : {});
      }),

    listRules: async (request: HttpRequest, context: InvocationContext) =>
      execute(request, context, async id => {
        const identity = await authenticate(request, dependencies.verifier);
        const result = await dependencies.rules.list(identity, request.query.get('scope') || 'mine');
        return response(200, result, request, dependencies.config, id);
      }),

    proposeRule: async (request: HttpRequest, context: InvocationContext) =>
      execute(request, context, async id => {
        const identity = await authenticate(request, dependencies.verifier);
        const result = await dependencies.rules.propose(
          identity,
          await jsonBody(request),
          request.headers.get('idempotency-key')?.trim() || '',
          id
        );
        return response(result.replay ? 200 : 201, result.rule, request, dependencies.config, id,
          result.rule.ETag ? { etag: result.rule.ETag } : {});
      }),

    transitionRule: async (request: HttpRequest, context: InvocationContext) =>
      execute(request, context, async id => {
        const operation = request.params.operation || '';
        if (!['approve', 'reject', 'revoke'].includes(operation)) {
          throw new ApiError(404, 'operation_not_found', 'The rule operation is not supported.');
        }
        const identity = await authenticate(request, dependencies.verifier);
        const rule = await dependencies.rules.transition(
          identity,
          (request.params.ruleId || '').toLowerCase(),
          operation as RuleTransition,
          await jsonBody(request, true),
          request.headers.get('if-match') || undefined,
          id
        );
        return response(200, rule, request, dependencies.config, id, rule.ETag ? { etag: rule.ETag } : {});
      }),

    enterAdminMode: async (request: HttpRequest, context: InvocationContext) =>
      execute(request, context, async id => {
        const identity = await authenticate(request, dependencies.verifier);
        const session = await dependencies.adminSessions.enter(identity, id);
        return response(200, session, request, dependencies.config, id);
      }),

    exitAdminMode: async (request: HttpRequest, context: InvocationContext) =>
      execute(request, context, async id => {
        const identity = await authenticate(request, dependencies.verifier);
        await dependencies.adminSessions.exit(identity, id, request.query.get('reason') || 'user');
        return response(204, null, request, dependencies.config, id);
      })
  };
}
