import { app } from '@azure/functions';
import { createProfileHandlers } from '../app.js';
import { loadConfig } from '../config.js';
import { EntraTokenVerifier } from '../identity.js';
import { ProfileService } from '../profileService.js';
import { ActionService } from '../actionService.js';
import { AdminSessionService } from '../adminSessionService.js';
import { RuleService } from '../ruleService.js';
import { AzureTableGovernanceRepository } from '../repositories.js';
import { DirectoryLookupService } from '../directoryService.js';

const config = loadConfig();
const repository = new AzureTableGovernanceRepository(config);
const handlers = createProfileHandlers({
  config,
  verifier: new EntraTokenVerifier(config),
  profiles: new ProfileService(repository),
  actions: new ActionService(repository, config),
  rules: new RuleService(repository, config),
  adminSessions: new AdminSessionService(repository, config),
  directory: new DirectoryLookupService()
});

app.http('IdentityLookupOptions', {
  methods: ['OPTIONS'],
  authLevel: 'anonymous',
  route: 'identities/lookup',
  handler: handlers.options
});

app.http('IdentityLookup', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'identities/lookup',
  handler: handlers.lookupIdentities
});

app.http('ProfileOptions', {
  methods: ['OPTIONS'],
  authLevel: 'anonymous',
  route: 'profile',
  handler: handlers.options
});

app.http('ProfileGet', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'profile',
  handler: handlers.get
});

app.http('ProfilePut', {
  methods: ['PUT'],
  authLevel: 'anonymous',
  route: 'profile',
  handler: handlers.put
});

app.http('RecoveryRotate', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'profile/recovery/rotate',
  handler: handlers.rotate
});

app.http('RecoveryRevoke', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'profile/recovery/revoke',
  handler: handlers.revoke
});

app.http('ActionOptions', {
  methods: ['OPTIONS'],
  authLevel: 'anonymous',
  route: 'actions',
  handler: handlers.options
});

app.http('ActionRequestGovernanceException', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'actions',
  handler: handlers.requestGovernanceException
});

app.http('ActionList', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'actions',
  handler: handlers.listActions
});

app.http('ActionCancelOptions', {
  methods: ['OPTIONS'],
  authLevel: 'anonymous',
  route: 'actions/{actionId}/cancel',
  handler: handlers.options
});

app.http('ActionCancel', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'actions/{actionId}/cancel',
  handler: handlers.cancelAction
});

app.http('RuleOptions', {
  methods: ['OPTIONS'],
  authLevel: 'anonymous',
  route: 'rules',
  handler: handlers.options
});

app.http('RuleList', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'rules',
  handler: handlers.listRules
});

app.http('RulePropose', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'rules',
  handler: handlers.proposeRule
});

app.http('RuleTransitionOptions', {
  methods: ['OPTIONS'],
  authLevel: 'anonymous',
  route: 'rules/{ruleId}/{operation}',
  handler: handlers.options
});

app.http('RuleTransition', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'rules/{ruleId}/{operation}',
  handler: handlers.transitionRule
});

app.http('AdminSessionOptions', {
  methods: ['OPTIONS'],
  authLevel: 'anonymous',
  route: 'sessions/admin',
  handler: handlers.options
});

app.http('AdminSessionEnter', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'sessions/admin',
  handler: handlers.enterAdminMode
});

app.http('AdminSessionExit', {
  methods: ['DELETE'],
  authLevel: 'anonymous',
  route: 'sessions/admin',
  handler: handlers.exitAdminMode
});