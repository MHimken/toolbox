# Local administrator governance API contract

Contract version: `2026-10-21`

This contract defines the protected backend boundary for personal profiles, allow rules, review actions, Admin mode, and auditing. The browser report may evaluate read-only data for display, but the backend is authoritative for identity, ownership, authorization, state transitions, concurrency, and writes.

## Identity and ownership

- Entra ownership is derived only from validated `tid` and `oid` token claims: `entra:<tid>:<oid>`.
- Recovery ownership is `recovery:<sha256>`, where the digest is derived from the 256-bit recovery secret. The plaintext secret is never stored by the API.
- Organization-owned governance entities use `org`.
- The API ignores client-supplied owner or actor values when an authenticated identity is available.
- A personal caller may read and write only its own owner partition. Governance reads and all governance writes require an assigned API role; approval, revocation, and privileged actions additionally require verified Admin mode.

## HTTP surface

All endpoints are under `/v1`, accept and return JSON, and return a correlation ID in `x-correlation-id`.

The initial BFF accepts either `Authorization: Bearer <API-token>` or `x-recovery-code`, never both. Recovery credentials are valid only for owner-scoped profile operations. Browser CORS is restricted to configured exact HTTPS origins.

An administrator may explicitly configure wildcard BFF CORS for controlled testing or broad hosting. This is less restrictive than exact origins and must be surfaced as a deployment warning. The API uses explicit headers rather than cookie authentication. An IIS same-origin reverse proxy is preferred when the report is hosted on IIS.

| Method and path | Purpose | Required authorization |
| --- | --- | --- |
| `GET /profile` | Read the caller's settings/profile | Authenticated Entra identity or valid recovery credential |
| `PUT /profile` | Create or replace caller-owned settings | Owner; `If-None-Match: *` for create or `If-Match` for replace |
| `POST /profile/recovery/rotate` | Rotate the recovery credential and invalidate the old digest | Current owner proof |
| `POST /profile/recovery/revoke` | Revoke recovery access | Current owner proof |
| `GET /rules?scope=mine` | Read caller-owned personal rules | Owner |
| `GET /rules?scope=governance` | Read governance rules | Assigned governance reader |
| `GET /identities/lookup?type=User\|Group&q=...` | Read-only Entra identity resolution | Entra identity and an assigned governance-reader API role |
| `POST /rules` | Create a personal draft or governance proposal | Owner; governance proposals require Entra identity |
| `PUT /rules/{ruleId}` | Update a mutable rule | Owner and matching ETag |
| `POST /rules/{ruleId}/submit` | Move a draft to `PendingApproval` | Owner and matching ETag |
| `POST /rules/{ruleId}/approve` | Activate a governance proposal | Admin mode and governance approver role |
| `POST /rules/{ruleId}/reject` | Reject a proposal | Admin mode and governance approver role |
| `POST /rules/{ruleId}/revoke` | Revoke an active governance rule | Admin mode and governance approver role |
| `GET /actions` | Read authorized action requests and outcomes | Owner for personal requests; assigned governance reader for the organization queue |
| `POST /actions` | Create an idempotent action request | Authenticated identity; privileged action types require Admin mode |
| `POST /actions/{actionId}/cancel` | Cancel an action before execution | Request owner or action operator |
| `POST /sessions/admin` | Establish short-lived Admin mode after a claims challenge | Entra identity, required authentication context, and active API role |
| `DELETE /sessions/admin` | End Admin mode | Authenticated identity |

Errors use `{ "code", "message", "correlationId", "details" }`. Ownership failures return `404` rather than revealing that another owner's entity exists. ETag conflicts return `412`. Duplicate idempotency keys return the original action with `200`, not a second request.

### Implemented Admin-mode deviations

- Admin mode is stateless on the backend. Every privileged request presents a token whose `acrs` claim contains the configured authentication context (default `c1`) and whose `iat` is no older than `ADMIN_SESSION_MAX_MINUTES` (default 30). Missing or stale step-up returns `401` with `admin_auth_context_required` or `admin_session_expired`, a `WWW-Authenticate` claims challenge, and `details.claims`.
- API roles: `LocalAdmin.Governance.Read`, `LocalAdmin.Governance.Approve`, `LocalAdmin.Governance.SelfApprove`, and `LocalAdmin.Actions.Operate`. Entering Admin mode requires Approve or Operate. Proposals require Read, Approve, or SelfApprove. Approving an own proposal requires both Approve and SelfApprove (four-eyes otherwise) and is audited as a self-approval.
- `POST /rules` creates governance proposals directly in `PendingApproval` and requires an `Idempotency-Key` UUID. Personal-rule creation, drafts, `PUT /rules/{ruleId}`, and `/submit` are deferred.
- Approve, reject, and revoke require an exact `If-Match` ETag; `*` is rejected.
- `POST /actions/{actionId}/cancel` accepts `{ "reason", "ownerKey" }`; `ownerKey` is required when an operator cancels another owner's action.

## Allow-rule entity

### Identity lookup and display metadata

`GET /identities/lookup` accepts `type=User|Group` and a trimmed query of 3-128 characters with no control characters. User queries match UPN/display-name prefixes; group queries match security-group display-name/mail prefixes; either accepts an exact Entra object GUID. OData literals are escaped, the Graph endpoint and selected fields are fixed, and at most 20 directory objects are returned with `truncated=true` when more exist.

The response is `{ identities: [{ sid, principalType, displayName, userPrincipalName, objectId, source, origin }], truncated }`. `source` is `Entra` or `AD`; `origin` is `directory`. Cloud SIDs are derived from immutable object GUIDs using Windows GUID byte order. Synced objects can return two choices: the Entra SID and `onPremisesSecurityIdentifier`. Clients must let the user choose; names must not become matching values.

The endpoint rejects unauthenticated/recovery callers and callers without a governance-reader role. The Function identity needs Graph `User.Read.All` and `Group.Read.All`. Queries/results have a bounded five-minute process-memory cache; a per-instance caller limit returns `429 directory_rate_limited` after ten requests per minute. Graph `403` returns `503 directory_permissions_required`; upstream throttling returns `429`; other upstream HTTP failures return `502`, not empty results.

`POST /rules` optionally accepts `principalDisplayName` (at most 256 characters) and `principalUserPrincipalName` (at most 1024), with no control characters. They are persisted as `PrincipalDisplayName` and `PrincipalUserPrincipalName`. These are unverified, informational snapshots supplied by the proposer, excluded from matching and security-relevant rule state hashes. The immutable SID remains mandatory in `principalSid` / `PrincipalValue`.

### Stored fields

`PartitionKey` is the authoritative owner key and `RowKey` is a random UUID. Required fields are:

- `SchemaVersion`, `RuleScope`, `Effect`, `PrincipalType`, `MatchType`, `PrincipalValue`;
- `PrincipalSource`, `MembershipScope`, `DeviceScopeType`;
- explicit join-state booleans;
- `Status`, `Reason`, `CreatedAtUtc`, and `CreatedBy`;
- optional source-group SID, device scope value, maximum device age, validity bounds, ticket, approval, rejection, and revocation metadata.

`Effect` is `Allow` or `Deny`. Personal rules may only allow; they cannot weaken or deny organizational policy. Exact-name matching is supported for review but governance approval should resolve the name to an immutable SID first.

### Evaluation precedence

1. Ignore invalid, rejected, revoked, future, or otherwise inactive rules.
2. Match principal type/value, source, membership path, source group, device scope, join state, maximum device age, and validity.
3. Evaluate governance rules before personal rules.
4. Within governance, the most specific tier wins: SID over exact name, then explicit source, membership, source group, exact/prefix device scope, and maximum age.
5. Conflicting `Allow` and `Deny` effects at the same highest specificity produce `Rule conflict`; no action may proceed.
6. A decisive governance deny produces `Governance denied`; a decisive allow produces `Governance approved`.
7. Only when no active governance rule matches may a personal allow produce `Personal acknowledgement`.
8. Pending and expired matches are reported after active rules. Otherwise the result is `No matching rule`.

Freshness and directory-presence states remain separate from policy status. The Review view may prioritize `Stale device`, `Unknown freshness`, or `Device missing from Entra`, but it must retain the underlying policy result.

## Rule states

Allowed states are `Draft`, `PendingApproval`, `Active`, `Expired`, `Rejected`, and `Revoked`.

- Personal rules: `Draft -> Active`, `Active -> Revoked`, with time-based expiry.
- Governance rules: `Draft -> PendingApproval -> Active`, or `PendingApproval -> Rejected`; active rules may become `Expired` or `Revoked`.
- Approval/rejection/revocation metadata is written only by the backend from the verified actor.
- Active governance rules are immutable except for revocation. Changes create a new draft with a new rule ID so audit history remains intact.

## Review actions

Each action uses an owner partition and random UUID `RowKey`. Required request fields include `CorrelationId`, `IdempotencyKey`, `ActionType`, device and principal targets, expected change, justification, requester owner key, timestamps, and `SchemaVersion`.

The lifecycle is:

```text
Requested -> Queued -> InProgress -> AwaitingInventory -> Succeeded
    |          |           |               |
    +------> Rejected      +-> Failed      +-> Failed/Expired
    +------> Cancelled
    +------> Expired
```

Only the backend worker can enter `InProgress`, `AwaitingInventory`, `Succeeded`, or `Failed`. `Succeeded` requires a later inventory cycle to confirm the expected state; a successful Graph, Intune, or AD call alone is not completion.

The idempotency key is unique per owner and action type. Replays return the original action. Workers also perform a current-state preflight before changing anything.

## Optimistic concurrency

- Creates use `If-None-Match: *`.
- Updates, transitions, revocations, and deletes require the exact ETag last returned by the API in `If-Match`.
- Wildcard `If-Match: *` is not accepted for governance, profile, or action mutations.
- A `412 Precondition Failed` response includes the current safe metadata and requires the caller to reload and reconsider the operation.

## Audit schema

Every accepted mutation emits an append-only audit event with:

- `EventId`, `CorrelationId`, `OccurredAtUtc`, `SchemaVersion`;
- validated tenant/object actor IDs and effective API roles;
- owner partition, entity type, entity ID, operation, previous and resulting state;
- request idempotency key, target identifiers, justification/ticket;
- authentication-context and Admin-mode session identifiers where applicable;
- outcome, error code, executor identity, and external operation identifiers;
- hashes of before/after security-relevant fields rather than credentials or tokens.

Audit records never contain SAS values, OAuth tokens, recovery secrets, authorization headers, or unrestricted Graph/AD response bodies.

Because profile and audit records are stored in separate Azure Tables, audit writes are not atomic with the profile mutation. A committed mutation followed by an audit failure returns `503 audit_write_failed` with `details.mutationCommitted = true`; callers must reload before retrying. Recovery rotation similarly reports `recovery_rotation_partial_failure` when create-before-delete cannot remove the old owner or roll back the new one.
