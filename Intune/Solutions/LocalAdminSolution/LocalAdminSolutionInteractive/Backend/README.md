# Local Admin Solution BFF

This Azure Functions TypeScript application is the protected backend-for-frontend for personal profiles and future governance/admin operations. It validates Microsoft Entra access tokens, derives owner partitions from immutable `tid` and `oid` claims, supports recovery-code ownership, accesses Azure Tables through managed identity, requires ETags for mutations, and writes append-only audit records.

## Implemented endpoints

| Method | Route | Purpose |
|---|---|---|
| `OPTIONS` | `/v1/profile` | Exact-origin CORS preflight |
| `GET` | `/v1/profile` | Load the caller-owned profile |
| `PUT` | `/v1/profile` | Create or replace caller-owned settings |
| `POST` | `/v1/profile/recovery/rotate` | Move a recovery-owned profile to a new recovery owner |
| `POST` | `/v1/profile/recovery/revoke` | Delete a recovery-owned profile |
| `OPTIONS` | `/v1/actions` | Exact-origin CORS preflight |
| `POST` | `/v1/actions` | Submit an auditable governance-exception request |
| `GET` | `/v1/actions?scope=mine\|all` | List own actions, or all actions with a governance role |
| `POST` | `/v1/actions/{id}/cancel` | Cancel an own action, or another owner's action in Admin mode with `LocalAdmin.Actions.Operate` |
| `POST`/`DELETE` | `/v1/sessions/admin` | Verify or end Admin mode (audited) |
| `GET` | `/v1/rules?scope=governance\|mine` | List governance rules (governance role) or own proposals |
| `POST` | `/v1/rules` | Propose a governance rule (`Idempotency-Key` UUID required) |
| `POST` | `/v1/rules/{id}/approve\|reject\|revoke` | Admin-mode rule transitions with `If-Match` |
| `GET` | `/v1/identities/lookup?type=User\|Group&q=...` | Bounded Entra identity search; Entra identity plus a governance-reader API role |

The Admin-mode route is `sessions/admin`, not `admin/session`: Azure Functions reserves routes beginning with `admin` or `runtime`, even when a custom route prefix is configured.

Admin mode requires an Entra token containing an app role and the Conditional Access authentication context `ADMIN_AUTH_CONTEXT_ID` in `acrs`, issued within `ADMIN_SESSION_MAX_MINUTES`. Otherwise the API returns `401` with a `WWW-Authenticate` claims challenge and `details.claims`, which the browser passes to MSAL. Roles: `LocalAdmin.Governance.Read` (read/propose), `LocalAdmin.Governance.Approve` (approve/reject/revoke; four-eyes), `LocalAdmin.Governance.SelfApprove` (with Approve, permits approving own proposals), and `LocalAdmin.Actions.Operate` (cancel other owners' actions).

Use either `Authorization: Bearer <API-token>` or `x-recovery-code: <43-character-code>`, never both. Recovery codes are hashed to derive the owner key and are not persisted by the API.

Create a profile with `If-None-Match: *`. Replace, rotate, or revoke with the exact ETag returned by the previous API response in `If-Match`.

## Required configuration

Copy `local.settings.example.json` to the git-ignored `local.settings.json` for local Functions execution:

- `TENANT_ID` — the allowed tenant GUID.
- `API_CLIENT_ID` — the exposed API application's client ID and required token audience.
- `SPA_CLIENT_ID` — the only trusted SPA client application ID; the BFF checks the access token's `azp` (or v1 `appid`) claim against it.
- `SPA_CLIENT_ID` — the explicitly trusted SPA client application ID; access tokens without a matching `azp` (or v1 `appid`) claim are rejected.
- `GOVERNANCE_TABLE_ENDPOINT` — the governance account's HTTPS Table endpoint.
- `ALLOWED_ORIGINS` — comma-separated exact HTTPS report origins. An explicit `*` is supported for controlled testing or intentionally broad hosting, but exact origins are strongly recommended.
- `ADMIN_AUTH_CONTEXT_ID` — optional Conditional Access authentication context (`c1`–`c99`); defaults to `c1`.
- `ADMIN_SESSION_MAX_MINUTES` — optional Admin-mode lifetime after step-up (5–240); defaults to `30`.

The Function managed identity needs `Storage Table Data Contributor` on:

- `LocalAdminAllowRules`;
- `LocalAdminUserSettings`;
- `LocalAdminReviewActions`;
- `LocalAdminAuditRecords`.

The deployment creates these tables and grants the Function managed identity table-scoped contributor access.

Directory lookup additionally requires `User.Read.All` and `Group.Read.All` Microsoft Graph application permissions on the **Function** managed identity. Grant them explicitly with `-ConfigureBffDirectoryLookup` on a deployment or resumed `-RepublishBff` run. Automation identity grants do not apply to the Function. Directory lookup is read-only, does not require Admin-mode step-up, rejects recovery/SAS credentials, and is restricted to the same API roles as governance reads. It uses the existing `DefaultAzureCredential` dependency, bounded five-minute in-memory caching and ten requests per caller per minute per Function instance. Browser and backend caches are not persistent; the per-instance rate limit is not a distributed gateway quota. Graph permission/throttling failures are returned explicitly rather than treated as no matches.

Rule proposals optionally accept `principalDisplayName` (256 characters) and `principalUserPrincipalName` (1024 characters), persisted as informational PascalCase entity columns. Both reject control characters. Neither is trusted for identity verification, authorization, or matching; `principalSid` remains mandatory.

### Governance-exception requests

Submit with an Entra bearer token and a UUID `Idempotency-Key` header:

```json
{
  "computerSid": "S-1-5-21-10-20-30-1001",
  "principalSid": "S-1-5-21-40-50-60-2001",
  "justification": "Required for the approved maintenance window.",
  "ticketReference": "CHG-1234"
}
```

The endpoint creates a `Requested` entity in `LocalAdminReviewActions` under the caller's Entra owner partition and writes a corresponding audit record. Retrying the same body with the same idempotency key returns the existing request; reusing that key with different content returns `409 idempotency_conflict`. Recovery credentials are not accepted. This endpoint only submits a request: it does not create or approve a governance rule and does not perform endpoint, Graph, or directory changes.

## Development

```powershell
npm install
npm run check
```

`npm run check` performs a strict TypeScript build and focused tests without requiring Azure Functions Core Tools or Azure credentials. Functions Core Tools is needed only to host the HTTP application locally.

The production service uses `DefaultAzureCredential`; it does not accept Storage keys or SAS tokens. Do not put Entra client secrets, recovery codes, access tokens, or Storage credentials in `local.settings.json`.

### Browser profile integration

The LiveHTML Settings view contains the client for these endpoints. Profiles include report preferences and bounded per-view column order/width layouts. It uses the pinned, self-hosted `@azure/msal-browser` package with authorization-code plus PKCE popup authentication. MSAL cache storage is `memoryStorage`; OAuth access tokens are not written to local or session storage.

When `bffBaseUrl`, `entraTenantId`, `spaClientId`, `apiScope`, and the exact SPA `redirectUri` are present in public `config.json`, the user can sign in and automatically load the Entra-owned profile. The browser derives no owner key and sends no owner identifier; the BFF derives ownership from validated `tid` and `oid` claims. The BFF generates correlation IDs server-side and returns them in responses. Recovery-profile requests send the recovery code only in the `x-recovery-code` header over HTTPS.

The SPA app registration must list the exact hosted report URL used by MSAL as a Single-page application redirect URI and must be granted the configured delegated API scope. A same-origin IIS reverse proxy may be used for the BFF URL, but Microsoft Entra endpoints still require outbound browser access.

### IIS hosting

The Azure Functions application cannot run inside the same IIS static-site process. For IIS-first hosting, deploy the Function App separately and use IIS URL Rewrite plus Application Request Routing to reverse proxy a path such as `/localadmin-api/` to the Function. This gives the browser one apparent origin and can remove browser CORS requirements between the report and BFF.

Running on the same Windows server is possible only as a separately managed Functions container/runtime or Node service behind IIS. Functions Core Tools is a development host and should not be used as the production service.

If `ALLOWED_ORIGINS=*`, any origin may issue browser requests to the API. The API does not use cookies, but malicious JavaScript that obtains a bearer token or recovery code could submit it. Use the wildcard only after accepting that exposure.

## Reliability boundary

Azure Table profile and audit writes cannot be transacted across tables. If a mutation commits but its audit write fails, the API returns `503 audit_write_failed` with `details.mutationCommitted = true`. The client must reload before retrying. Recovery rotation uses create-before-delete and attempts to roll back the new owner if removal of the old owner fails; unrecoverable dual-owner outcomes return `recovery_rotation_partial_failure`.
