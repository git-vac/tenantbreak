# Authentication

Each identity uses its own credentials for verification, owner controls and probes. A policy stores environment variable names; credential values belong in the environment or a private credential file. Existing policies with `token_env` continue to work.

## Bearer tokens

Use the existing `token_env` identity field, or replace it with an explicit `auth` object:

```json
"auth": {"type": "bearer", "token_env": "TB_ALICE_TOKEN"}
```

An identity must have either `token_env` or `auth`. Its `verify` assertions still need to distinguish the authenticated account from every other configured identity.

## Custom headers

```json
"auth": {
  "type": "headers",
  "values": {"X-API-Key": "TB_ALICE_API_KEY", "X-Tenant-Key": "TB_ACME_KEY"}
}
```

The map associates HTTP header names with environment variable names. Values are sent verbatim, so an `Authorization` entry can supply a complete custom scheme. Up to eight headers are supported per identity. Header names are case-insensitive; duplicates, routing/framing headers and transport-controlled fields are rejected. Do not include `Cookie` here; use cookie authentication.

## Session cookies

```json
"auth": {
  "type": "cookies",
  "values": {"session": "TB_ALICE_SESSION", "tenant_session": "TB_ALICE_TENANT_SESSION"}
}
```

Supply each cookie's value without its name or attributes. The runner constructs a `Cookie` header from these entries and sends it only to the configured origin. Values containing separators, quotes, whitespace or backslashes are rejected. Cookie names are case-sensitive.

There is no shared cookie jar. Responses cannot replace an account's credentials through `Set-Cookie`. TenantBreak does not open a browser, log in, import a browser profile, apply browser cookie attributes, or automate MFA. Obtain the test sessions separately. Header and cookie modes are alternatives; a combined cookie/header login flow needs an integration change.

Try the built-in API:

```bash
tenantbreak demo --auth headers --mode fixed
tenantbreak demo --auth cookies --mode fixed
```

Complete policies are provided in [policy.headers.json](../examples/policy.headers.json) and [policy.cookies.json](../examples/policy.cookies.json). To use either against a separate lab process, start `tenantbreak lab --auth headers` or `--auth cookies` with a new `--credentials-out private/...` path, then load its generated environment file as described in [the lab walkthrough](lab.md).

## Refresh before a run

Bearer authentication can include an OAuth 2.0 refresh-token exchange:

```json
"auth": {
  "type": "bearer",
  "token_env": "TB_ALICE_TOKEN",
  "refresh": {
    "path": "/oauth/token",
    "refresh_token_env": "TB_ALICE_REFRESH",
    "client_auth": "basic",
    "client_id_env": "TB_OAUTH_CLIENT_ID",
    "client_secret_env": "TB_OAUTH_CLIENT_SECRET"
  }
}
```

Enable the exchange explicitly and choose a new private credential output:

```bash
tenantbreak run private/policy.json --refresh-auth --refresh-out private/refreshed-1.json --json reports/access.json
```

Without `--refresh-auth`, refresh configuration is inactive and `token_env` must already contain an access token. With the flag, selected accounts with refresh configuration use their refresh credentials; an old access token is not required. Other selected accounts use their normal credentials. Focused selection includes the owner's credentials automatically.

The runner performs at most one form-encoded POST per required refresh account, before identity verification. It sends `grant_type=refresh_token`, the refresh token and the explicitly configured client credentials. `client_auth` supports `basic`, `body` and `none` (default). Basic/body require both client fields. With `none`, an optional client ID is sent in the body. No scope is requested. The endpoint must be a path without a query on the same origin as the API; external identity providers, discovery, client assertions and custom JSON exchanges are not supported.

Refresh uses the same timeout and total run budget as the GET checks. Responses are limited to 64 KiB. Redirects, proxy inheritance and compressed responses are refused. A valid response needs HTTP 200, an `access_token` and `token_type` equal to `Bearer` (case-insensitive). Returned credentials then undergo the usual account verification and owner controls. A successful exchange alone cannot establish the subject or a passing authorization test.

No retry or refresh occurs during identity checks, controls or resource probes. If a credential expires during the run, the failure remains visible. Use accounts whose access-token lifetime covers the bounded run.

## Keep rotated credentials private

`--refresh-out` is required because providers may rotate refresh tokens. It creates a new JSON file inside the current directory's `private/` folder before requests begin. Each valid returned access/refresh value is saved and flushed before the next request. Previously saved entries survive a later account's failure. An omitted refresh token leaves the supplied one unchanged. A returned rotation may be saved even if the rest of the response is invalid; the run still fails.

This file contains credentials, not test evidence. New credentials have not passed subject verification merely because they were saved. Do not share it. Unix files use mode 0600; Windows uses inherited filesystem permissions. Existing files and paths resolving outside `private/` are refused. Unexpected termination, disk errors or a lost response can still require account recovery through the provider; do not run concurrent refreshes with the same rotating credential.

To use returned credentials on a later run:

```bash
tenantbreak run private/policy.json --credentials-file private/refreshed-1.json
# Or refresh again, preserving the prior snapshot:
tenantbreak run private/policy.json --credentials-file private/refreshed-1.json --refresh-auth --refresh-out private/refreshed-2.json
```

File entries override environment values for the same names. Credentials not returned by refresh, such as client secrets and unrelated accounts, still come from the environment. The file format is `{"format":"tenantbreak-credentials-v1","environment":{...}}`; it is never loaded from a saved report or accepted as a policy.

Reports omit authentication headers, cookies, refresh bodies and token-response digests. They record authentication type, refresh outcome and identity verification. Comparison requires matching refresh execution modes. `replay` supports the same explicit authentication flags as `run`.

The [refresh lab policy](../examples/policy.refresh.json) uses the synthetic server's unauthenticated client mode. Start `tenantbreak lab --auth refresh --mode fixed --credentials-out private/refresh-env.sh` (use `.ps1` for PowerShell), load that environment file, and run the policy with `--refresh-auth --refresh-out private/fresh.json`. The lab rotates both tokens to exercise the complete workflow. Use the client authentication required by your actual provider.

Protocol references: [OAuth refresh-token grant](https://www.rfc-editor.org/rfc/rfc6749#section-6), [OAuth security guidance](https://www.rfc-editor.org/rfc/rfc9700.html), [cookie value syntax](https://www.rfc-editor.org/rfc/rfc6265#section-4.1.1).
