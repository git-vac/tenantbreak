# Configure an existing API

Policy setup runs offline. It creates a draft for the API operator to complete; it does not infer ownership or perform discovery requests.

## Start with a template

```bash
tenantbreak init --base-url https://staging.example.test --out private/policy.draft.json
```

The JSON file contains `policy`, `review` and `source` fields. The starter has two account definitions, environment variable names and a protected-resource template. Credential values are never part of the file. The empty allow list and `__SET_` fields deliberately prevent execution.

## Import routes from OpenAPI

```bash
tenantbreak import-openapi examples/openapi.json --base-url http://127.0.0.1:8080 --operation readInvoice --out private/invoices.draft.json
```

OpenAPI 3.0, 3.1 and 3.2 JSON documents are supported for GET route extraction. YAML uses the optional dependency installed by `python -m pip install ".[openapi]"`. JSON requires no extra dependency.

Use repeatable `--operation` to select operation IDs, or `--path` to select exact specification paths when operation IDs are absent. Both selectors intersect. At most 64 GET resources are imported. Required query parameters receive placeholders; concrete values are never copied from examples. Path variables stay visible for explicit resolution. Non-GET methods are omitted.

The target origin must be provided explicitly. Specification server URLs are never used to contact a service or copied into a draft. To include an API version prefix, specify `--path-prefix /v1`. Operation/path-specific server overrides are not applied; verify each route against the intended deployment.

Local JSON Pointer references for path items, operations and parameters are resolved within bounded limits. External references are not fetched. Bundle multi-file specifications locally first. Cycles and ambiguous referenced objects with operation overrides are rejected. The importer extracts supported routes rather than validating every part of an OpenAPI document.

YAML input uses a bounded SafeLoader. Aliases, merge keys, duplicate keys, unsupported tags and excessive nesting are rejected. HTTP response code keys may be unquoted numbers; they are normalized to strings. JSON and YAML input are limited to 8 MiB, 50,000 nodes and nesting depth 64.

## Complete the policy

Edit only the draft's `policy` object for execution. The review notes and operation metadata provide context.

| Field | Supply |
| --- | --- |
| `base_url` | The target HTTP(S) origin, with no credentials, query or path |
| `identity_check.path` | An authenticated endpoint identifying the current subject |
| `identities[].verify` | Exact subject, tenant and role expectations for each test account |
| `identities[].token_env` | The name of a privately set environment variable |
| `resources[].path` | A concrete GET path, resolving every path/query placeholder |
| `resources[].allow` | Every configured identity allowed to retrieve this fixture |
| `resources[].control_identity` | One allowed identity that proves the resource exists |
| `resources[].match` | At least two specific JSON fields identifying the protected record |

For the bundled invoice lab, resolve `/api/invoices/{invoiceId}` to `/api/invoices/inv-a104`, set its tenant to `acme`, configure Alice/Bob using `/api/me`, allow Alice, and set identifying resource evidence from the synthetic invoice fixture. [The complete demo policy](../examples/policy.json) illustrates a larger user/tenant/role matrix.

An OpenAPI security scheme describes a mechanism, not which test account owns a resource. The importer does not copy security-scheme descriptions, credential examples, response examples or allow lists. It starts with bearer placeholders; replace each identity's `token_env` with an `auth` object for [custom headers, cookies or optional refresh](authentication.md). Required headers, cookies, querystring bodies and GET request bodies are not generated. Configure [collection and field checks](collections.md) explicitly for list operations. The importer extracts GET routes only; [disposable write policies](writes.md) require separate configuration.

## Finalize and run

```bash
tenantbreak finalize private/policy.draft.json --out private/policy.json
tenantbreak validate private/policy.json
tenantbreak run private/policy.json --json reports/access.json --html reports/access.html
```

Finalize rejects remaining `__SET_` placeholders, unresolved path variables, empty/unknown allow lists and invalid identity/resource definitions. It does not verify that the operator's business rules are correct. The generated policy still undergoes identity and owner checks during execution.

Setup outputs must be new files. Drafts and finalized policies are created with mode 0600 on Unix; Windows uses inherited filesystem permissions. Keep actual configuration in the Git-ignored `private/` directory. Do not put credentials in URLs, path values, assertion fields or source documents.

Format references: [OpenAPI 3.0](https://spec.openapis.org/oas/v3.0.4.html), [3.1](https://spec.openapis.org/oas/v3.1.1.html), [3.2](https://spec.openapis.org/oas/v3.2.1.html), and [PyYAML's safe parsing API](https://pyyaml.org/wiki/PyYAMLDocumentation).
