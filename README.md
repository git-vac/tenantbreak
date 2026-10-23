# TenantBreak

**Prove which users can read which API resources. Keep authorization bugs from coming back.**

TenantBreak runs an explicit access matrix across users, roles and tenants. A finding requires a verified identity, a successful owner control, and matching resource evidence in a forbidden response. A `200 OK` alone never establishes a leak.

![Synthetic lab: nine leaks before the fix, zero after](examples/overview.svg)

[Vulnerable report](examples/vulnerable.html) · [Fixed report](examples/fixed.html) · [Example policy](examples/policy.json) · [How evidence works](docs/evidence.md)

## Try the complete experiment

Python 3.10+; no runtime dependencies, cloud account or API key.

```bash
git clone https://github.com/git-vac/tenantbreak.git
cd tenantbreak
python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows PowerShell instead: .\.venv\Scripts\Activate.ps1
python -m pip install .

tenantbreak demo --html reports/vulnerable.html --json reports/vulnerable.json
tenantbreak demo --mode fixed --html reports/fixed.html --junit reports/fixed.xml
```

The first command exits **1**: it confirms **nine forbidden reads** in the bundled vulnerable API. The second exits **0**: all **six allowed and ten forbidden reads** match the same policy. Both commands make real HTTP requests to a temporary loopback server with entirely invented data. They close the server when finished.

Open the HTML files locally. Reports contain an access matrix, finding evidence, identity checks and owner controls. They work offline and load no scripts or remote assets.

The lab demonstrates three boundaries:

- **User:** Bob must not read Alice's private invoice.
- **Tenant:** Charlie from Nova must not read Acme's invoices.
- **Role:** Acme members must not retrieve its administrator export.

## Test your own API

Use an API and test accounts you are authorized to examine. Start with staging fixtures whose ownership is known.

1. Copy [examples/policy.json](examples/policy.json) and replace the target origin, identity checks, paths, ownership evidence and allowed identities.
2. Set each test account's bearer token in the environment variable named by `token_env`. Tokens are read from the environment; they are never placed in the policy or a CLI argument.
3. Validate and run the policy:

```bash
tenantbreak validate private/policy.json
tenantbreak run private/policy.json --html reports/audit.html --json reports/audit.json --junit reports/audit.xml
```

`validate` checks structure without credentials or network requests. `run` first checks every identity against the configured identity endpoint, then establishes an allowed control for each resource, then exercises every identity/resource combination.

For a disposable target with a changing port:

```bash
tenantbreak run private/policy.json --base-url https://staging.example.test --timeout 5 --max-seconds 120
```

The origin must have no path, embedded credentials, query or fragment. Resource paths are absolute paths on that origin. HTTPS is required outside loopback unless you explicitly use `--allow-http`. Redirects are refused and ambient proxy settings are ignored. Corporate proxies and custom authentication flows need an integration change.

## Declare access and evidence

Each resource names an explicit set of allowed identities. Every other configured identity is expected to be denied. Tenant and role labels help explain findings; they do not infer permissions.

```json
{
  "id": "alice-invoice",
  "label": "Alice's private invoice",
  "tenant": "acme",
  "path": "/api/invoices/inv-a104",
  "allow": ["alice", "admin-acme"],
  "control_identity": "alice",
  "match": {
    "/id": "inv-a104",
    "/tenant": "acme",
    "/marker": "TB-FIXTURE-ALICE-104"
  }
}
```

`match` uses JSON Pointer equality checks. Choose identifying values that prove the protected resource was returned, such as its ID, tenant and a unique fixture marker. Generic fields such as `success: true` are weak evidence. TenantBreak requires at least two assertions, but their meaning and specificity remain the policy author's responsibility. Assertion values are omitted from reports.

Identity `verify` assertions should independently check the authenticated subject, tenant and role. At least two fields are required, and each identity must have distinct verification assertions and a distinct token.

## Interpret outcomes

| Result | Meaning |
| --- | --- |
| `confirmed-leak` | An expected-deny response matched **every** configured resource assertion, after identity and owner verification. Even a 403 containing the complete protected record is a leak. |
| `allowed` | Expected access returned HTTP 200 and all resource assertions matched. |
| `denied` | Expected-deny response returned 403/404 without matching protected resource assertions. Non-JSON denials are accepted by status only. |
| `inconclusive` | A control failed, only some evidence matched, an expected resource was absent, or the response did not establish access or denial. |
| `error` | Authentication expired, a redirect was refused, the API failed, JSON was malformed, or a transport limit was reached. |

An expired token, missing resource, login redirect or generic HTTP 200 error page cannot produce a clean passing run. JSON evidence is exact and structural: fields outside the configured assertions, encoded data and non-JSON response contents are not assessed for leakage.

Exit **0**: all configured checks matched policy. Exit **1**: confirmed leak(s), with complete controls/results. Exit **2**: error or incomplete evidence, including when leaks were also observed; those findings remain in the report. Exit **130**: interrupted.

## Put the policy in CI

```bash
tenantbreak run private/policy.json --json reports/access.json --junit reports/access.xml
```

Configure your CI runner to provide tokens through its secret environment mechanism and to collect artifacts even when the command fails. JUnit includes identity checks, owner controls and access probes: leaks are failures; missing evidence is an error. Preserve TenantBreak's nonzero exit status.

The repository's [CI workflow](.github/workflows/tests.yml) installs the package and runs real loopback integration tests on Linux and Windows. Lab credentials are generated in memory at runtime and omitted from published examples.

## Scope and limits

This first release supports explicit **GET requests**, bearer-token identities, HTTP 200 owner controls, 403/404 denials and JSON equality assertions. It does not discover accounts, enumerate IDs, import OpenAPI, change resource state, refresh tokens, exercise browser sessions or generate policies automatically.

Every policy is limited to 32 identities, 64 resources and 16 assertions per identity/resource. JSON input and responses are bounded to 1 MiB. Requests run sequentially. The socket timeout defaults to 5 seconds; a 120-second run budget is checked before requests and between response chunks. A blocking operation can overrun that budget by up to its socket timeout, and OS DNS resolution may take longer. Results are observations over time, not an atomic snapshot.

Reports omit raw bodies and headers and redact exact supplied token values. Encoded/transformed token values are not a general redaction guarantee. Paths, tenant labels and response digests can still describe your application. `reports/`, `private/` and `.env*` are Git-ignored. Output files must be new; existing files and symlink targets are refused.

## Develop and extend

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

[Architecture and evidence](docs/evidence.md) explains the decision rules. [Manual lab walkthrough](docs/lab.md) lets you test the CLI against a separate running API.

Related work: [AuthMatrix](https://github.com/SecurityInnovation/AuthMatrix) provides authorization matrices inside Burp Suite. TenantBreak focuses on an explicit standalone policy, evidence checks and CI results. Background: [OWASP broken object-level authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) and [JSON Pointer, RFC 6901](https://www.rfc-editor.org/rfc/rfc6901).

MIT licensed.
