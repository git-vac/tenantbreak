# Disposable write authorization tests

Write testing uses a separate policy and command. It performs real mutations, including an allowed owner control and configured reset requests. Use an isolated staging namespace with disposable fixtures and exclusive access for the run. The runner verifies the configured state; it cannot reverse unobserved side effects or make the application transactional.

## Run the built-in experiment

```bash
tenantbreak demo --scenario writes --enable-writes --json reports/writes-before.json --html reports/writes-before.html
tenantbreak demo --scenario writes --mode fixed --enable-writes --json reports/writes-after.json
tenantbreak compare reports/writes-before.json reports/writes-after.json --html reports/writes-change.html
```

The vulnerable server permits six forbidden create/update/delete effects and exits 1. The fixed server permits six allowed operations, denies six forbidden ones and exits 0. The comparison confirms six resolved writes. Each successful experiment verifies restoration of its fixtures. The first exit 1 is intentional; run the remaining commands after observing it.

The [complete write policy](../examples/policy.writes.json) is executable against `tenantbreak lab --scenario writes`. Supply the lab's generated environment credentials as described in [the lab walkthrough](lab.md). Default lab mode is vulnerable; specify `--mode fixed` for the corrected application.

## Policy contract

The top-level policy declares `"kind": "write"` and `"disposable": true`. It retains the existing identity definitions and adds up to eight fixtures in `resources`. Each fixture has the usual ID, label, tenant, observation `path`, allowed identities and control account. Its `match` contains at least three identifying assertions, including a specific disposable marker selected by `fixture_pointer`.

A write fixture adds this configuration:

```json
"write": {
  "scope": "/api/fixtures/tenantbreak/",
  "fixture_pointer": "/marker",
  "guard": {
    "path": "/api/fixtures/tenantbreak/guard",
    "disposable_pointer": "/disposable",
    "match": {
      "/id": "tenantbreak-lab",
      "/tenant": "acme",
      "/disposable": true
    }
  },
  "before": {"status": 200, "match": {"/value": "before"}},
  "after": {"status": 200, "match": {"/value": "after"}},
  "request": {
    "method": "PATCH",
    "path": "/api/fixtures/tenantbreak/records/update",
    "json": {"value": "after"}
  },
  "reset": {
    "method": "PUT",
    "path": "/api/fixtures/tenantbreak/records/update",
    "json": {
      "id": "update", "tenant": "acme",
      "marker": "TB-DISPOSABLE-update", "value": "before"
    }
  }
}
```

The corresponding resource's `path` is `/api/fixtures/tenantbreak/records/update`; its identifying `match` asserts `/id`, `/tenant` and `/marker` with the values shown above. State assertions are combined with those fixture identifiers for every HTTP 200 observation. The combined assertion count must not exceed 16.

The guard is an independent, authenticated read of the disposable namespace. It needs at least three assertions, including the declared disposable field equal to JSON `true`. It must remain present throughout the operation and cleanup. Guard paths cannot be mutated or reused as fixture paths. Configure a guard endpoint in your test application; the tool does not guess whether a deployment is disposable.

All observation, guard, mutation and reset paths stay inside the concrete `scope`, which ends in `/` and has at least two path segments. Queries, encoded path segments, traversal and unresolved templates are refused. Mutations normally target the fixture's observation path. A POST to its immediate parent collection is allowed only when the JSON body explicitly matches all fixture identifiers. This supports known client-assigned IDs; server-generated IDs, dynamic response substitution and arbitrary action routes are not supported.

`request` and `reset` support POST, PUT, PATCH and DELETE with optional JSON bodies, limited to 16 KiB each. A before/after state uses HTTP 200 plus exact assertions, or HTTP 404 without `match`. Before and after must be mutually exclusive. For creation, use 404 before and 200 after; for deletion, use 200 before and 404 after. Use a synchronous observation endpoint that exposes the relevant fixture state. Delayed jobs, eventual consistency and external effects require application-specific instrumentation.

## Execution and evidence

For each fixture, the control account first demonstrates the allowed effect and verified restoration. A failed positive control prevents that fixture's test probes. For every selected account, the runner then:

1. Verifies the observer account, namespace guard, initial fixture state and acting account.
2. Sends the configured mutation once.
3. Re-verifies the actor and observer, checks the guard, and independently reads the fixture as the observer.
4. Attempts cleanup with the control account and verifies the original configured state and namespace guard again.

The mutation response body is never proof of an effect. A forbidden operation returning HTTP 403 while changing the observed state is a `confirmed-write`. A 403/404 with verified unchanged state is `denied`. A 200 response without the expected change is inconclusive. An expired account cannot become a passing denial.

Cleanup first reads the current fixture. It resets only if the namespace and account remain valid and the fixture is either absent or still matches its identifying assertions. It refuses to overwrite a different record at the same path. Already restored fixtures need no reset request. Restoration covers the configured state assertions, not every possible application field or external effect.

Unverified cleanup stops all later mutations in the run. Findings already observed remain in the report, while exit 2 takes precedence. A timed-out or interrupted mutation can still be executing on the server: the runner attempts best-effort cleanup, marks cleanup unverified and stops, even if an immediate read looks restored. Recover the isolated namespace through your application's fixture tooling before another run.

Cleanup has a separate per-attempt budget (`--cleanup-seconds`, default 10, range 1..120), allowing a reset attempt after the normal run budget expires. Ctrl+C after dispatch triggers cleanup before the report returns exit 130. Another interruption, process termination, unavailable credentials or a network/disk failure can prevent restoration. No client-side tool can guarantee rollback under those conditions.

## Test your application

```bash
tenantbreak validate private/write-policy.json
tenantbreak write private/write-policy.json --enable-writes --case update:bob --cleanup-seconds 10 --json reports/write.json --html reports/write.html --junit reports/write.xml
```

Both the write command and `--enable-writes` are required. Ordinary `run` and `replay` reject write policies before requests begin. Repeat a write case explicitly with the write command. Selectors retain the owner's positive control and cleanup; choosing a single forbidden case still performs those allowed mutations. This is why fixtures must be disposable.

Existing bearer/header/cookie credentials and explicit pre-run refresh options apply. Reports contain mutation reply status, independent observation evidence, per-stage digests and cleanup outcomes. They omit request/response bodies, expected scalar values and credentials. JSON evidence remains locally editable and is not an authenticated attestation.

Offline comparison checks the exact policy, cases, authentication mode, run limits and cleanup budget. It distinguishes new, persistent and resolved writes. Missing observations, interrupted runs, incomplete execution or failed cleanup cannot establish a resolved write. JUnit records confirmed writes as failures and incomplete cleanup/execution as errors.
