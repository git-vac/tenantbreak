# Collections and field exposure

Collection checks search for explicitly configured fixture records inside an array. They do not infer record ownership or discover arbitrary identifiers. A complete run covers the named fixtures, selected accounts and configured assertions.

## Configure a known record in a list

An ordinary resource can add a `collection` definition:

```json
{
  "id": "alice-invoice",
  "label": "Alice's private invoice",
  "tenant": "acme",
  "path": "/api/invoices",
  "allow": ["alice", "admin-acme"],
  "control_identity": "alice",
  "match": {
    "/id": "inv-a104",
    "/tenant": "acme",
    "/marker": "TB-FIXTURE-ALICE-104"
  },
  "collection": {
    "items": "/items",
    "identify": {"/id": "inv-a104", "/tenant": "acme"},
    "next": "/next",
    "max_pages": 4,
    "max_items": 100
  }
}
```

`items` is a JSON Pointer to the record array. Use an empty string for a root array. `identify` must contain at least two exact assertions from `match`; these distinguish the target fixture from legitimate records with shared tenant or role fields. Every row is assessed separately. Matching fields from different rows or pages never combine into a leak.

The owner must retrieve the complete expected fixture in a complete scan. An invalid owner control prevents that resource's probes. An allowed account also needs the complete expected fixture. A forbidden account is denied when a complete HTTP 200 collection excludes the identified target, or when the initial request returns an explicit 403/404 without matching configured collection evidence. Non-JSON denials are accepted by status; bodies outside the configured array are not scanned for exposure.

A partially identified target without enough exposure evidence is inconclusive. Other records in the same tenant do not establish exposure of this target. Add separate resources for every fixture whose authorization needs testing.

## Bounded pagination

`next` points to a next-page path, or `null`/an empty string at the end. When configured, the field must be present on every HTTP 200 page. Only an absolute path on the configured origin with the **same endpoint path** as the initial request is followed; the query may change. Full URLs, protocol-relative URLs, changed endpoints, cycles and fragments are refused. Next-page values are not stored in reports; page paths are hashed.

`max_pages` is required and limited to 1..20; `max_items` is limited to 1..5000 across the scan. For an unpaginated response, omit `next` and set `max_pages` to 1. Offset/cursor values may appear in the server's next path; header-based links and automatic cursor construction are not supported.

Reaching a limit while more data remains, a failed later page, malformed records, or a missing cursor makes coverage incomplete. A confirmed finding from a valid earlier page remains visible, but the overall exit is 2. A partial scan cannot establish that a record is absent or that a leak was resolved. The socket/run budgets also apply across all pages.

Reports show inspected pages and record counts, the representative record's page/index, response digests and assertion outcomes. They omit record values, complete bodies and next-page cursors. Large matrices can produce large reports; use the existing selectors to keep each run focused. The saved-report loader accepts up to 16 MiB.

## Confirm configured partial exposure

For an object or collection resource, optionally add `leak_match`:

```json
"match": {
  "/id": "inv-a104",
  "/tenant": "acme",
  "/marker": "TB-FIXTURE-ALICE-104",
  "/amount": 120
},
"leak_match": {"/id": "inv-a104", "/amount": 120}
```

This declares that returning this fixture ID together with its protected amount is sufficient exposure evidence, even if other record fields are omitted. The group must contain at least two exact assertions from `match`. The owner's full `match` remains mandatory. Without an explicit subset, a partial object match remains inconclusive.

Choose fields and values that specifically identify the fixture and the protected data. A generic success flag or a common tenant name alone is weak evidence. Assertions require exact values; presence-only checks, arbitrary field discovery, transformed/encoded values and streaming responses are not supported.

## Run the experiment

```bash
tenantbreak demo --scenario collections --json reports/collections-before.json --html reports/collections-before.html
tenantbreak demo --scenario collections --mode fixed --json reports/collections-after.json
tenantbreak compare reports/collections-before.json reports/collections-after.json --html reports/collections-change.html
```

The vulnerable demo intentionally exits 1 and confirms nine forbidden reads across list records and a partial projection. The fixed demo and comparison exit 0. Continue the commands after observing the expected first failure.

For a separate lab process, start `tenantbreak lab --scenario collections --credentials-out private/collections-env.sh` (use `.ps1` on PowerShell). Load that file and run [policy.collections.json](../examples/policy.collections.json) with the usual `run`, selection and replay commands. Header and cookie authentication are also supported. The advanced lab scenarios do not implement OAuth refresh; use the ordinary object lab for that experiment.
