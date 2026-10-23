# Focused replay and run comparison

## Select a probe while retaining proof

```bash
tenantbreak run private/policy.json --case alice-invoice:bob --json reports/before-focused.json
```

This selects Bob's read of Alice's invoice. The engine also verifies Alice and Bob, then establishes Alice's allowed owner read. It does not require credentials for unrelated accounts. It never reduces a failed owner control to a passing denial.

`--identity`, `--resource` and `--case` are repeatable. Their filters intersect. Unknown IDs and empty intersections fail before credentials are read or API requests begin. Policy and case fingerprints retain the original definitions; selection does not rewrite the access rules.

HTML marks missing cells in a sparse selection as NOT RUN. Terminal and HTML display the selected count and full policy count. JUnit includes every executed dependency and selected probe.

## Rerun recorded findings

```bash
tenantbreak replay private/policy.json reports/before-focused.json --case alice-invoice:bob --json reports/after-focused.json
```

Credentials come from the current environment, optionally overridden by an explicit private `--credentials-file`. `replay` supports the same opt-in pre-run refresh flags as `run`; see [authentication](authentication.md). The target comes from the supplied policy, or an explicit `--base-url`; a saved report cannot redirect requests. The policy fingerprint, recorded request metadata and schema 2 case definitions must match. A policy change requires a new `run` rather than replaying a different definition under an old finding.

Without `--case`, replay selects confirmed leaks. Explicit cases can also select recorded errors, denials or successful allowed reads for investigation. A run with no recorded leaks requires an explicit case selection. The replay report records the source file's SHA-256, excluding its filename and credentials.

## Compare evidence offline

```bash
tenantbreak compare reports/before-focused.json reports/after-focused.json --html reports/change.html --json reports/change.json --junit reports/change.xml
```

Comparison makes no network requests and never rewrites its input files. It checks policy fingerprints, exact selected-case sets, per-case definitions, execution limits, refresh execution mode and demo/application context. Different application origins require `--allow-target-change`; target origins and timestamps remain visible. That flag does not override policy, scope, definition or evidence failures.

The same bundled demo fixture may use different temporary loopback ports. Its vulnerable/fixed implementations remain explicitly labeled. Demo results cannot establish a change in an unrelated application.

| Conclusion | Required evidence |
| --- | --- |
| New leak | Previously complete expected access/denial; now a confirmed forbidden read |
| Persistent leak | Confirmed forbidden reads in both runs |
| Resolved leak | A confirmed forbidden read followed by a complete expected denial |
| Unchanged | Complete expected access/denial in both runs |
| Inconclusive | A selected case has missing controls, an error or incomplete evidence |
| Not comparable | Definitions, selected cases or execution context do not match |

A missing case is never resolved. Incompatible run contexts suppress directional conclusions. An individual incomplete case prevents a clean comparison exit; other complete rows retain their evidence. A successful compare does not cover unselected policy cases.

Comparison exit 0 requires complete comparable evidence and no new or persistent leaks in the after run. Exit 1 means leaks remain. Exit 2 means incomplete/incompatible evidence and takes precedence even if other leaks were confirmed. JUnit uses failures for new/persistent leaks and errors for incomplete/incompatible rows.

## Saved evidence format

Version 0.2 writes report schema 2, including per-case definition fingerprints and explicit selection scope. The bounded loader rejects malformed structures, duplicate JSON keys, duplicate case IDs, invalid hashes and contradictory evidence shapes. It recomputes identity/control validity, outcomes and counts from the recorded evidence rather than trusting edited summary flags.

This validates consistency, not authenticity. A local report can still be fabricated; no signatures or independent server attestation are implied. Bodies and expected/actual assertion values remain omitted. Version 0.1 reports can be read for replay using the matching policy, but they lack the definitions required by the comparison workflow; rerun both sides with version 0.2.
