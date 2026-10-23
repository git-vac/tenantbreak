# Run the lab as a separate API

`demo` starts its own temporary API automatically. To exercise `run` against a separate application process, start the lab in one terminal. It binds only to `127.0.0.1` and generates fresh process-local bearer tokens. Token values are never printed.

For Bash:

```bash
tenantbreak lab --mode vulnerable --port 8080 --credentials-out private/lab-env.sh
```

In a second terminal, load the generated environment variables and run the policy:

```bash
source private/lab-env.sh
tenantbreak run examples/policy.json --html reports/manual-vulnerable.html --json reports/manual-vulnerable.json
```

For PowerShell, start the server with:

```powershell
tenantbreak lab --mode vulnerable --port 8080 --credentials-out private/lab-env.ps1
```

In a second PowerShell terminal:

```powershell
. .\private\lab-env.ps1
tenantbreak run examples/policy.json --html reports/manual-vulnerable.html --json reports/manual-vulnerable.json
```

The result should contain nine leaks and exit 1. Stop the server with Ctrl+C and restart it with `--mode fixed` and a **new** credentials output path. Load that new environment file, then repeat the policy with a new report path. The result should contain six allowed reads, ten denials and exit 0.

All accounts and records are invented. The credentials file contains generated lab tokens and belongs in the Git-ignored `private/` directory. Existing credential files are refused. On Unix the file is created with mode 0600. Integrated `demo` runs keep credentials entirely in memory.

To investigate only Bob's invoice access, use `tenantbreak replay examples/policy.json reports/manual-vulnerable.json --case alice-invoice:bob --html reports/replayed.html`. This retains Alice's identity/owner control and Bob's identity check. Save a complete fixed `run` as `reports/manual-fixed.json`, then compare it with the complete vulnerable run using `tenantbreak compare reports/manual-vulnerable.json reports/manual-fixed.json --html reports/change.html`. A one-case replay has a different scope from a complete run and cannot establish a full-matrix comparison.

The vulnerable invoice route checks authentication but omits tenant/owner authorization. The fixed route requires matching tenant **and** either the owner or that tenant's administrator. The vulnerable export checks tenant membership alone; the fixed route also requires the administrator role. See `src/tenantbreak/lab.py` for both implementations.
