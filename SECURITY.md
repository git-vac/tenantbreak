# Security reports

Please avoid publishing real bearer tokens, account data or private API responses in an issue. A synthetic reproducer is usually sufficient.

For a security issue in TenantBreak itself, use GitHub's private vulnerability reporting if enabled on this repository. Otherwise, open an issue requesting a private reporting channel without including the sensitive details.

Current boundaries: configured GET requests only; bearer tokens supplied through environment variables; one target origin; no redirects, proxy inheritance, arbitrary code execution or telemetry. Lab credentials are generated at runtime; only invented records and credential variable names are committed.
