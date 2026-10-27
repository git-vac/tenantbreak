"""Compare compatible, complete access evidence without hiding missing tests."""

from collections import Counter
from datetime import datetime, timezone
from html import escape
from xml.etree.ElementTree import Element, SubElement, tostring

from .report import LABELS, STYLE, _xml_text, plain, needs_attention
from .saved import normalize


def compare(before, after, *, allow_target_change=False, before_sha=None, after_sha=None):
    before, after = normalize(before), normalize(after)
    left = {case["id"]: case for case in before["cases"]}
    right = {case["id"]: case for case in after["cases"]}
    issues = []
    if before["schema_version"] != 2 or after["schema_version"] != 2:
        issues.append("legacy-report-rerun-required")
    if before["policy_sha256"] != after["policy_sha256"]:
        issues.append("policy-definitions-differ")
    if set(left) != set(right):
        issues.append("selected-cases-differ")
    if before.get("scope", {}).get("total_cases") != after.get("scope", {}).get("total_cases"):
        issues.append("policy-case-counts-differ")
    if before["limits"] != after["limits"]:
        issues.append("execution-limits-differ")
    if before.get("kind", "read") != after.get("kind", "read") or before.get("write_limits") != after.get("write_limits"):
        issues.append("operation-context-differs")
    if before.get("authentication", {"refresh_requested": False}) != after.get("authentication", {"refresh_requested": False}):
        issues.append("authentication-execution-differs")
    both_demo = before["mode"].startswith("demo-") and after["mode"].startswith("demo-")
    if before["mode"].startswith("demo-") != after["mode"].startswith("demo-"):
        issues.append("demo-and-application-runs-differ")
    same_fixture = both_demo and before.get("fixture_id") == after.get("fixture_id") == "tenantbreak-ledgercloud-v1"
    target_changed = before["base_url"] != after["base_url"]
    if target_changed and not (allow_target_change or same_fixture):
        issues.append("target-origins-differ-use-allow-target-change")
    rows = []
    for key in dict.fromkeys([*left, *right]):
        a, b = left.get(key), right.get(key)
        row = {"id": key, "resource": (b or a)["resource"], "identity": (b or a)["identity"],
               "label": (b or a)["label"], "before": a["status"] if a else None,
               "after": b["status"] if b else None}
        if issues:
            state, reason = "not-comparable", ", ".join(issues)
        elif a.get("definition_sha256") != b.get("definition_sha256") or any(a[key] != b[key] for key in ("expected", "method", "path", "identity_tenant", "role", "resource_tenant")):
            state, reason = "not-comparable", "case-definitions-differ"
        elif needs_attention(a) or needs_attention(b) or before.get("interrupted") or after.get("interrupted"):
            state, reason = "inconclusive", "a-run-lacks-complete-case-evidence"
        elif a["status"] == "confirmed-leak" and b["status"] == "denied":
            state, reason = "resolved-leak", "forbidden-read-now-denied"
        elif a["status"] != "confirmed-leak" and b["status"] == "confirmed-leak":
            state, reason = "new-leak", "new-forbidden-read-confirmed"
        elif a["status"] == b["status"] == "confirmed-leak":
            state, reason = "persistent-leak", "forbidden-read-remains-confirmed"
        elif a["status"] == "confirmed-write" and b["status"] == "denied":
            state, reason = "resolved-write", "forbidden-write-now-denied"
        elif a["status"] != "confirmed-write" and b["status"] == "confirmed-write":
            state, reason = "new-write", "new-forbidden-state-change-confirmed"
        elif a["status"] == b["status"] == "confirmed-write":
            state, reason = "persistent-write", "forbidden-state-change-remains-confirmed"
        else:
            state, reason = "unchanged", "expected-access-unchanged"
        row.update(status=state, reason=reason)
        rows.append(row)
    metadata = lambda report, digest: {key: report[key] for key in ("name", "created_at", "mode", "base_url", "policy_sha256", "limits")} | {
        "source_sha256": digest, "kind": report.get("kind", "read"), "selected_cases": len(report["cases"]),
        "total_cases": report.get("scope", {}).get("total_cases", len(report["cases"]))}
    return {"schema_version": 1, "kind": "comparison", "tool": "TenantBreak",
            "created_at": datetime.now(timezone.utc).isoformat(), "before": metadata(before, before_sha),
            "after": metadata(after, after_sha), "target_change_acknowledged": bool(target_changed and allow_target_change),
            "issues": issues, "rows": rows, "counts": dict(Counter(row["status"] for row in rows))}


def exit_code(comparison):
    if any(row["status"] in {"not-comparable", "inconclusive"} for row in comparison["rows"]):
        return 2
    return 1 if any(row["status"] in {"new-leak", "persistent-leak", "new-write", "persistent-write"} for row in comparison["rows"]) else 0


def terminal(comparison):
    lines = ["", "TENANTBREAK / RUN COMPARISON",
             f"Before: {plain(comparison['before']['base_url'])} | {comparison['before']['mode']}",
             f"After:  {plain(comparison['after']['base_url'])} | {comparison['after']['mode']}",
             f"Scope: {comparison['before']['selected_cases']}/{comparison['before']['total_cases']} -> {comparison['after']['selected_cases']}/{comparison['after']['total_cases']} selected policy checks", ""]
    lines.extend("ATTENTION: " + issue for issue in comparison["issues"])
    if comparison["target_change_acknowledged"]:
        lines.append("Different target origins explicitly acknowledged; deployment equivalence is not established.")
    for row in comparison["rows"]:
        before = LABELS[row["before"]] if row["before"] else "NOT RUN"
        after = LABELS[row["after"]] if row["after"] else "NOT RUN"
        lines.append(f"{plain(row['id']):<36} {before:<8} -> {after:<8} {row['status'].upper()}")
    counts = Counter(row["status"] for row in comparison["rows"])
    lines.append(f"\n{counts['new-leak'] + counts['new-write']} new | {counts['persistent-leak'] + counts['persistent-write']} persistent | {counts['resolved-leak'] + counts['resolved-write']} resolved | {counts['unchanged']} unchanged | {counts['inconclusive'] + counts['not-comparable']} need attention")
    lines.append("Saved reports are local evidence records, not authenticated attestations. Results cover only the selected policy checks.\n")
    return "\n".join(lines)


def html(comparison):
    e = lambda value: escape(str(value), quote=True)
    counts = Counter(row["status"] for row in comparison["rows"])
    parts = ["<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>",
             "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">",
             f"<title>TenantBreak | Run comparison</title><style>{STYLE}</style></head><body><main><header><div class='eyebrow'>TENANTBREAK / RUN COMPARISON</div>",
             "<h1>Run comparison</h1><p class='muted'>Access results before and after the change.</p></header><section class='stats'>"]
    suffix, noun = ("write", "WRITES") if comparison["after"].get("kind") == "write" else ("leak", "LEAKS")
    for label, key, cls in (("NEW " + noun, "new-" + suffix, "bad"), ("PERSISTENT " + noun, "persistent-" + suffix, "bad"), ("RESOLVED " + noun, "resolved-" + suffix, "good")):
        parts.append(f"<div class='stat'><strong class='{cls}'>{counts[key]}</strong><span>{label}</span></div>")
    parts.append(f"<div class='stat'><strong class='warn'>{counts['not-comparable'] + counts['inconclusive']}</strong><span>NEED ATTENTION</span></div></section>")
    if comparison["issues"]:
        parts.append("<div class='notice'>These runs cannot support a directional conclusion.<ul>" + "".join(f"<li>{e(issue.replace('-', ' '))}</li>" for issue in comparison["issues"]) + "</ul></div>")
    if comparison["target_change_acknowledged"]:
        parts.append("<p class='notice'>Different target origins explicitly acknowledged. Matching policy definitions do not establish that deployments or underlying data are equivalent.</p>")
    parts.append("<div class='facts'>")
    for key in ("before", "after"):
        meta = comparison[key]
        parts.append(f"<section class='card'><div class='eyebrow'>{key.upper()}</div><h2>{e(meta['name'])}</h2><p><code>{e(meta['base_url'])}</code></p><p>{e(meta['mode'])} / {meta['selected_cases']} of {meta['total_cases']} checks</p><small>{e(meta['created_at'])}</small><details><summary>Definition and file fingerprints</summary><p>Policy <code>{e(meta['policy_sha256'])}</code></p><p>Source file <code>{e(meta['source_sha256'] or 'not supplied')}</code></p></details></section>")
    parts.append("</div><h2>Access changes</h2><div class='scroll'><table><thead><tr><th>RESOURCE / IDENTITY</th><th>BEFORE</th><th>AFTER</th><th>CONCLUSION</th></tr></thead><tbody>")
    for row in comparison["rows"]:
        cls = "bad" if row["status"] in {"new-leak", "persistent-leak", "new-write", "persistent-write"} else "warn" if row["status"] in {"not-comparable", "inconclusive"} else "good"
        before, after = LABELS.get(row["before"], "NOT RUN"), LABELS.get(row["after"], "NOT RUN")
        parts.append(f"<tr><td><strong>{e(row['label'])}</strong><small>{e(row['identity'])}</small></td><td>{before}</td><td>{after}</td><td class='{cls}'>{e(row['status'].replace('-', ' ').upper())}<small>{e(row['reason'].replace('-', ' '))}</small></td></tr>")
    parts.append("</tbody></table></div><footer>Comparison exit 0 means complete compatible evidence and no new or persistent violations in the after run. Exit 1 means violations remain; exit 2 means incomplete or incompatible evidence. A missing test, incomplete scan or failed cleanup cannot establish a resolved violation. Reports are local, unauthenticated evidence records.</footer></main></body></html>")
    return "".join(parts)


def junit(comparison):
    suite = Element("testsuite", name="TenantBreak run comparison")
    props = SubElement(suite, "properties")
    for side in ("before", "after"):
        for key in ("base_url", "mode", "policy_sha256", "selected_cases", "total_cases"):
            SubElement(props, "property", name=side + "." + key, value=_xml_text(comparison[side][key]))
    for row in comparison["rows"]:
        test = SubElement(suite, "testcase", classname="tenantbreak.comparison", name=_xml_text(row["id"]))
        if row["status"] in {"new-leak", "persistent-leak", "new-write", "persistent-write"}:
            SubElement(test, "failure", message=row["status"]).text = _xml_text(row["reason"])
        elif row["status"] in {"not-comparable", "inconclusive"}:
            SubElement(test, "error", message=row["status"]).text = _xml_text(row["reason"])
    for name, path in (("tests", "testcase"), ("failures", "testcase/failure"), ("errors", "testcase/error")):
        suite.set(name, str(len(suite.findall(path))))
    return '<?xml version="1.0" encoding="utf-8"?>\n' + tostring(suite, encoding="unicode") + "\n"
