"""Offline terminal, HTML and JUnit views. No response bodies or tokens."""

from collections import Counter
from html import escape
import json
import re
from xml.etree.ElementTree import Element, SubElement, tostring


LABELS = {"confirmed-leak": "LEAK", "confirmed-write": "WRITE", "allowed": "ALLOW", "denied": "DENY", "inconclusive": "UNKNOWN", "error": "ERROR"}


def needs_attention(case):
    return case["status"] in {"error", "inconclusive"} or any(case.get(key) is False for key in ("cleanup_verified", "coverage_complete", "execution_complete"))


def request_status(case):
    return (case["write"].get("request") or {}).get("http_status") if "write" in case else case["http_status"]


def details_html(item):
    e = lambda value: escape(str(value), quote=True)
    parts = []
    if "collection" in item:
        collection = item["collection"]
        pages = collection["pages"]
        parts.append(f"<p><strong>Collection coverage:</strong> {len(pages)} / {collection['max_pages']} pages; {sum(p['items_seen'] for p in pages)} / {collection['max_items']} records inspected. {'Complete' if item['coverage_complete'] else 'Incomplete'}.</p>")
        parts.append("<details><summary>Page evidence</summary><ul>")
        for number, page in enumerate(pages, 1):
            location = f"record {page['record_index'] + 1}" if page["record_index"] is not None else "no candidate record"
            parts.append(f"<li>Page {number}: HTTP {page['http_status'] or '-'}; {page['items_seen']} records; {location}; {e(page['transport_error'] or page['next_state'])}<p><code>{e(page['response_sha256'] or 'No complete response')}</code></p></li>")
        parts.append("</ul></details>")
    if item.get("leak_assertions"):
        parts.append("<p><strong>Configured exposure checks:</strong> " + ", ".join(f"<code>{e(c['pointer'])}</code> {'matched' if c['matched'] else 'different' if c['present'] else 'missing'}" for c in item["leak_assertions"]) + "</p>")
    if "write" in item:
        trial = item["write"]
        parts.append(f"<p><strong>Cleanup:</strong> {'verified' if item.get('cleanup_verified') else 'UNVERIFIED — subsequent writes stopped'}.</p><details><summary>Mutation and independent state checks</summary><ul>")
        for key, value in trial.items():
            if key in {"cleanup", "before_status", "after_status", "interrupted"} or value is None:
                continue
            checks = ", ".join(f"{e(c['pointer'])}: {'matched' if c['matched'] else 'different' if c['present'] else 'missing'}" for c in value["assertions"])
            parts.append(f"<li>{e(key.replace('_', ' '))}: HTTP {value['http_status'] or '-'}; {e(value['transport_error'] or 'response received')}<small>{checks}</small><code>{e(value['response_sha256'] or 'No complete response')}</code></li>")
        for key, value in (trial.get("cleanup") or {}).items():
            if value is not None:
                parts.append(f"<li>Cleanup {e(key.replace('_', ' '))}: HTTP {value['http_status'] or '-'}; {e(value['transport_error'] or 'response received')}; {sum(c['matched'] for c in value['assertions'])}/{len(value['assertions'])} assertions matched</li>")
        parts.append("</ul></details>")
    return "".join(parts)


def plain(value):
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", str(value))


def terminal(report):
    counts = Counter(case["status"] for case in report["cases"])
    lines = ["", "TENANTBREAK / AUTHORIZATION EVIDENCE", f"{plain(report['name'])} | {plain(report['mode'])}",
             f"Target: {plain(report['base_url'])}",
             f"Identities verified: {sum(i['valid'] for i in report['identities'])}/{len(report['identities'])} | Owner controls: {sum(c['valid'] for c in report['controls'])}/{len(report['controls'])}", "",
             f"{'RESOURCE':<23} {'IDENTITY':<14} {'EXPECTED':<9} {'HTTP':<5} RESULT", "-" * 75]
    if report.get("scope", {}).get("total_cases", len(report["cases"])) != len(report["cases"]):
        lines.insert(4, f"Focused run: {len(report['cases'])}/{report['scope']['total_cases']} policy checks selected; unselected checks were not run.")
    if report.get("authentication", {}).get("refresh_requested"):
        lines.insert(4, "Authentication: pre-run refresh requested; no refresh or retries during access probes.")
    for case in report["cases"]:
        lines.append(f"{plain(case['resource']):<23} {plain(case['identity']):<14} {case['expected']:<9} {str(request_status(case) or '-'):<5} {LABELS[case['status']]}")
    violation = "confirmed writes" if report.get("kind") == "write" else "confirmed leaks"
    lines.extend(["", f"{len(report['cases'])} checks | {counts['confirmed-write'] + counts['confirmed-leak']} {violation} | {counts['allowed'] + counts['denied']} expected outcomes | {sum(needs_attention(c) for c in report['cases'])} need attention"])
    for case in report["cases"]:
        if case["status"] == "confirmed-leak":
            lines.append(f"  LEAK {plain(case['identity'])} -> {plain(case['resource'])}: {case['reason']}")
        elif case["status"] == "confirmed-write":
            lines.append(f"  WRITE {plain(case['identity'])} -> {plain(case['resource'])}: forbidden state change observed")
        elif case["status"] in {"error", "inconclusive"}:
            lines.append(f"  {LABELS[case['status']]} {plain(case['id'])}: {case['reason']}")
        if "collection" in case:
            lines.append(f"  {plain(case['id'])}: collection pages {len(case['collection']['pages'])}; records {sum(p['items_seen'] for p in case['collection']['pages'])}; coverage {'complete' if case['coverage_complete'] else 'INCOMPLETE'}")
        if "write" in case:
            lines.append(f"  {plain(case['id'])}: cleanup {'verified' if case['cleanup_verified'] else 'UNVERIFIED; further writes stopped'}")
    lines.extend(["", "A passing run covers only this policy's configured operations and evidence assertions."])
    return "\n".join(lines) + "\n"


STYLE = """
:root{color-scheme:dark;--bg:#0b1220;--panel:#111c2e;--line:#26354b;--text:#e8eef7;--muted:#a8b8ce;--mint:#72e6ba;--red:#ff939e;--amber:#ffcf85}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}main{max-width:1180px;margin:auto;padding:52px 28px 70px}.eyebrow{font:700 12px ui-monospace,monospace;letter-spacing:.18em;color:var(--mint)}h1{font-size:clamp(29px,4vw,44px);line-height:1.15;margin:15px 0}h2{font-size:21px;margin:36px 0 15px}h3{margin:0;font-size:18px}p{margin:10px 0}.muted,small{color:var(--muted)}code{font:13px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}header{border-bottom:1px solid var(--line);padding-bottom:26px}.meta{display:flex;gap:12px 24px;flex-wrap:wrap}.pill{border:1px solid var(--line);border-radius:30px;padding:3px 10px;font-size:12px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:26px 0}.stat,.card{border:1px solid var(--line);background:var(--panel);border-radius:12px;padding:20px}.stat strong{font-size:32px;display:block;line-height:1.2}.stat span{font-size:12px;color:var(--muted)}.bad{color:var(--red)}.good{color:var(--mint)}.warn{color:var(--amber)}.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:12px}table{border-collapse:collapse;width:100%;min-width:640px}th,td{padding:14px 18px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{font-size:12px;color:var(--muted);background:var(--panel);font-weight:600}tr:last-child td{border-bottom:0}td small,th small{display:block;font-weight:400}.cell{white-space:nowrap;font:700 12px ui-monospace,monospace}.cell small{font-weight:400;margin-top:5px}.card{margin-bottom:14px}.card-top{display:flex;gap:12px;justify-content:space-between;align-items:baseline;flex-wrap:wrap}.facts{display:grid;grid-template-columns:1fr 1fr;gap:15px;margin-top:15px}.fact{min-width:0}.fact small{display:block;margin-bottom:4px}details{margin-top:15px;border-top:1px solid var(--line);padding-top:12px}summary{cursor:pointer;color:var(--muted)}ul{padding-left:22px}.notice{border-left:3px solid var(--mint);padding:12px 18px;background:var(--panel)}footer{margin-top:40px;padding-top:18px;border-top:1px solid var(--line);font-size:12px;color:var(--muted)}@media(max-width:700px){main{padding:28px 16px}.stats{grid-template-columns:1fr 1fr}.facts{grid-template-columns:1fr}.stat{padding:15px}}
"""


def html(report):
    e = lambda value: escape(str(value), quote=True)
    counts = Counter(case["status"] for case in report["cases"])
    attention = sum(needs_attention(case) for case in report["cases"])
    probe_ids = {case["identity"] for case in report["cases"]}
    identities = [identity for identity in report["identities"] if identity["id"] in probe_ids]
    resources = list(dict.fromkeys(case["resource"] for case in report["cases"]))
    lookup = {(case["resource"], case["identity"]): case for case in report["cases"]}
    outcome_class = lambda status: "bad" if status in {"confirmed-leak", "confirmed-write"} else "warn" if status in {"error", "inconclusive"} else "good"
    violations = counts["confirmed-leak"] + counts["confirmed-write"]
    violation_label = "CONFIRMED WRITES" if report.get("kind") == "write" else "CONFIRMED LEAKS"
    subtitle = "Observed mutation effects, account checks and fixture restoration." if report.get("kind") == "write" else "Who could access each resource, with verified identities and owner controls."
    parts = ["<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>",
             "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">",
             f"<title>TenantBreak | {e(report['name'])}</title><style>{STYLE}</style></head><body><main>",
             "<header><div class='eyebrow'>TENANTBREAK / AUTHORIZATION EVIDENCE</div>",
             f"<h1>{e(report['name'])}</h1><p class='muted'>{subtitle}</p>",
             f"<div class='meta'><code>{e(report['base_url'])}</code><span class='pill'>{e(report['mode'])}</span><small>{e(report['created_at'])}</small></div></header>",
             "<section class='stats' aria-label='Run summary'>",
             f"<div class='stat'><strong>{len(report['cases'])}</strong><span>ACCESS CHECKS</span></div>",
             f"<div class='stat'><strong class='bad'>{violations}</strong><span>{violation_label}</span></div>",
             f"<div class='stat'><strong class='good'>{counts['allowed'] + counts['denied']}</strong><span>EXPECTED OUTCOMES</span></div>",
             f"<div class='stat'><strong class='warn'>{attention}</strong><span>NEED ATTENTION</span></div></section>"]
    if report["mode"].startswith("demo"):
        parts.append("<p class='notice'>Local lab run against an actual HTTP API with invented users and records. These findings describe the bundled fixture application.</p>")
    if report.get("authentication", {}).get("refresh_requested"):
        parts.append("<p class='notice'>Pre-run credential refresh was requested. No refresh or retries occur during access probes.</p>")
    if report.get("scope", {}).get("total_cases", len(report["cases"])) != len(report["cases"]):
        parts.append(f"<p class='notice'>Focused run: {len(report['cases'])} of {report['scope']['total_cases']} policy checks selected. Unselected checks were not run. Required identity checks and owner controls are retained.</p>")
    if attention or any(not c["valid"] for c in report["controls"]) or any(not i["valid"] for i in identities):
        parts.append("<p class='notice'>This run has incomplete evidence. Review identity checks, owner controls and individual results before drawing a conclusion.</p>")
    parts.append("<h2>Access matrix</h2><p class='muted'>ALLOW and DENY match the declared policy. LEAK confirms configured resource or field exposure. WRITE confirms a forbidden state change. UNKNOWN, ERROR and incomplete coverage or cleanup require investigation.</p><div class='scroll'><table><thead><tr><th>RESOURCE</th>")
    for identity in identities:
        parts.append(f"<th>{e(identity['id'])}<small>{e(identity['tenant'])} / {e(identity['role'])}</small></th>")
    parts.append("</tr></thead><tbody>")
    for resource in resources:
        first = next(case for case in report["cases"] if case["resource"] == resource)
        parts.append(f"<tr><td><strong>{e(first['label'])}</strong><small>{e(first['resource_tenant'])}</small><small><code>{e(first['method'])} {e(first['path'])}</code></small></td>")
        for identity in identities:
            case = lookup.get((resource, identity["id"]))
            if case is None:
                parts.append("<td class='cell muted'>NOT RUN<small>outside selection</small></td>")
                continue
            parts.append(f"<td class='cell {outcome_class(case['status'])}'>{LABELS[case['status']]}<small>expected {e(case['expected'])} / HTTP {request_status(case) or '-'}</small></td>")
        parts.append("</tr>")
    parts.append("</tbody></table></div><h2>Findings and attention</h2>")
    selected = [case for case in report["cases"] if case["status"] in {"confirmed-leak", "confirmed-write"} or needs_attention(case)]
    if not selected:
        parts.append("<p class='notice'>All configured access checks matched the declared policy. This result covers only the resources, identities and assertions in this run.</p>")
    for case in selected:
        parts.append(f"<article class='card'><div class='card-top'><h3>{e(case['identity'])} &rarr; {e(case['label'])}</h3><span class='pill {outcome_class(case['status'])}'>{LABELS[case['status']]}</span></div>")
        parts.append(f"<p>{e(case['reason'].replace('-', ' '))}</p><div class='facts'><div class='fact'><small>REQUEST</small><code>{e(case['method'])} {e(case['path'])}</code></div><div class='fact'><small>POLICY</small>Expected {e(case['expected'])}; request HTTP {request_status(case) or '-'}; observation HTTP {case['http_status'] or '-'}</div><div class='fact'><small>IDENTITY</small>{e(case['identity_tenant'])} / {e(case['role'])}</div><div class='fact'><small>CONTROLS</small>Identity {'verified' if case['identity_valid'] else 'unverified'}; owner {'verified' if case['control_valid'] else 'unverified'}</div></div>")
        parts.append(details_html(case))
        parts.append("<details><summary>Evidence checks and response fingerprint</summary><ul>")
        for check in case["assertions"]:
            parts.append(f"<li><code>{e(check['pointer'])}</code>: {'matched' if check['matched'] else 'different' if check['present'] else 'missing'}</li>")
        parts.append(f"</ul><small>Response SHA-256</small><p><code>{e(case.get('response_sha256') or 'No complete response')}</code></p><small>Raw body and credential values are omitted.</small></details></article>")
    parts.append("<h2>Control checks</h2><div class='scroll'><table><thead><tr><th>CHECK</th><th>SUBJECT</th><th>RESULT</th><th>HTTP / DETAIL</th></tr></thead><tbody>")
    for identity in report["identities"]:
        refresh = identity.get("refresh_status", "not-requested")
        parts.append(f"<tr><td>Authenticated identity<small>{e(identity.get('auth_type', 'bearer'))}; refresh {e(refresh)}</small></td><td>{e(identity['id'])}</td><td class='{'good' if identity['valid'] else 'warn'}'>{'VERIFIED' if identity['valid'] else 'FAILED'}</td><td>{identity['http_status'] or '-'} / {e(identity['transport_error'] or 'identity assertions checked')}</td></tr>")
    for control in report["controls"]:
        label = "Owner can change and restore fixture" if report.get("kind") == "write" else "Owner can retrieve resource"
        parts.append(f"<tr><td>{label}</td><td>{e(control['identity'])} / {e(control['resource'])}</td><td class='{'good' if control['valid'] else 'warn'}'>{'VERIFIED' if control['valid'] else 'FAILED'}</td><td>{control['http_status'] or '-'} / {e(control['transport_error'] or 'configured evidence checked')}</td></tr>")
    parts.append("</tbody></table></div>")
    selected_ids = {case["id"] for case in selected}
    extended = [item for item in report["controls"] + [case for case in report["cases"] if case["id"] not in selected_ids] if "collection" in item or "write" in item]
    if extended:
        parts.append("<h2>Coverage and operation checks</h2>")
        for item in extended:
            label = item.get("id", item.get("resource", "Control"))
            parts.append(f"<article class='card'><h3>{e(label)}</h3>{details_html(item)}</article>")
    parts.append("<h2>Scope of this evidence</h2><ul>")
    parts.extend(f"<li>{e(note)}</li>" for note in report["notes"])
    parts.append(f"</ul><footer>TenantBreak {e(report['version'])} &middot; Policy SHA-256 <code>{e(report['policy_sha256'])}</code><p>Policy fingerprints exclude the target origin and do not authenticate a report. No general security score is assigned.</p></footer></main></body></html>")
    return "".join(parts)


def _xml_text(value):
    # XML 1.0 excludes several code points that valid JSON can represent.
    return "".join(c for c in str(value) if c in "\t\n\r" or 0x20 <= ord(c) <= 0xD7FF or 0xE000 <= ord(c) <= 0xFFFD or 0x10000 <= ord(c) <= 0x10FFFF)


def junit(report):
    suite = Element("testsuite", name=_xml_text(report["name"]))
    props = SubElement(suite, "properties")
    for name in ("mode", "base_url", "policy_sha256"):
        SubElement(props, "property", name=name, value=_xml_text(report[name]))
    SubElement(props, "property", name="refresh_requested", value=str(report.get("authentication", {}).get("refresh_requested", False)).lower())
    total = report.get("scope", {}).get("total_cases", len(report["cases"]))
    for name, value in (("selected_cases", len(report["cases"])), ("policy_cases", total),
                        ("scope", "focused" if len(report["cases"]) != total else "complete")):
        SubElement(props, "property", name=name, value=str(value))
    for identity in report["identities"]:
        test = SubElement(suite, "testcase", classname="tenantbreak.identity", name=_xml_text(identity["id"]))
        if not identity["valid"]:
            SubElement(test, "error", message="Identity verification failed")
    for control in report["controls"]:
        test = SubElement(suite, "testcase", classname="tenantbreak.control", name=_xml_text(control["resource"]))
        if not control["valid"]:
            SubElement(test, "error", message="Owner control failed")
    for case in report["cases"]:
        test = SubElement(suite, "testcase", classname="tenantbreak.access", name=_xml_text(case["id"]), time=str(case.get("elapsed_ms", 0) / 1000))
        diagnostic = json.dumps({key: case[key] for key in ("id", "expected", "http_status", "reason", "assertions")}, ensure_ascii=True)
        if case["status"] in {"confirmed-leak", "confirmed-write"}:
            SubElement(test, "failure", message="Forbidden state change observed" if case["status"] == "confirmed-write" else "Protected resource or fields returned to a forbidden identity").text = diagnostic
        elif case["status"] in {"error", "inconclusive"}:
            SubElement(test, "error", message=case["reason"]).text = diagnostic
    for item in report["controls"] + report["cases"]:
        key = item.get("id", item.get("resource"))
        for flag, label in (("coverage_complete", "coverage"), ("cleanup_verified", "cleanup"), ("execution_complete", "execution")):
            if flag in item:
                check = SubElement(suite, "testcase", classname="tenantbreak." + label, name=_xml_text(key))
                if item[flag] is False:
                    SubElement(check, "error", message=label + " incomplete")
    suite.set("tests", str(len(suite.findall("testcase"))))
    suite.set("failures", str(len(suite.findall("testcase/failure"))))
    suite.set("errors", str(len(suite.findall("testcase/error"))))
    return '<?xml version="1.0" encoding="utf-8"?>\n' + tostring(suite, encoding="unicode") + "\n"
