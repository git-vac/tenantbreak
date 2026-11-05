"""Regenerate committed synthetic examples and verify the complete lab experiment.

Run from an installed checkout with: python tools/build_examples.py
This deliberately overwrites only the known synthetic files in examples/.
"""

from html import escape
import json
from pathlib import Path

from tenantbreak.engine import exit_code, run
from tenantbreak import comparison
from tenantbreak.lab import TOKENS, demo_environment, demo_policy, server
from tenantbreak.config import credentials
from tenantbreak.onboarding import from_openapi, read_spec
from tenantbreak.report import html, junit, terminal
from tenantbreak.saved import normalize
from tenantbreak.scenarios import collection_policy, write_policy
from tenantbreak.writes import run_writes

ROOT = Path(__file__).resolve().parents[1]


def overview(before, after):
    identities = [item["id"] for item in before["identities"]]
    resources = list(dict.fromkeys(case["resource"] for case in before["cases"]))
    matrices = [
        {(case["resource"], case["identity"]): case["status"] for case in report["cases"]}
        for report in (before, after)
    ]
    expected = {(resource, identity) for resource in resources for identity in identities}
    if len(resources) != 4 or len(identities) != 4 or any(m.keys() != expected for m in matrices):
        raise ValueError("showcase requires matching four-by-four demo matrices")
    leaks = [sum(status == "confirmed-leak" for status in m.values()) for m in matrices]
    controls = [sum(item["valid"] for item in report["controls"]) for report in (before, after)]
    verified = [sum(item["valid"] for item in report["identities"]) for report in (before, after)]
    if controls != [4, 4] or verified != [4, 4]:
        raise ValueError("showcase requires verified identities and passing owner controls")

    svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="580" viewBox="0 0 1200 580" role="img" aria-labelledby="title desc">',
           '<!-- Design method: Unslop by Damir Sokolovsky (@heydamir), CC BY 4.0. https://github.com/heydamir/unslop -->',
           '<title id="title">TenantBreak: API authorization before and after the fix</title>',
           f'<desc id="desc">The synthetic HTTP lab found {leaks[0]} forbidden reads before the fix and {leaks[1]} after. For each resource and identity, the left cell is before and the right cell is after.</desc>',
           '<style>',
           'text{font-family:system-ui,Segoe UI,sans-serif;fill:#252422;font-variant-numeric:tabular-nums}',
           '.mono{font-family:Consolas,Menlo,monospace}.meta{fill:#625c55}.rule{stroke:#d8d2c9}.leak{fill:#913525}',
           '</style>',
           '<rect x="0.5" y="0.5" width="1199" height="579" rx="16" fill="#f7f4ee" stroke="#d8d2c9"/>',
           '<text x="40" y="43" font-size="18" font-weight="600">TenantBreak</text>',
           '<text x="1160" y="43" text-anchor="end" class="mono meta" font-size="16">Synthetic HTTP lab</text>',
           '<path d="M40 60H1160" class="rule"/>',
           '<text x="40" y="110" font-size="42" font-weight="500">API authorization before and after the fix</text>',
           f'<text x="40" y="180" class="mono leak" font-size="52">{leaks[0]}</text>',
           '<path d="M83 162h30m-8-7 8 7-8 7" fill="none" stroke="#777068" stroke-width="1.5"/>',
           f'<text x="130" y="180" class="mono" font-size="52">{leaks[1]}</text>',
           '<text x="184" y="174" font-size="22">Confirmed forbidden reads</text>',
           f'<text x="1160" y="150" text-anchor="end" class="meta" font-size="17">{len(expected)} checks per run</text>',
           f'<text x="1160" y="176" text-anchor="end" class="meta" font-size="17">{verified[0]} verified identities · {controls[0]} passing owner controls per run</text>',
           '<rect x="40" y="208" width="1120" height="296" rx="12" fill="#fdfbf7"/>',
           '<path d="M52 208H1148Q1160 208 1160 220V280H40V220Q40 208 52 208Z" fill="#ede8df"/>',
           '<text x="60" y="252" font-size="18" font-weight="500">Resource</text>']
    labels = {"confirmed-leak": "Leak", "allowed": "Allow", "denied": "Deny"}
    for col, identity in enumerate(identities):
        x = 280 + col * 220
        svg.extend([
            f'<text x="{x+110}" y="236" text-anchor="middle" class="mono" font-size="19">{escape(identity)}</text>',
            f'<text x="{x+55}" y="264" text-anchor="middle" class="meta" font-size="16">Before</text>',
            f'<text x="{x+165}" y="264" text-anchor="middle" class="meta" font-size="16">After</text>',
            f'<path d="M{x} 208V504M{x+110} 248V504" class="rule"/>',
        ])
    for row, resource in enumerate(resources):
        y = 280 + row * 56
        svg.append(f'<text x="60" y="{y+35}" class="mono" font-size="18">{escape(resource)}</text>')
        for col, identity in enumerate(identities):
            for side, matrix in enumerate(matrices):
                x = 280 + col * 220 + side * 110
                status = matrix[resource, identity]
                label = labels[status]
                color = "leak" if status == "confirmed-leak" else "meta" if status == "denied" else ""
                if status == "confirmed-leak":
                    svg.append(f'<rect x="{x+1}" y="{y+1}" width="109" height="55" fill="#f4ded4"/>')
                svg.append(f'<text x="{x+55}" y="{y+35}" text-anchor="middle" class="{color}" font-size="18">{label}</text>')
        svg.append(f'<path d="M40 {y}H1160" class="rule"/>')
    svg.extend([
        '<rect x="40" y="208" width="1120" height="296" rx="12" fill="none" class="rule"/>',
        '<text x="40" y="548" class="leak" font-size="17">Leak = a forbidden read confirmed</text>',
        '<text x="1160" y="548" text-anchor="end" class="meta" font-size="17">Real HTTP requests against invented records</text>',
        '</svg>',
    ])
    return "\n".join(svg) + "\n"


def main():
    destination = ROOT / "examples"
    destination.mkdir(exist_ok=True)
    reports = {}
    for mode, expected in (("vulnerable", 1), ("fixed", 0)):
        with server(mode) as address:
            report = run(demo_policy(), TOKENS, base_url=address, mode="demo-" + mode)
        if exit_code(report) != expected:
            raise RuntimeError(f"{mode} lab returned unexpected evidence")
        if not all(item["valid"] for item in report["identities"] + report["controls"]):
            raise RuntimeError("lab controls failed")
        reports[mode] = report
        for extension, content in (("json", json.dumps(report, indent=2) + "\n"), ("html", html(report)), ("xml", junit(report)), ("txt", terminal(report))):
            (destination / f"{mode}.{extension}").write_text(content, encoding="utf-8", newline="\n")
    if reports["vulnerable"]["counts"].get("confirmed-leak") != 9 or reports["fixed"]["counts"] != {"allowed": 6, "denied": 10}:
        raise RuntimeError("unexpected lab matrix")
    if reports["vulnerable"]["policy_sha256"] != reports["fixed"]["policy_sha256"]:
        raise RuntimeError("lab policy changed between implementations")
    result = comparison.compare(reports["vulnerable"], reports["fixed"])
    if comparison.exit_code(result) != 0 or result["counts"].get("resolved-leak") != 9:
        raise RuntimeError("lab comparison did not establish the expected resolutions")
    for extension, content in (("json", json.dumps(result, indent=2) + "\n"), ("html", comparison.html(result)),
                               ("xml", comparison.junit(result)), ("txt", comparison.terminal(result))):
        (destination / f"comparison.{extension}").write_text(content, encoding="utf-8", newline="\n")
    with server("vulnerable") as address:
        focused = run(demo_policy(), TOKENS, base_url=address, mode="demo-vulnerable", case_ids=["alice-invoice:bob"])
    if len(focused["cases"]) != 1 or exit_code(focused) != 1 or len(focused["identities"]) != 2 or len(focused["controls"]) != 1:
        raise RuntimeError("focused replay did not retain its dependencies")
    (destination / "focused.html").write_text(html(focused), encoding="utf-8", newline="\n")
    (destination / "focused.json").write_text(json.dumps(focused, indent=2) + "\n", encoding="utf-8", newline="\n")
    document, digest = read_spec(destination / "openapi.json")
    draft = from_openapi(document, base_url="http://127.0.0.1:8080", name="LedgerCloud authorization policy", operation_ids=["readInvoice"])
    draft["source"]["document_sha256"] = digest
    (destination / "policy.draft.json").write_text(json.dumps(draft, indent=2) + "\n", encoding="utf-8", newline="\n")
    (destination / "policy.json").write_text(json.dumps(demo_policy(), indent=2) + "\n", encoding="utf-8", newline="\n")
    (destination / "overview.svg").write_text(overview(reports["vulnerable"], reports["fixed"]), encoding="utf-8", newline="\n")
    for auth in ("headers", "cookies", "refresh"):
        policy = demo_policy(auth)
        (destination / f"policy.{auth}.json").write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8", newline="\n")
        tokens = credentials(policy, demo_environment(), refresh_auth=auth == "refresh")
        with server("fixed", auth=auth) as address:
            report = run(policy, tokens, base_url=address, refresh_auth=auth == "refresh", refresh_sink=lambda *_: None)
        if exit_code(report) != 0 or report["counts"] != {"allowed": 6, "denied": 10}:
            raise RuntimeError("lab authentication workflow failed")
    for scenario, policy, runner, confirmed, resolved in (("collections", collection_policy(), run, "confirmed-leak", "resolved-leak"),
                                                         ("writes", write_policy(), run_writes, "confirmed-write", "resolved-write")):
        pair = []
        (destination / f"policy.{scenario}.json").write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8", newline="\n")
        for mode in ("vulnerable", "fixed"):
            with server(mode, scenario=scenario) as address:
                report = runner(policy, TOKENS, base_url=address, mode="demo-" + mode, **({"enable_writes": True} if scenario == "writes" else {}))
            pair.append(report)
            for extension, content in (("json", json.dumps(report, indent=2) + "\n"), ("html", html(report)), ("xml", junit(report)), ("txt", terminal(report))):
                (destination / f"{scenario}-{mode}.{extension}").write_text(content, encoding="utf-8", newline="\n")
            if exit_code(report) != (1 if mode == "vulnerable" else 0):
                attention = ", ".join(case["id"] + ":" + case["reason"] for case in report["cases"] if case["status"] in {"error", "inconclusive"})
                raise RuntimeError(f"{scenario} {mode} returned incomplete or unexpected evidence: {attention}")
            if normalize(report)["counts"] != report["counts"]:
                raise RuntimeError("saved scenario evidence was inconsistent")
        expected = 9 if scenario == "collections" else 6
        difference = comparison.compare(*pair)
        if pair[0]["counts"].get(confirmed) != expected or difference["counts"].get(resolved) != expected or comparison.exit_code(difference) != 0:
            raise RuntimeError("advanced experiment did not establish the expected resolutions")
        for extension, content in (("json", json.dumps(difference, indent=2) + "\n"), ("html", comparison.html(difference)),
                                   ("xml", comparison.junit(difference)), ("txt", comparison.terminal(difference))):
            (destination / f"{scenario}-comparison.{extension}").write_text(content, encoding="utf-8", newline="\n")
    print("Verified HTTP labs: 9 object leaks, 9 collection/field leaks and 6 forbidden writes resolved; focused checks and cleanup verified. Examples regenerated.")


if __name__ == "__main__":
    main()
