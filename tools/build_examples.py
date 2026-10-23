"""Regenerate committed synthetic examples and verify the complete lab experiment.

Run from an installed checkout with: python tools/build_examples.py
This deliberately overwrites only the known synthetic files in examples/.
"""

from html import escape
import json
from pathlib import Path

from tenantbreak.engine import exit_code, run
from tenantbreak import comparison
from tenantbreak.lab import TOKENS, demo_policy, server
from tenantbreak.onboarding import from_openapi, read_spec
from tenantbreak.report import html, junit, terminal

ROOT = Path(__file__).resolve().parents[1]


def overview(before, after):
    e = escape
    svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="660" viewBox="0 0 1280 660" role="img" aria-labelledby="title desc">',
           '<title id="title">TenantBreak: verify access, expose leaks, replay the fix</title>',
           '<desc id="desc">The same four identities and four resources produce nine confirmed leaks against the vulnerable lab and zero against the fixed lab.</desc>',
           '<rect width="1280" height="660" rx="18" fill="#0b1220"/>',
           '<g font-family="system-ui,Segoe UI,sans-serif">',
           '<text x="40" y="46" fill="#72e6ba" font-family="monospace" font-size="13" letter-spacing="3">TENANTBREAK / AUTHORIZATION EVIDENCE</text>',
           '<text x="40" y="103" fill="#e8eef7" font-size="36" font-weight="700">Same policy. Two implementations. Observable proof.</text>',
           '<text x="40" y="138" fill="#a8b8ce" font-size="17">Actual HTTP requests / invented fixture records / verified identities and owner controls</text>']
    for x, report, title, accent in ((40, before, "VULNERABLE API", "#ff939e"), (660, after, "FIXED API", "#72e6ba")):
        leak_count = sum(case["status"] == "confirmed-leak" for case in report["cases"])
        svg.extend([f'<rect x="{x}" y="177" width="580" height="413" rx="12" fill="#111c2e" stroke="#26354b"/>',
                    f'<text x="{x+24}" y="215" fill="{accent}" font-size="13" font-weight="700" letter-spacing="1.5">{title}</text>',
                    f'<text x="{x+24}" y="272" fill="{accent}" font-size="42" font-weight="700">{leak_count}</text>',
                    f'<text x="{x+88}" y="268" fill="#e8eef7" font-size="19">confirmed forbidden reads</text>',
                    f'<text x="{x+24}" y="304" fill="#a8b8ce" font-size="14">4 identities verified / 4 owner controls passed / 16 checks</text>'])
        for column, identity in enumerate(report["identities"]):
            label = identity["id"].replace("admin-acme", "admin")
            svg.append(f'<text x="{x+238+column*88}" y="349" text-anchor="middle" fill="#a8b8ce" font-size="13">{e(label)}</text>')
        resources = list(dict.fromkeys(case["resource"] for case in report["cases"]))
        lookup = {(case["resource"], case["identity"]): case for case in report["cases"]}
        for row, resource in enumerate(resources):
            y = 383 + row * 48
            svg.append(f'<text x="{x+24}" y="{y+7}" fill="#e8eef7" font-size="14">{e(resource)}</text>')
            for column, identity in enumerate(report["identities"]):
                case = lookup[(resource, identity["id"])]
                leak = case["status"] == "confirmed-leak"
                label = "LEAK" if leak else "ALLOW" if case["status"] == "allowed" else "DENY"
                color = "#ff939e" if leak else "#72e6ba"
                fill = "#392331" if leak else "#15322e"
                cx = x + 238 + column * 88
                svg.append(f'<rect x="{cx-36}" y="{y-15}" width="72" height="31" rx="5" fill="{fill}"/><text x="{cx}" y="{y+6}" text-anchor="middle" fill="{color}" font-family="monospace" font-size="13" font-weight="700">{label}</text>')
    svg.extend(['<text x="40" y="628" fill="#a8b8ce" font-size="14">A result covers the configured identities, resources and assertions. No general security score.</text>', '</g></svg>'])
    return "".join(svg)


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
    print("Verified HTTP lab: 9 leaks before; 6 allowed + 10 denied after; 9 resolutions; focused case retains controls. Examples regenerated.")


if __name__ == "__main__":
    main()
