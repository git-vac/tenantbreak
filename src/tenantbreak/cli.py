"""Policy setup, bounded API checks and offline evidence workflows."""

import argparse
from contextlib import nullcontext
import json
import math
import os
from pathlib import Path
import time

from . import __version__
from . import comparison
from .config import PolicyError, credentials, load, origin
from .credential_file import read_credentials, refresh_output
from .engine import exit_code, run
from .lab import TOKENS, demo_environment, demo_policy, server
from .onboarding import finalize, from_openapi, load_draft, read_spec, starter
from .report import html, junit, terminal
from .saved import load_report, replay_cases
from .selection import dependencies, select
from .writes import run_writes


def positive_seconds(value):
    try:
        result = float(value)
        if not math.isfinite(result) or not 0 < result <= 3600:
            raise ValueError
        return result
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected seconds greater than 0 and at most 3600") from exc


def output_options(parser, network=True):
    parser.add_argument("--html", type=Path, help="write a self-contained evidence report (new file)")
    parser.add_argument("--json", type=Path, help="write machine-readable evidence (new file)")
    parser.add_argument("--junit", type=Path, help="write CI test results (new file)")
    if network:
        parser.add_argument("--timeout", type=positive_seconds, default=5.0, help="socket timeout in seconds (default: 5)")
        parser.add_argument("--max-seconds", type=positive_seconds, default=120.0, help="run budget in seconds (default: 120)")


def selector_options(parser):
    parser.add_argument("--identity", dest="identity_ids", action="append", help="select a probe identity; repeatable")
    parser.add_argument("--resource", dest="resource_ids", action="append", help="select a resource; repeatable")
    parser.add_argument("--case", dest="case_ids", action="append", help="select RESOURCE:IDENTITY; repeatable; filters intersect")


def auth_options(parser):
    parser.add_argument("--credentials-file", type=Path, help="private credential JSON; entries override environment values")
    parser.add_argument("--refresh-auth", action="store_true", help="refresh configured bearer accounts once before verification; requires --refresh-out")
    parser.add_argument("--refresh-out", type=Path, help="new credential snapshot inside private/; contains secrets and must not be shared")


def preflight(args):
    targets = [path for path in (args.html, args.json, args.junit) if path is not None]
    if len({str(path.resolve()).casefold() for path in targets}) != len(targets):
        raise PolicyError("output paths must be distinct")
    for path in targets:
        if path.exists() or path.is_symlink():
            raise PolicyError("output files must be new; choose a different report path")
        if not path.name:
            raise PolicyError("expected an output file")
        path.parent.mkdir(parents=True, exist_ok=True)


def write_outputs(args, report, render_html=html, render_junit=junit):
    # Generate every format before opening any output file.
    outputs = [(args.html, render_html(report)), (args.json, json.dumps(report, indent=2, ensure_ascii=True) + "\n"), (args.junit, render_junit(report))]
    for path, content in outputs:
        if path is not None:
            with path.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(content)


def write_setup(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    contents = json.dumps(value, indent=2, ensure_ascii=True) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(contents)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Test explicit API authorization rules with verified identities and resource evidence.")
    parser.add_argument("--version", action="version", version=f"TenantBreak {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="run against a temporary loopback API with synthetic data")
    demo.add_argument("--mode", choices=["vulnerable", "fixed"], default="vulnerable")
    demo.add_argument("--auth", choices=["bearer", "headers", "cookies"], default="bearer")
    demo.add_argument("--scenario", choices=["objects", "collections", "writes"], default="objects")
    demo.add_argument("--enable-writes", action="store_true", help="explicitly enable disposable fixture mutations")
    demo.add_argument("--cleanup-seconds", type=positive_seconds, default=10.0)
    output_options(demo)
    selector_options(demo)
    live = sub.add_parser("run", help="evaluate your explicit read-only policy")
    live.add_argument("policy", type=Path)
    live.add_argument("--base-url", help="override the configured target origin")
    live.add_argument("--allow-http", action="store_true", help="permit plaintext HTTP outside loopback")
    output_options(live)
    selector_options(live)
    auth_options(live)
    writer = sub.add_parser("write", help="test explicitly disposable fixture mutations and verify cleanup")
    writer.add_argument("policy", type=Path)
    writer.add_argument("--enable-writes", action="store_true", help="required opt-in for mutation requests")
    writer.add_argument("--cleanup-seconds", type=positive_seconds, default=10.0, help="separate cleanup budget per attempt, 1..120 seconds")
    writer.add_argument("--base-url")
    writer.add_argument("--allow-http", action="store_true")
    output_options(writer)
    selector_options(writer)
    auth_options(writer)
    replay = sub.add_parser("replay", help="rerun recorded cases using a matching policy and fresh environment credentials")
    replay.add_argument("policy", type=Path)
    replay.add_argument("saved", type=Path)
    replay.add_argument("--case", dest="case_ids", action="append", help="recorded RESOURCE:IDENTITY; default: confirmed leaks")
    replay.add_argument("--base-url", help="explicit target override; saved-report URLs are never used for requests")
    replay.add_argument("--allow-http", action="store_true")
    output_options(replay)
    auth_options(replay)
    diff = sub.add_parser("compare", help="compare saved evidence offline without making API requests")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("--allow-target-change", action="store_true", help="acknowledge different target origins; definitions and scope must still match")
    output_options(diff, network=False)
    init = sub.add_parser("init", help="create an editable policy draft offline")
    init.add_argument("--out", type=Path, required=True)
    init.add_argument("--base-url", default="https://api.example.invalid")
    init.add_argument("--name", default="API authorization policy")
    importer = sub.add_parser("import-openapi", help="extract GET routes from a local OpenAPI JSON/YAML file into a draft")
    importer.add_argument("specification", type=Path)
    importer.add_argument("--out", type=Path, required=True)
    importer.add_argument("--base-url", required=True, help="explicit target origin; specification server URLs are not used")
    importer.add_argument("--name", default="API authorization policy")
    importer.add_argument("--path-prefix", default="", help="explicit API version prefix, such as /v1")
    importer.add_argument("--operation", dest="operation_ids", action="append", help="select a GET operationId; repeatable")
    importer.add_argument("--path", dest="path_filters", action="append", help="select an exact OpenAPI path; repeatable; intersects --operation")
    finish = sub.add_parser("finalize", help="validate an edited draft and write a runnable policy offline")
    finish.add_argument("draft", type=Path)
    finish.add_argument("--out", type=Path, required=True)
    check = sub.add_parser("validate", help="validate policy structure without reading credentials or contacting the API")
    check.add_argument("policy", type=Path)
    lab = sub.add_parser("lab", help="serve the synthetic API on loopback for manual experiments")
    lab.add_argument("--mode", choices=["vulnerable", "fixed"], default="vulnerable")
    lab.add_argument("--auth", choices=["bearer", "headers", "cookies", "refresh"], default="bearer")
    lab.add_argument("--scenario", choices=["objects", "collections", "writes"], default="objects")
    lab.add_argument("--port", type=int, default=8080)
    lab.add_argument("--credentials-out", type=Path, required=True,
                     help="new private .sh or .ps1 file for the lab's generated environment variables")
    args = parser.parse_args(argv)
    try:
        if args.command in {"init", "import-openapi", "finalize"}:
            if args.command == "init":
                value = starter(base_url=args.base_url, name=args.name)
            elif args.command == "import-openapi":
                document, digest = read_spec(args.specification)
                value = from_openapi(document, base_url=args.base_url, name=args.name,
                                     path_prefix=args.path_prefix, operation_ids=args.operation_ids, path_filters=args.path_filters)
                value["source"]["document_sha256"] = digest
            else:
                value = finalize(load_draft(args.draft))
            write_setup(args.out, value)
            print("Runnable policy written. No requests made." if args.command == "finalize" else "Editable draft written. Complete its policy values and review notes, then run tenantbreak finalize. No requests made.")
            return 0
        if args.command == "validate":
            policy = load(args.policy)
            print(f"Policy valid: {len(policy['identities'])} identities x {len(policy['resources'])} resources. No requests made.")
            return 0
        if args.command == "lab":
            if args.scenario != "objects" and args.auth == "refresh":
                raise PolicyError("advanced lab scenarios support bearer, headers or cookies; refresh uses the objects lab")
            if not 1 <= args.port <= 65535:
                raise PolicyError("port must be between 1 and 65535")
            if args.credentials_out.suffix not in {".sh", ".ps1"}:
                raise PolicyError("lab credentials output must be a new .sh or .ps1 file inside private/")
            private_root = Path.cwd().resolve() / "private"
            if private_root.is_symlink() or not args.credentials_out.resolve().is_relative_to(private_root):
                raise PolicyError("generated lab credentials must stay inside the current directory's private/ folder")
            args.credentials_out.parent.mkdir(parents=True, exist_ok=True)
            with server(args.mode, args.port, auth=args.auth, scenario=args.scenario) as address:
                lines = []
                for identity in demo_policy()["identities"]:
                    key, value = identity["token_env"], TOKENS[identity["id"]]
                    lines.append(f"$env:{key} = '{value}'" if args.credentials_out.suffix == ".ps1" else f"export {key}='{value}'")
                    if args.auth == "refresh":
                        key += "_REFRESH"
                        value = demo_environment()[key]
                        lines.append(f"$env:{key} = '{value}'" if args.credentials_out.suffix == ".ps1" else f"export {key}='{value}'")
                fd = os.open(args.credentials_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                    stream.write("\n".join(lines) + "\n")
                print(f"TenantBreak synthetic {args.mode} lab: {address}", flush=True)
                print("Generated credentials saved to the selected private file. No token values are printed. Ctrl+C to stop.", flush=True)
                while True:
                    time.sleep(0.5)
        preflight(args)
        if args.command == "compare":
            before, before_sha = load_report(args.before)
            after, after_sha = load_report(args.after)
            result = comparison.compare(before, after, allow_target_change=args.allow_target_change, before_sha=before_sha, after_sha=after_sha)
            write_outputs(args, result, comparison.html, comparison.junit)
            print(comparison.terminal(result))
            return comparison.exit_code(result)
        if args.command == "demo":
            from .scenarios import collection_policy, write_policy
            policy = collection_policy() if args.scenario == "collections" else write_policy() if args.scenario == "writes" else demo_policy(args.auth)
            if args.scenario != "objects" and args.auth != "bearer":
                # Apply the existing credential definitions to advanced fixtures.
                for identity, configured in zip(policy["identities"], demo_policy(args.auth)["identities"]):
                    identity.pop("token_env", None)
                    identity["auth"] = configured["auth"]
            if args.scenario == "writes" and not args.enable_writes:
                raise PolicyError("the disposable write demo requires --enable-writes")
            selected = select(policy, identity_ids=args.identity_ids, resource_ids=args.resource_ids, case_ids=args.case_ids)
            tokens = credentials(policy, demo_environment(), dependencies(policy, selected))
            with server(args.mode, auth=args.auth, scenario=args.scenario) as address:
                runner = run_writes if args.scenario == "writes" else run
                extra = {"enable_writes": args.enable_writes, "cleanup_seconds": args.cleanup_seconds} if args.scenario == "writes" else {}
                report = runner(policy, tokens, base_url=address, timeout=args.timeout,
                             max_seconds=args.max_seconds, mode="demo-" + args.mode,
                             identity_ids=args.identity_ids, resource_ids=args.resource_ids, case_ids=args.case_ids, **extra)
        else:
            policy = load(args.policy)
            if args.command == "run" and policy.get("kind") == "write":
                raise PolicyError("write policies require tenantbreak write with --enable-writes")
            if args.command == "write" and (policy.get("kind") != "write" or not args.enable_writes or not 1 <= args.cleanup_seconds <= 120):
                raise PolicyError("write requires a disposable write policy, --enable-writes and cleanup-seconds between 1 and 120")
            if args.refresh_auth != (args.refresh_out is not None):
                raise PolicyError("use --refresh-auth together with --refresh-out private/NEW-FILE.json")
            if args.refresh_out and any(args.refresh_out.resolve() == path.resolve() for path in (args.html, args.json, args.junit) if path):
                raise PolicyError("private credentials and evidence must use different output files")
            source_sha = None
            if args.command == "replay":
                source, source_sha = load_report(args.saved)
                selected = replay_cases(policy, source, args.case_ids)
            else:
                selected = select(policy, identity_ids=args.identity_ids, resource_ids=args.resource_ids, case_ids=args.case_ids)
            target = origin(args.base_url or policy["base_url"], allow_http=args.allow_http)
            environment = dict(os.environ)
            if args.credentials_file:
                environment.update(read_credentials(args.credentials_file))
            tokens = credentials(policy, environment, dependencies(policy, selected), args.refresh_auth)
            runner = run_writes if args.command == "write" else run
            extra = {"enable_writes": True, "cleanup_seconds": args.cleanup_seconds} if args.command == "write" else {}
            with refresh_output(args.refresh_out) if args.refresh_out else nullcontext(None) as save:
                report = runner(policy, tokens, base_url=target, timeout=args.timeout,
                             max_seconds=args.max_seconds, allow_http=args.allow_http, case_ids=selected,
                             refresh_auth=args.refresh_auth, refresh_sink=save, **extra)
            if args.refresh_out:
                print("Refreshed credential state saved privately. The file contains secrets; do not share it. Identity verification results follow.")
            if source_sha:
                report["replay_of"] = source_sha
        write_outputs(args, report)
        print(terminal(report))
        return exit_code(report)
    except KeyboardInterrupt:
        print("Interrupted.")
        return 130
    except (PolicyError, OSError, UnicodeError):
        # Never print arbitrary OS/provider errors: they can embed credentials.
        # PolicyError messages are locally authored and contain no token values.
        import sys
        error = sys.exc_info()[1]
        print(f"TenantBreak: {error if isinstance(error, PolicyError) else 'unable to open a local file or lab port'}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
