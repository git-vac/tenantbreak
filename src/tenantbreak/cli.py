"""Small CLI: validate a policy, run it, or reproduce the bundled HTTP lab."""

import argparse
import json
import math
import os
from pathlib import Path
import time

from . import __version__
from .config import PolicyError, credentials, load, origin
from .engine import exit_code, run
from .lab import TOKENS, demo_policy, server
from .report import html, junit, terminal


def positive_seconds(value):
    try:
        result = float(value)
        if not math.isfinite(result) or not 0 < result <= 3600:
            raise ValueError
        return result
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected seconds greater than 0 and at most 3600") from exc


def output_options(parser):
    parser.add_argument("--html", type=Path, help="write a self-contained evidence report (new file)")
    parser.add_argument("--json", type=Path, help="write machine-readable evidence (new file)")
    parser.add_argument("--junit", type=Path, help="write CI test results (new file)")
    parser.add_argument("--timeout", type=positive_seconds, default=5.0, help="per-request timeout in seconds (default: 5)")
    parser.add_argument("--max-seconds", type=positive_seconds, default=120.0, help="run budget in seconds (default: 120)")


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


def write_outputs(args, report):
    # Generate every format before opening any output file.
    outputs = [(args.html, html(report)), (args.json, json.dumps(report, indent=2, ensure_ascii=True) + "\n"), (args.junit, junit(report))]
    for path, content in outputs:
        if path is not None:
            with path.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(content)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Test explicit API authorization rules with verified identities and resource evidence.")
    parser.add_argument("--version", action="version", version=f"TenantBreak {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="run against a temporary loopback API with synthetic data")
    demo.add_argument("--mode", choices=["vulnerable", "fixed"], default="vulnerable")
    output_options(demo)
    live = sub.add_parser("run", help="evaluate your explicit read-only policy")
    live.add_argument("policy", type=Path)
    live.add_argument("--base-url", help="override the configured target origin")
    live.add_argument("--allow-http", action="store_true", help="permit plaintext HTTP outside loopback")
    output_options(live)
    check = sub.add_parser("validate", help="validate policy structure without reading credentials or contacting the API")
    check.add_argument("policy", type=Path)
    lab = sub.add_parser("lab", help="serve the synthetic API on loopback for manual experiments")
    lab.add_argument("--mode", choices=["vulnerable", "fixed"], default="vulnerable")
    lab.add_argument("--port", type=int, default=8080)
    lab.add_argument("--credentials-out", type=Path, required=True,
                     help="new private .sh or .ps1 file for the lab's generated environment variables")
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            policy = load(args.policy)
            print(f"Policy valid: {len(policy['identities'])} identities x {len(policy['resources'])} resources. No requests made.")
            return 0
        if args.command == "lab":
            if not 1 <= args.port <= 65535:
                raise PolicyError("port must be between 1 and 65535")
            if args.credentials_out.suffix not in {".sh", ".ps1"}:
                raise PolicyError("lab credentials output must be a new .sh or .ps1 file inside private/")
            private_root = Path.cwd().resolve() / "private"
            if private_root.is_symlink() or not args.credentials_out.resolve().is_relative_to(private_root):
                raise PolicyError("generated lab credentials must stay inside the current directory's private/ folder")
            args.credentials_out.parent.mkdir(parents=True, exist_ok=True)
            with server(args.mode, args.port) as address:
                lines = []
                for identity in demo_policy()["identities"]:
                    key, value = identity["token_env"], TOKENS[identity["id"]]
                    lines.append(f"$env:{key} = '{value}'" if args.credentials_out.suffix == ".ps1" else f"export {key}='{value}'")
                fd = os.open(args.credentials_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                    stream.write("\n".join(lines) + "\n")
                print(f"TenantBreak synthetic {args.mode} lab: {address}", flush=True)
                print("Generated credentials saved to the selected private file. No token values are printed. Ctrl+C to stop.", flush=True)
                while True:
                    time.sleep(0.5)
        preflight(args)
        if args.command == "demo":
            with server(args.mode) as address:
                report = run(demo_policy(), TOKENS, base_url=address, timeout=args.timeout,
                             max_seconds=args.max_seconds, mode="demo-" + args.mode)
        else:
            policy = load(args.policy)
            target = origin(args.base_url or policy["base_url"], allow_http=args.allow_http)
            tokens = credentials(policy)
            report = run(policy, tokens, base_url=target, timeout=args.timeout,
                         max_seconds=args.max_seconds, allow_http=args.allow_http)
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
