"""One-shot scan, collect, evaluate, report and diff commands."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
from .engine import collect_snapshot, evaluate_snapshot, run_scan, diff_reports, get_catalog
from .reports import render_markdown


def _load(path):
    with open(path, encoding="utf-8") as stream:
        if str(path).endswith((".yaml", ".yml")):
            import yaml
            value = yaml.safe_load(stream)
        else:
            value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError("input must contain an object")
    return value


def _write(value, destination, format):
    text = render_markdown(value) if format == "markdown" else json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if destination:
        path = Path(destination).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(text)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    else:
        sys.stdout.write(text)


def _selectors(parser):
    parser.add_argument("--categories", nargs="+", help="hardening exposure least_privilege iam_graph network privesc")
    parser.add_argument("--checks", nargs="+", help="native check IDs, 'privesc', or privesc technique IDs")
    parser.add_argument("--frameworks", nargs="+", help="hacktricks nist_800_53, or full framework names")


def _output(parser):
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    parser.add_argument("--output", "-o")


def build_parser():
    parser = argparse.ArgumentParser(prog="peaso", description="Read-only cloud inventory and offline defensive security review")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "collect"):
        command = commands.add_parser(name)
        command.add_argument("--request", help="JSON/YAML scan request containing connector")
        command.add_argument("--provider", choices=("aws", "gcp", "azure", "k8s"))
        command.add_argument("--name", default="cli")
        command.add_argument("--scopes", nargs="+", help="account/project/subscription or cluster namespace selection")
        command.add_argument("--auth-file", help="private JSON/YAML provider auth object; SDK default credentials when omitted")
        command.add_argument("--options-file", help="JSON/YAML collection settings and optional explicit limits")
        command.add_argument("--profile", help="AWS profile")
        command.add_argument("--context", help="Kubernetes kubeconfig context")
        command.add_argument("--demo", action="store_true", help="deterministic offline sample, no cloud calls")
        command.add_argument("--snapshot", help="offline snapshot JSON input, no cloud calls")
        command.add_argument("--snapshot-output", help="save collected immutable snapshot JSON")
        _selectors(command)
        _output(command)
    command = commands.add_parser("evaluate")
    command.add_argument("snapshot")
    _selectors(command)
    _output(command)
    command = commands.add_parser("report")
    command.add_argument("report")
    _output(command)
    command.set_defaults(format="markdown")
    command = commands.add_parser("diff")
    command.add_argument("before")
    command.add_argument("after")
    _selectors(command)
    _output(command)
    command = commands.add_parser("catalog")
    _output(command)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    selectors = {key: getattr(args, key, None) for key in ("categories", "checks", "frameworks")}
    try:
        if args.command in ("scan", "collect"):
            request = _load(args.request) if args.request else {}
            connector = request.setdefault("connector", {})
            if args.provider:
                connector["provider"] = args.provider
            if args.name != "cli" or "name" not in connector:
                connector["name"] = args.name
            if args.scopes:
                connector["scopes"] = args.scopes
            auth = connector.setdefault("auth", {})
            options = connector.setdefault("options", {})
            if args.auth_file:
                auth.update(_load(args.auth_file))
            if args.options_file:
                options.update(_load(args.options_file))
            if args.profile:
                auth["profile"] = args.profile
            if args.context:
                auth["context"] = args.context
            if args.demo:
                options["demo"] = True
            if args.snapshot:
                snapshot = _load(args.snapshot)
                connector.setdefault("provider", snapshot.get("provider"))
                options["snapshot"] = snapshot
            for key, value in selectors.items():
                if value is not None:
                    request[key] = value
            value = run_scan(request) if args.command == "scan" else collect_snapshot(request)
            if args.snapshot_output:
                _write(value.get("snapshot", value), args.snapshot_output, "json")
            if args.command == "collect" and args.format == "markdown":
                value = evaluate_snapshot(value, **selectors)
        elif args.command == "evaluate":
            value = evaluate_snapshot(_load(args.snapshot), **selectors)
        elif args.command == "report":
            value = _load(args.report)
        elif args.command == "diff":
            before, after = _load(args.before), _load(args.after)
            if "collections" in before:
                before = evaluate_snapshot(before, **selectors)
            if "collections" in after:
                after = evaluate_snapshot(after, **selectors)
            value = diff_reports(before, after)
        else:
            value = get_catalog()
        _write(value, args.output, args.format)
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"peaso: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
