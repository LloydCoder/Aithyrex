"""Aithyrex CLI. The ai-shield command remains a legacy entry-point alias."""

from __future__ import annotations

import asyncio
import os
import sys


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        _print_help()
    elif args[0] == "version":
        from ai_shield import __version__
        print(f"aithyrex {__version__}")
    elif args[0] == "health":
        _cmd_health(args[1:])
    elif args[0] == "inspect":
        _cmd_inspect(args[1:])
    elif args[0] == "mitre-report":
        _cmd_mitre_report(args[1:])
    else:
        print(f"Unknown command: {args[0]}")
        _print_help()
        sys.exit(1)


def _cmd_mitre_report(args: list[str]) -> None:
    fmt = _get_flag(args, "--format") or "all"
    out = _get_flag(args, "--output") or "docs"
    print(f"\nGenerating Aithyrex threat-mapping report ({fmt})...")
    from backend.core.mitre_report import generate_json, generate_markdown, generate_csv, write_reports

    if fmt == "all":
        paths = write_reports(out)
        for file_type, path in paths.items():
            print(f"  {file_type}: {path}")
    elif fmt == "json":
        print(generate_json())
    elif fmt == "markdown":
        print(generate_markdown())
    elif fmt == "csv":
        print(generate_csv())
    else:
        print("Supported formats: all, json, markdown, csv")
        sys.exit(2)


def _print_help() -> None:
    print("""
Aithyrex — Agentic AI Runtime Security

Usage:
  aithyrex <command> [options]

Commands:
  health              Check configured API health
  inspect <prompt>    Inspect a prompt; configuration/transport errors do not pass
  mitre-report        Generate a heuristic threat-mapping report
  version             Show version

Options:
  --token TOKEN       Clerk session JWT (not a generic static API key)
  --url URL           API base URL; alternatively set AITHYREX_API_URL

Environment:
  AITHYREX_API_URL    Verified service URL
  AITHYREX_API_TOKEN  Clerk session JWT

Example:
  aithyrex inspect "Ignore all previous instructions" --token "$AITHYREX_API_TOKEN" --url "$AITHYREX_API_URL"

New deployments must configure the verified API URL explicitly; no hosted URL is assumed.
""")


def _cmd_health(args: list[str]) -> None:
    url = _get_flag(args, "--url") or os.getenv("AITHYREX_API_URL", "")
    from ai_shield.client import Shield

    shield = Shield(base_url=url)

    async def run():
        result = await shield.health()
        print(f"\nAithyrex health: {result.get('status', 'unknown').upper()}")
        for dependency, info in result.get("dependencies", {}).items():
            status = info.get("status", "?") if isinstance(info, dict) else str(info)
            latency = info.get("latency_ms", "") if isinstance(info, dict) else ""
            suffix = f" ({latency}ms)" if latency else ""
            print(f"  {dependency:12} {status}{suffix}")
        if result.get("status") == "unconfigured":
            print("Set AITHYREX_API_URL or pass --url.")
            sys.exit(2)

    asyncio.run(run())


def _cmd_inspect(args: list[str]) -> None:
    if not args or args[0].startswith("--"):
        print('Usage: aithyrex inspect "prompt" --token TOKEN --url URL')
        sys.exit(2)

    prompt = args[0]
    token = _get_flag(args[1:], "--token") or _get_flag(args[1:], "--api-key") or os.getenv("AITHYREX_API_TOKEN", "")
    url = _get_flag(args[1:], "--url") or os.getenv("AITHYREX_API_URL", "")
    if not token or not url:
        print("Inspection requires a Clerk session JWT and a verified Aithyrex API URL.")
        print("Set AITHYREX_API_TOKEN and AITHYREX_API_URL, or pass --token and --url.")
        sys.exit(2)

    from ai_shield.client import Shield
    shield = Shield(token=token, base_url=url)

    async def run():
        print("\nInspecting prompt...")
        verdict = await shield.inspect(prompt=prompt)
        status = _result_status(verdict)
        print(f"  Result:   {status}")
        print(f"  Action:   {verdict.action.upper()}")
        print(f"  Severity: {verdict.severity.upper()}")
        if verdict.degraded:
            print(f"  Degraded: {verdict.error_code or 'inspection_unavailable'}")
        if verdict.detections:
            print("  Detectors fired:")
            for detection in verdict.detections:
                print(f"    {detection.detector} ({detection.severity}, {detection.confidence:.0%} confidence)")
        if verdict.blocked or verdict.degraded or verdict.action in {"block", "alert"}:
            sys.exit(1)

    asyncio.run(run())


def _result_status(verdict) -> str:
    """Never label an alert or unavailable inspection as a successful pass."""
    if verdict.degraded:
        return "DEGRADED"
    if verdict.blocked or verdict.action == "block":
        return "BLOCKED"
    if verdict.action == "alert":
        return "ALERT"
    if verdict.action == "log":
        return "LOGGED"
    return "PASSED"


def _get_flag(args: list[str], flag: str) -> str:
    try:
        index = args.index(flag)
        return args[index + 1]
    except (ValueError, IndexError):
        return ""


if __name__ == "__main__":
    main()
