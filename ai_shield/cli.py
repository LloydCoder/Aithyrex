"""
AI Shield CLI
==============
Command-line interface for AI Shield.

Commands:
    ai-shield health          Check API health
    ai-shield inspect         Inspect a prompt
    ai-shield version         Show version
"""

from __future__ import annotations
import asyncio
import sys


def main() -> None:
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help", "help"):
        _print_help()
    elif args[0] == "version":
        from ai_shield import __version__
        print(f"ai-shield {__version__}")
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

    print(f"\n🛡  Generating MITRE ATLAS coverage report ({fmt})...")
    from backend.core.mitre_report import generate_json, generate_markdown, generate_csv, write_reports
    import os

    if fmt == "all":
        paths = write_reports(out)
        for path, f in paths.items():
            print(f"   ✅ {f}: {path}")
    elif fmt == "json":
        print(generate_json())
    elif fmt == "markdown":
        print(generate_markdown())
    elif fmt == "csv":
        print(generate_csv())
    print()


def _print_help() -> None:
    print("""
AI Shield — Runtime Security for LLM & Agentic AI Systems

Usage:
  ai-shield <command> [options]

Commands:
  health              Check API health status
  inspect <prompt>    Inspect a prompt for threats
  mitre-report        Generate MITRE ATLAS coverage report
  version             Show version

Options:
  --api-key KEY       AI Shield API key
  --url URL           API base URL (default: https://api.aishield.tinlance.com)

Examples:
  ai-shield health --api-key sk-shield-...
  ai-shield inspect "Ignore all previous instructions" --api-key sk-shield-...
  ai-shield version

Docs: https://tinlance.com/ai-shield
""")


def _cmd_health(args: list[str]) -> None:
    api_key = _get_flag(args, "--api-key")
    url = _get_flag(args, "--url") or "https://api.aishield.tinlance.com"

    from ai_shield.client import Shield
    shield = Shield(api_key=api_key, base_url=url)

    async def run():
        result = await shield.health()
        status = result.get("status", "unknown")
        print(f"\n🛡  AI Shield Health")
        print(f"   Status:  {status.upper()}")
        print(f"   Version: {result.get('version', '?')}")
        deps = result.get("dependencies", {})
        for dep, info in deps.items():
            s = info.get("status", "?") if isinstance(info, dict) else str(info)
            ms = info.get("latency_ms", "") if isinstance(info, dict) else ""
            print(f"   {dep:12} {s}" + (f"  ({ms}ms)" if ms else ""))
        print()

    asyncio.run(run())


def _cmd_inspect(args: list[str]) -> None:
    if not args or args[0].startswith("--"):
        print("Usage: ai-shield inspect <prompt> [--api-key KEY]")
        sys.exit(1)

    prompt = args[0]
    api_key = _get_flag(args[1:], "--api-key")
    url = _get_flag(args[1:], "--url") or "https://api.aishield.tinlance.com"

    from ai_shield.client import Shield
    shield = Shield(api_key=api_key, base_url=url)

    async def run():
        print(f"\n🛡  Inspecting prompt...")
        verdict = await shield.inspect(prompt=prompt)
        status = "🔴 BLOCKED" if verdict.blocked else "🟢 PASSED"
        print(f"   Result:   {status}")
        print(f"   Action:   {verdict.action.upper()}")
        print(f"   Severity: {verdict.severity.upper()}")
        if verdict.detections:
            print("   Detectors fired:")
            for d in verdict.detections:
                print(f"     • {d.detector} ({d.severity}, {d.confidence:.0%} confidence)")
                if d.mitre_atlas:
                    print(f"       MITRE: {', '.join(d.mitre_atlas)}")
        print()

    asyncio.run(run())


def _get_flag(args: list[str], flag: str) -> str:
    try:
        i = args.index(flag)
        return args[i + 1]
    except (ValueError, IndexError):
        return ""


if __name__ == "__main__":
    main()
