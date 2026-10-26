"""
php_Archangel — CLI-first with interactive fallback.

  php_archangel scan https://t.com [flags]   -> full pipeline, prompts only at gates
  php_archangel scan                          -> guided interactive (ask URL, then run)
  php_archangel report <scan.json>            -> Markdown narrative report (SecPipe style)
  php_archangel mcp [--allow-exploit] [--http] -> run MCP server (stdio default)

Gates: confirmation (OOM oracle) and exploitation ALWAYS ask in interactive mode
unless --auto-confirm / --auto-exploit / --no-interact is given. This is the
"user decides" doctrine enforced in code.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core.models import Verdict, ScanResult
from . import term as ui
from .reporting.markdown import build_markdown_report


def build_report_inline(d: dict) -> str:
    """AI triage (best-effort, provider default = free openrouter) + markdown.
    Continues the scan flow to completion — the user gets the full report
    without running any second command. Degrades to deterministic if AI off."""
    try:
        from .ai.provider import (AIProvider, ProviderConfig,
                                  triage_findings, apply_triage)
        ai = AIProvider(ProviderConfig(provider="openrouter"))
        if ai.available:
            t = triage_findings(ai, d)
            if t:
                d = apply_triage(d, t)
                d["ai_spend"] = ai.meter.report()
                print(f"[+] AI triage via {ai.cfg.provider}/{ai.cfg.model} "
                      f"({ai.meter.report()})")
            else:
                print("[!] AI triage returned no result — report continues deterministic")
        else:
            print("[i] AI triage skipped (no key set — php_archangel config)")
    except Exception as e:
        print(f"[!] AI triage skipped: {e}")
    return build_markdown_report(d, ai_narrative=True)
from .pipeline import run_scan  # pipeline orchestrator (next build step)


def _interactive_target() -> str:
    print("╔══════════════════════════════════════╗")
    print("║   php_Archangel — PHP Runtime Analyzer ║")
    print("║   CVE-2026-109618 / 109619 & floor   ║")
    print("╚══════════════════════════════════════╝")
    return input("Enter target URL (e.g. https://target.com): ").strip()


def _ask(prompt: str, options: list[str], default: int = 0) -> int:
    for i, o in enumerate(options, 1):
        print(f"    [{i}] {o}")
    while True:
        raw = input(f"{prompt} (default {default+1}): ").strip()
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw) - 1


def cmd_scan(args: argparse.Namespace) -> int:
    ui.print_banner()
    url = args.url or (None if args.no_interact else _interactive_target())
    if not url:
        print("error: target URL required (or pass --no-interact for automation "
              "with URL as positional argument)", file=sys.stderr)
        return 2

    result = run_scan(url, aggressive=args.aggressive,
                      js_deep=args.js_deep,
                      changelog_probes=not args.no_changelog_probes,
                      verify_mode=args.verify_mode)

    ui.print_target_panel(url, result.sapi_guess,
                           result.php_version_estimate,
                           result.php_version_confidence)
    ui.phase("RECON COMPLETE")
    ui.findings_table(result.to_dict().get("findings", []))

    # ---- Gate 1: confirmation oracle (interactive unless flags given)
    probables = [f for f in result.findings
                 if f.verdict == Verdict.PROBABLE and f.cve_id]
    if probables and not args.no_interact:
        print("\n[✓] PROBABLE finding(s):")
        for f in probables:
            print(f"    - {f.cve_id}: {f.title}  (evidence strength {f.evidence_strength():.2f})")
        if not args.auto_confirm:
            choice = _ask("Run deterministic confirmation oracle?", [
                "Confirm — OOM oracle (a vulnerable worker may crash & restart)",
                "Worker-affinity path (CVE-2026-109619, slower)",
                "Skip confirmation",
                "Skip and go straight to report"])
            if choice in (0, 1):
                from .verify.oom_oracle import confirm_findings
                ui.phase("ORACLE — 3-TIER ESCALATION")
                result = confirm_findings(result, mode="oom" if choice == 0 else "affinity")
                ui.phase("ORACLE COMPLETE")
                ui.findings_table(result.to_dict().get("findings", []))
                learned = {}
                for f in result.findings:
                    for e in f.evidence:
                        if e.kind == "oracle_oom_divergence":
                            learned = e.detail.get("learned") or {}
                for k, v in learned.items():
                    ui.intel_line(k, str(v))
    elif probables and args.auto_confirm:
        from .verify.oom_oracle import confirm_findings
        result = confirm_findings(result, mode="oom")

    # ---- Gate 2: exploitation (authorized use only)
    confirmed = [f for f in result.findings if f.verdict == Verdict.CONFIRMED]
    if confirmed and not args.no_interact and not args.no_exploit:
        if not args.auto_exploit:
            choice = _ask("Confirmed vulnerability present. Attempt exploit?",
                          ["Attempt exploit (test command on target)",
                           "Report only"], default=1)
            if choice == 0:
                from .exploit.angel_sword import exploit_confirmed
                result = exploit_confirmed(result)

    # ---- outputs
    outdir = Path(args.outdir or f"./archangel-out/{url.replace('://','_').replace('/','')}")
    outdir.mkdir(parents=True, exist_ok=True)
    d = result.to_dict()
    d["fingerprint"] = result.fingerprint_hash()
    (outdir / "findings.json").write_text(
        json.dumps(d, indent=2, default=str), encoding="utf-8")
    md = build_report_inline(d)
    (outdir / "report.md").write_text(md, encoding="utf-8")
    print(f"[+] Markdown report -> {outdir/'report.md'}")

    # Present the finished report to the user — paged when interactive
    # (like git/man), full dump when piped (CI/automation friendly)
    import sys
    print("\n" + "=" * 72)
    if sys.stdout.isatty():
        import subprocess
        try:
            subprocess.run(["less", "-R"], input=md.encode())   # q to quit
        except (FileNotFoundError, KeyboardInterrupt):
            print(md)
    else:
        print(md)
    print("=" * 72)
    print(f"\n[+] JSON findings -> {outdir/'findings.json'} "
          f"(fingerprint {result.fingerprint_hash()})")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from .reporting.markdown import build_markdown_report
    data = json.loads(Path(args.scan_json).read_text(encoding="utf-8"))
    data.setdefault('fingerprint', 'recomputed-see-findings.json')
    if not args.no_ai:
        try:
            from .ai.provider import (AIProvider, ProviderConfig,
                                      triage_findings, apply_triage)
            ai = AIProvider(ProviderConfig(provider=args.ai_provider,
                                           model=args.ai_model))
            if ai.available:
                t = triage_findings(ai, data)
                if t:
                    data = apply_triage(data, t)          # THE MISSING CALL
                    data["ai_spend"] = ai.meter.report()
                    print(f"[+] AI triage via {ai.cfg.provider}/{ai.cfg.model} "
                          f"({ai.meter.report()})")
                else:
                    print("[!] AI tier: triage returned no usable result "
                          "(transient model/API issue — re-run the command)")
            else:
                print(f"[!] AI tier unavailable: no key for {args.ai_provider} "
                      f"(run: php_archangel config)")
                if t:
                    data = apply_triage(data, t)
                    data["ai_spend"] = ai.meter.report()
                    print(f"[+] AI triage via {ai.cfg.provider}/{ai.cfg.model} "
                          f"({ai.meter.report()})")
        except Exception as e:
            print(f"[!] AI tier skipped: {e}")
    md = build_markdown_report(data, ai_narrative=not args.no_ai)
    Path(args.output).write_text(md, encoding="utf-8")
    print(f"[+] report -> {args.output}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="php_archangel",
                                 description="PHP runtime security posture analyzer (php_Archangel)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a target")
    s.add_argument("url", nargs="?", help="target URL (omit for interactive)")
    s.add_argument("--aggressive", action="store_true", help="opt-in heavier probing")
    s.add_argument("--js-deep", action="store_true", help="deep JS analysis tier")
    s.add_argument("--no-changelog-probes", action="store_true",
                   help="disable 8.5.11-vs-8.5.12 behavioral probes")
    s.add_argument("--verify-mode", choices=["safe", "confirm"], default="safe")
    s.add_argument("--auto-confirm", action="store_true")
    s.add_argument("--auto-exploit", action="store_true")
    s.add_argument("--no-exploit", action="store_true")
    s.add_argument("--no-interact", action="store_true")
    s.add_argument("--outdir", default="")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("report", help="generate Markdown report from findings.json")
    r.add_argument("scan_json")
    r.add_argument("--output", default="report.md")
    r.add_argument("--no-ai", action="store_true")
    r.add_argument("--ai-provider", default="nvidia",
                  choices=("openrouter", "nvidia", "anthropic", "openai"))
    r.add_argument("--ai-model", default=None,
                  help="override provider default model")
    r.set_defaults(func=cmd_report)

    c = sub.add_parser("config", help="set AI provider API keys (stored locally)")
    c.add_argument("--show", action="store_true", help="display stored keys (masked)")
    c.set_defaults(func=lambda a: (_show_keys() if a.show else _setup_keys()) or 0)

    u = sub.add_parser("ui", help="Rich hybrid console (needs [ui] extra)")
    u.add_argument("url", nargs="?", help="optional target to pre-arm")
    u.add_argument("--splash", action="store_true",
                   help="full-quality image on Kitty/iTerm2 before the dashboard")
    u.set_defaults(func=lambda a: _run_ui(a.url, a.splash) or 0)

    m = sub.add_parser("mcp", help="run MCP server (stdio default)")
    m.add_argument("--http", action="store_true", help="Streamable HTTP transport")
    m.add_argument("--port", type=int, default=8765)
    m.add_argument("--allow-exploit", action="store_true",
                   help="arm the exploit-capable tool (dual gate)")
    m.set_defaults(func=lambda a: _run_mcp(a))

    args = ap.parse_args(argv)
    return args.func(args)


def _run_mcp(args: argparse.Namespace) -> int:
    from .mcp.server import serve
    serve(http=args.http, port=args.port, allow_exploit=args.allow_exploit)
    return 0


if __name__ == "__main__":
    sys.exit(main())


def _setup_keys() -> None:
    from .config import interactive_setup
    interactive_setup()


def _show_keys() -> None:
    from .config import show_masked
    show_masked()


def _run_tui(url):
    from .tui import run_tui
    run_tui(target_url=url)
    return None


def _run_ui(url, splash):
    from .ui import run_dashboard
    run_dashboard(target_url=url, splash=splash)
    return 0
