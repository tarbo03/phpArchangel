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
from typing import Optional
import os
from pathlib import Path

from .core.models import Verdict, ScanResult
from . import term as ui
from .reporting.markdown import build_markdown_report


def build_report_inline(d: dict, show_progress: bool = True) -> str:
    """AI triage (best-effort, provider default = free openrouter) + markdown.
    Continues the scan flow to completion — the user gets the full report
    without running any second command. Degrades to deterministic if AI off."""
    try:
        from .ai.provider import (AIProvider, ProviderConfig,
                                  triage_findings, apply_triage)
        from .progress import Spinner as _Spinner
        ai = AIProvider(ProviderConfig(provider="openrouter"))
        if ai.available:
            _sp = _Spinner("AI-TRIAGE", enabled=show_progress and sys.stdout.isatty())
            _sp.start()
            try:
                t = triage_findings(ai, d)
            finally:
                _sp.stop()
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

    use_progress = (
        not getattr(args, "no_progress", False) and sys.stdout.isatty()
    )
    if use_progress:
        from .progress import ProgressBar
        from .term import S as _S
        print(f"  {_S.CYAN}\u25b8{_S.RESET} {url}")
        pb = ProgressBar(
            phases=["entry", "easteregg", "components", "js",
                    "changelog", "reconcile", "verdicts"],
            label="RECON",
        )
        pb.start("entry")
        try:
            result = run_scan(url, aggressive=args.aggressive,
                              js_deep=args.js_deep,
                              changelog_probes=not args.no_changelog_probes,
                              verify_mode=args.verify_mode,
                              verbose=False,
                              on_event=pb.tick)
        except BaseException:
            pb.fail("interrupted")
            raise
        pb.done()
    else:
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
                from .progress import ProgressBar as _PB
                ui.phase("ORACLE — 3-TIER ESCALATION")
                _oracle_phases = (["tier_1", "tier_2", "tier_3"] if choice == 0
                                  else ["step_1", "step_2"])
                _oracle_pb = _PB(phases=_oracle_phases, label="ORACLE",
                                  enabled=use_progress)
                _oracle_pb.start()
                try:
                    result = confirm_findings(
                        result,
                        mode="oom" if choice == 0 else "affinity",
                        on_event=_oracle_pb.tick,
                        verbose=not use_progress,
                    )
                except BaseException:
                    _oracle_pb.fail("oracle interrupted")
                    raise
                _oracle_pb.done(f"{_oracle_pb.current}/{_oracle_pb.total} "
                                 + ("tiers" if choice == 0 else "steps"))
                ui.phase("ORACLE COMPLETE")
                ui.findings_table(result.to_dict().get("findings", []))
                learned = {}
                for f in result.findings:
                    for e in f.evidence:
                        if e.kind == "oracle_oom_divergence":
                            learned = e.detail.get("learned") or {}
                for k, v in learned.items():
                    ui.intel_line(k, str(v))
        elif args.auto_confirm:
            # Auto-confirm in interactive mode — run oracle without prompting
            from .verify.oom_oracle import confirm_findings
            from .progress import ProgressBar as _PB
            ui.phase("ORACLE — 3-TIER ESCALATION")
            _oracle_pb = _PB(phases=["tier_1", "tier_2", "tier_3"],
                              label="ORACLE", enabled=use_progress)
            _oracle_pb.start()
            try:
                result = confirm_findings(
                    result, mode="oom",
                    on_event=_oracle_pb.tick,
                    verbose=not use_progress,
                )
            except BaseException:
                _oracle_pb.fail("oracle interrupted")
                raise
            _oracle_pb.done(f"{_oracle_pb.current}/{_oracle_pb.total} tiers")
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
        from .progress import ProgressBar as _PB
        _oracle_pb = _PB(phases=["tier_1", "tier_2", "tier_3"],
                          label="ORACLE", enabled=use_progress)
        _oracle_pb.start()
        try:
            result = confirm_findings(result, mode="oom",
                                      on_event=_oracle_pb.tick,
                                      verbose=not use_progress)
        except BaseException:
            _oracle_pb.fail("oracle interrupted")
            raise
        _oracle_pb.done(f"{_oracle_pb.current}/{_oracle_pb.total} tiers")

    # ---- Gate 2: exploitation (authorized use only)
    confirmed = [f for f in result.findings if f.verdict == Verdict.CONFIRMED]
    if confirmed and not args.no_exploit:
        do_exploit = False
        
        if args.auto_exploit:
            do_exploit = True
        elif not args.no_interact:
            choice = _ask("Confirmed vulnerability present. Attempt exploit?",
                          ["Attempt exploit (test command on target)",
                           "Report only"], default=1)
            if choice == 0:
                do_exploit = True
                
        if do_exploit:
            from .exploit.angel_sword import exploit_confirmed
            from .progress import ProgressBar as _PB
            _exp_pb = _PB(
                phases=["rotate", "stage1", "stage2", "stage3"],
                label="EXPLOIT", enabled=use_progress,
            )
            _exp_pb.start()
            try:
                result = exploit_confirmed(
                    result,
                    on_event=_exp_pb.tick,
                    verbose=not use_progress,
                )
            except BaseException:
                _exp_pb.fail("exploit interrupted")
                raise
            # exploit_confirmed appends the outcome as the last note;
            # use it to decide success vs failure honestly.
            _last_note = (result.notes or [""])[-1]
            if "chain executed" in _last_note:
                _exp_pb.done(f"{_exp_pb.current}/{_exp_pb.total} stages")
            else:
                _exp_pb.fail(
                    f"failed at stage {_exp_pb.current + 1}"
                    f" (see findings.json)"
                )

    # ---- outputs
    outdir = Path(args.outdir or f"./archangel-out/{url.replace('://','_').replace('/','')}")
    outdir.mkdir(parents=True, exist_ok=True)
    d = result.to_dict()
    d["fingerprint"] = result.fingerprint_hash()
    (outdir / "findings.json").write_text(
        json.dumps(d, indent=2, default=str), encoding="utf-8")
    md = build_report_inline(d, show_progress=use_progress)
    (outdir / "report.md").write_text(md, encoding="utf-8")
    print(f"[+] Markdown report -> {outdir/'report.md'}")

    # Present the finished report to the user.
    # If interactive, open the markdown file in the system's default GUI editor.
    # If piped/automated, dump the markdown directly to stdout.
    if sys.stdout.isatty():
        import subprocess
        import platform
        report_path = outdir / "report.md"
        print(f"\n[+] Report saved to: {report_path}")
        print(f"[+] Opening in default text editor...")
        try:
            if platform.system() == "Linux":
                # xdg-open triggers the default GUI app (e.g., Mousepad, gedit, VS Code)
                subprocess.Popen(["xdg-open", str(report_path)], 
                                 stdout=subprocess.DEVNULL, 
                                 stderr=subprocess.DEVNULL)
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", str(report_path)])
            elif platform.system() == "Windows":
                os.startfile(str(report_path))
            else:
                raise OSError("Unknown OS")
        except Exception as e:
            print(f"[!] Could not open GUI editor ({e}). Falling back to terminal output.\n")
            print(md)
    else:
        print("\n" + "=" * 72)
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
        except Exception as e:
            print(f"[!] AI tier skipped: {e}")
    md = build_markdown_report(data, ai_narrative=not args.no_ai)
    report_path = Path(args.output)
    report_path.write_text(md, encoding="utf-8")
    print(f"[+] report -> {report_path}")

    if sys.stdout.isatty():
        import subprocess
        import platform
        print("[+] Opening in default text editor...")
        try:
            if platform.system() == "Linux":
                subprocess.Popen(["xdg-open", str(report_path)],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", str(report_path)])
            elif platform.system() == "Windows":
                os.startfile(str(report_path))
        except Exception as e:
            print(f"[!] Could not open GUI editor ({e}).")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    # banner even on -h/--help: print before argparse renders its view
    import sys as _sys
    _args = argv if argv is not None else _sys.argv[1:]
    if "-h" in _args or "--help" in _args or not _args:
        from .term import print_banner
        print_banner()
    ap = argparse.ArgumentParser(prog="archangel",
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
    s.add_argument("--no-progress", action="store_true",
                   help="disable the live progress bar (falls back to verbose output)")
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

    m = sub.add_parser("mcp", help="run MCP server (stdio default)")
    m.add_argument("--http", action="store_true", help="Streamable HTTP transport")
    m.add_argument("--port", type=int, default=8765)
    m.add_argument("--allow-exploit", action="store_true",
                   help="arm the exploit-capable tool (dual gate)")
    m.set_defaults(func=lambda a: _run_mcp(a))

    args = ap.parse_args(argv)
    return args.func(args)


def _run_mcp(args: argparse.Namespace) -> int:
    if args.http:
        print("[!] WARNING: HTTP transport is exposed. Ensure you are using a firewall or reverse proxy.")
        print("[!] It is highly recommended to use stdio for local MCP connections.")
    from .mcp.server import serve
    serve(http=args.http, port=args.port, allow_exploit=args.allow_exploit)
    return 0


def _setup_keys() -> None:
    from .config import interactive_setup
    interactive_setup()


def _show_keys() -> None:
    from .config import show_masked
    show_masked()


if __name__ == "__main__":
    sys.exit(main())
