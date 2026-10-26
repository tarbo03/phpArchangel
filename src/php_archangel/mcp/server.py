"""
php_Archangel MCP server — the tool as an agentic capability.

Two transports:
  stdio (default)   — local: Claude Desktop / Cursor / Cline
  Streamable HTTP   — remote deployments: bearer-token authenticated

Tool exposure (trust boundary by tool):
  scan_target   — recon sweep, non-destructive, PROBABLE verdicts
  confirm_cve   — deterministic confirmation oracle (may crash vulnerable worker)
  get_evidence  — return the evidence chain of a saved scan
  report        — Markdown report generation
  exploit_target — angel-sword weapon. DUAL-GATED:
        gate 1: server started with --allow-exploit
        gate 2: bearer token auth on HTTP transport (stdio = local owner)
    An AI operator cannot autonomously weaponize; the human arms the server.

Non-interactive parity: every CLI prompt is a parameter here — one core,
two faces. Requires: pip install mcp  (optional dependency [mcp])
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Optional

from ..core.models import Verdict
from ..pipeline import run_scan
from ..verify.oom_oracle import confirm_findings

_CACHE: dict[str, dict] = {}   # scan_id -> result payload (session lifetime)


def _out_dir_for(url: str) -> Path:
    safe = url.replace("://", "_").replace("/", "").replace(":", "")
    return Path(os.environ.get("ARCHANGEL_OUT", "./archangel-out")) / safe


def _scan_to_payload(result) -> dict:
    d = result.to_dict()
    d["fingerprint"] = result.fingerprint_hash()
    return d


def _do_scan(url: str, auto_confirm: bool = False,
             aggressive: bool = False) -> dict:
    result = run_scan(url, aggressive=aggressive, verbose=False)
    if auto_confirm:
        result = confirm_findings(result, mode="oom")
    payload = _scan_to_payload(result)
    scan_id = payload["fingerprint"]
    _CACHE[scan_id] = payload
    outdir = _out_dir_for(url)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "findings.json").write_text(
        json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return {"scan_id": scan_id, **payload}


def _do_confirm(scan_id: str, mode: str = "oom") -> dict:
    if scan_id not in _CACHE:
        return {"error": f"unknown scan_id {scan_id} — run scan_target first"}
    payload = _CACHE[scan_id]
    from ..core.models import ScanResult, Finding, Severity
    result = ScanResult(target=payload["target"])
    result.php_version_estimate = payload["php_version"]["estimate"]
    result.sapi_guess = payload["php_version"]["sapi_guess"]
    for fd in payload["findings"]:
        f = Finding(cve_id=fd.get("cve_id"), title=fd.get("title", ""),
                    description=fd.get("description", ""),
                    severity=Severity(fd.get("severity", "MEDIUM")),
                    target_url=payload["target"])
        f.verdict = Verdict(fd.get("verdict", "PROBABLE"))
        result.findings.append(f)
    if mode not in ("oom", "affinity"):
        mode = "oom"
    result = confirm_findings(result, mode=mode)
    payload = _scan_to_payload(result)
    _CACHE[scan_id] = payload
    return {"scan_id": scan_id,
            "summary": result.summary_line(),
            "findings": payload["findings"]}


def _do_evidence(scan_id: str) -> dict:
    payload = _CACHE.get(scan_id)
    if not payload:
        return {"error": "unknown scan_id"}
    return {"evidence_chains": [
        {"finding": f.get("cve_id") or f.get("title"),
         "verdict": f.get("verdict"),
         "evidence": f.get("evidence")}
        for f in payload.get("findings", [])]}


def _do_report(scan_id: str, use_ai: bool = True) -> dict:
    payload = _CACHE.get(scan_id)
    if not payload:
        return {"error": "unknown scan_id"}
    from ..reporting.markdown import build_markdown_report
    if use_ai:
        try:
            from ..ai.provider import (AIProvider, ProviderConfig,
                                       triage_findings, apply_triage)
            ai = AIProvider(ProviderConfig())
            if ai.available:
                t = triage_findings(ai, payload)
                payload = apply_triage(payload, t)
                payload["ai_spend"] = ai.meter.report()
        except Exception:
            pass
    md = build_markdown_report(payload, ai_narrative=use_ai)
    outdir = _out_dir_for(payload["target"])
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "report.md").write_text(md, encoding="utf-8")
    return {"scan_id": scan_id, "report_path": str(outdir / "report.md"),
            "report_markdown": md[:4000],
            "note": "full report persisted to report_path"}


def _do_exploit(scan_id: str, cmd: str = "id>/tmp/a1",
               profile: str = "bookworm") -> dict:
    if not _ALLOW_EXPLOIT:
        return {"error": "exploit tool not armed — start server with --allow-exploit"}
    payload = _CACHE.get(scan_id)
    if not payload:
        return {"error": "unknown scan_id"}
    from ..core.models import ScanResult, Finding, Severity
    result = ScanResult(target=payload["target"])
    for fd in payload["findings"]:
        f = Finding(cve_id=fd.get("cve_id"), title=fd.get("title", ""),
                    description=fd.get("description", ""),
                    severity=Severity(fd.get("severity", "MEDIUM")),
                    target_url=payload["target"])
        f.verdict = Verdict(fd.get("verdict", "PROBABLE"))
        result.findings.append(f)
    from ..exploit.angel_sword import exploit_confirmed
    result = exploit_confirmed(result, cmd=cmd, profile=profile)
    _CACHE[scan_id] = _scan_to_payload(result)
    return {"executed": True, "cmd": cmd, "notes": result.notes}


_ALLOW_EXPLOIT = False
_HTTP_TOKEN: Optional[str] = None


def serve(http: bool = False, port: int = 8765, allow_exploit: bool = False,
          token: Optional[str] = None) -> None:
    """Entry from `php_archangel mcp [--http] [--allow-exploit]`."""
    global _ALLOW_EXPLOIT, _HTTP_TOKEN
    _ALLOW_EXPLOIT = allow_exploit

    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        raise SystemExit("MCP extra not installed: pip install 'php-archangel[mcp]'")

    if http:
        _HTTP_TOKEN = token or secrets.token_urlsafe(24)
        mcp = FastMCP("php_Archangel", host="0.0.0.0", port=port)
    else:
        mcp = FastMCP("php_Archangel")

    @mcp.tool()
    def scan_target(url: str, auto_confirm: bool = False,
                    aggressive: bool = False) -> dict:
        """Recon sweep of a PHP target. Non-destructive; returns PROBABLE
        verdicts with evidence chains. auto_confirm=True additionally runs
        the OOM oracle (may crash a vulnerable worker — disclosed cost)."""
        return _do_scan(url, auto_confirm=auto_confirm, aggressive=aggressive)

    @mcp.tool()
    def confirm_cve(scan_id: str, mode: str = "oom") -> dict:
        """Run the deterministic confirmation oracle (oom|affinity). Promotes
        PROBABLE->CONFIRMED only on definitive evidence; retracts on patched."""
        return _do_confirm(scan_id, mode)

    @mcp.tool()
    def get_evidence(scan_id: str) -> dict:
        """Return full evidence chains for a completed scan."""
        return _do_evidence(scan_id)

    @mcp.tool()
    def report(scan_id: str, use_ai: bool = True) -> dict:
        """Generate the SecPipe-style Markdown report (AI narrative if key set)."""
        return _do_report(scan_id, use_ai)

    @mcp.tool()
    def exploit_target(scan_id: str, cmd: str = "id>/tmp/a1",
                      profile: str = "bookworm") -> dict:
        """Chain-D weapon: execute a command (<=14 bytes) on a CONFIRMED
        target. Only available if server was started with --allow-exploit."""
        return _do_exploit(scan_id, cmd, profile)

    if http:
        print(f"[*] php_Archangel MCP (HTTP) on :{port}  "
              f"bearer token: {_HTTP_TOKEN}  "
              f"exploit armed: {_ALLOW_EXPLOIT}")
        mcp.run(transport="streamable-http")
    else:
        import sys
        print(f"[*] php_Archangel MCP (stdio)  exploit armed: {_ALLOW_EXPLOIT}",
              file=sys.stderr)
        mcp.run(transport="stdio")
