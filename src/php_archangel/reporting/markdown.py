"""
SecPipe-style Markdown report generator.

Report doctrine:
  - every finding shows its evidence chain (kind, strength, detail)
  - retracted suspicions get their own section WITH reasons — never hidden
  - deterministic severity is the severity of record; AI opinion appears
    distinctly labeled (ai_risk/ai_note) — never merged into fact
  - methodology + limitations sections keep the output defensible in front
    of clients and auditors
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _ev_strength(e: dict) -> str:
    table = {"header_xpoweredby": "weak", "header_server": "weak",
             "setcookie_phpsessid": "moderate", "error_text_versionband": "moderate",
             "easteregg_hash": "strong", "easteregg_credits": "moderate",
             "behavioral_quirk": "strong", "composer_lock": "definitive",
             "wp_readme_version": "strong", "oracle_oom_divergence": "definitive",
             "oracle_worker_affinity": "definitive", "exploit_execution": "definitive",
             "changelog_delta_probe": "strong", "sapi_inferred": "moderate",
             "cms_detected": "moderate", "js_library_version": "moderate",
             "js_sourcemap_ref": "moderate", "php_rpc_endpoint": "moderate",
             "vendor_exposed": "moderate", "php_entrypoint": "weak"}
    return table.get(e.get("kind"), "?")


def _ts(x: Optional[float]) -> str:
    if not x:
        return "?"
    return datetime.fromtimestamp(x, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def build_markdown_report(scan: dict, ai_narrative: bool = True) -> str:
    """scan: dict from ScanResult.to_dict() (already AI-triaged or not)."""
    pv = scan.get("php_version", {})
    out: list[str] = []
    w = out.append

    w("# php_Archangel Scan Report")
    w("")
    w(f"**Target:** `{scan.get('target')}`  ")
    w(f"**Scanned:** {_ts(scan.get('started'))} — finished {_ts(scan.get('finished'))}  ")
    w(f"**PHP version:** ~{pv.get('estimate') or 'unknown'} "
      f"(confidence {pv.get('confidence', 0):.2f}) — SAPI: {pv.get('sapi_guess') or 'unknown'}  ")
    w(f"**Evidence fingerprint:** `{scan.get('fingerprint', '')}`")
    w("")

    # ---------------- executive summary ---------------------------------
    findings = scan.get("findings", [])
    confirmed = [f for f in findings if f.get("verdict") == "CONFIRMED"]
    probable  = [f for f in findings if f.get("verdict") == "PROBABLE"]
    retracted = [f for f in findings if f.get("verdict") == "RETRACTED"]
    clean    = [f for f in findings if f.get("verdict") == "CLEAN"]
    w("## Executive Summary")
    w("")
    if confirmed:
        w(f"**{len(confirmed)} CONFIRMED finding(s)** — verified by deterministic "
          "oracle against the live target. Immediate remediation recommended.")
    elif probable:
        w(f"**{len(probable)} PROBABLE finding(s)** — strong evidence, confirmation "
          "oracle not run (safe mode). Run `php_archangel scan --auto-confirm` to "
          "convert to CONFIRMED (a vulnerable worker may crash and auto-restart).")
    else:
        w("No vulnerable-path findings. Patch-floor posture is reported below "
          "if the target is behind its branch's current release.")
    w("")
    w("| # | CVE | Verdict | Severity |")
    w("|---|-----|----------|----------|")
    idx = 1
    for f in sorted([*confirmed, *probable, *retracted],
                    key=lambda f: _SEV_ORDER.index(f.get("severity", "LOW"))
                    if f.get("severity") in _SEV_ORDER else 4):
        if f.get("verdict") == "CLEAN":
            continue
        cve = f.get("cve_id") or "—"
        w(f"| {idx} | {cve} | {f.get('verdict')} | {f.get('severity')} |")
        idx += 1
    w("")

    # ---------------- findings detail ------------------------------------
    for i, f in enumerate(sorted([*confirmed, *probable], key=lambda x:
            _SEV_ORDER.index(x.get("severity", "LOW"))
            if x.get("severity") in _SEV_ORDER else 4), 1):
        w(f"### Finding {i}: {f.get('cve_id') or 'Informational'} — "
          f"{f.get('title', '')}")
        w("")
        w(f"**Verdict:** {f.get('verdict')} &nbsp; **Severity:** {f.get('severity')}")
        w("")
        if f.get("verdict") == "CONFIRMED":
            w("> Deterministically confirmed: the verification oracle reproduced "
              "the vulnerable behavior against the live target.")
            w("")
        desc = f.get("description") or ""
        if desc:
            w(desc)
            w("")
        if f.get("ai_note"):
            w(f"*AI triage ({f.get('ai_risk') or 'n/a'}):* {f['ai_note']}")
            w("")
        rem = f.get("remediation") or f.get("ai_remediation")
        if rem:
            w(f"**Remediation:** {rem}")
            w("")
        w("**Evidence chain:**")
        w("")
        w("| Kind | Strength | Key detail |")
        w("|------|----------|------------|")
        for e in f.get("evidence", []):
            d = e.get("detail", {})
            key = ", ".join(f"{k}={str(v)[:60]}" for k, v in list(d.items())[:3])
            w(f"| `{e.get('kind')}` | {_ev_strength(e)} | {key} |")
        w("")

    # ---------------- retraction log (never hidden) ----------------------
    if retracted:
        w("## Retracted Suspicions")
        w("")
        w("Suspected findings the verification pipeline could not prove. "
          "Kept visible for auditability — an honest tool retracts loudly.")
        w("")
        for f in retracted:
            w(f"- **{f.get('cve_id') or 'info'}**: {f.get('retraction_reason')}")
        w("")

    if clean:
        w("## Clean Checks")
        w("")
        for f in clean:
            w(f"- `{f.get('cve_id')}` — clean ({f.get('retraction_reason') or 'version above fix'})")
        w("")

    # ---------------- components ----------------------------------------
    comps = scan.get("components", [])
    if comps:
        w("## Detected Components")
        w("")
        w("| Component | Version | Source |")
        w("|-----------|---------|--------|")
        seen = set()
        for c in comps:
            key = (c.get("name"), c.get("version"))
            if key in seen:
                continue
            seen.add(key)
            w(f"| {c.get('name')} | {c.get('version')} | {c.get('source')} |")
        w("")
        w("*Embedded PHP components (requirement 8): resolve the actual runtime "
          "for each — a CMS does not determine the PHP version beneath it.*")
        w("")

    # ---------------- notes ---------------------------------------------
    notes = scan.get("notes", [])
    if notes:
        w("## Operational Notes")
        w("")
        for n in notes:
            w(f"- {n}")
        w("")

    # ---------------- methodology ---------------------------------------
    w("## Methodology")
    w("")
    w("- **Pipeline:** recon (headers, easter-egg hash corpus, composer/CMS "
      "discovery, JS asset analysis, changelog-delta probes) → version "
      "reconciliation (weighted evidence fusion) → signature-DB verdicts → "
      "5 false-positive filters → confirmation oracle on demand.")
    w("- **Verdicts:** CONFIRMED = deterministic oracle passed against the "
      "live target. PROBABLE = strong evidence, oracle not run. RETRACTED "
      "= verification failed, reason recorded. CLEAN = deterministically "
      "not affected.")
    w("- **AI tier:** structured evidence only — the model classifies and "
      "explains; it cannot invent facts or raise severity. Deterministic "
      "severity is the severity of record.")
    spend = scan.get("ai_spend")
    if spend:
        w(f"- **AI spend:** {spend.get('calls')} calls / "
          f"{spend.get('tokens')} tokens.")
    w("")
    w("## Limitations")
    w("")
    w("- Version reconciliation is probabilistic when the target strips "
      "headers and expose_php is off; PROBABLE findings on unknown-version "
      "targets await oracle confirmation.")
    w("- The confirmation oracle may crash a *vulnerable* worker (it "
      "auto-restarts). Patched targets respond gracefully at both steps.")
    w("- Patch-floor findings are CVE-pending fix-set deficits, not "
      "confirmed exploitable paths.")
    w("")
    w("---")
    w(f"*Generated by php_Archangel — authorized-security-testing use. "
      f"Report object: {json.dumps({'target': scan.get('target')})}*")
    return "\n".join(out)
