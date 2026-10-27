"""
SecPipe-style Markdown report generator.

Report doctrine:
  - every finding shows its evidence chain (kind, strength, detail)
  - retracted suspicions get their own section WITH reasons — never hidden
  - deterministic severity is the severity of record; AI opinion appears
    distinctly labeled (ai_risk/ai_note) — never merged into fact
  - methodology + limitations sections keep the output defensible in front
    of clients and auditors

Aesthetic:
  - Uses inline HTML spans for neon cybersecurity colors (VS Code / Obsidian)
  - Uses GFM alerts (> [!WARNING]) for structural visual hierarchy
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# --- Color Palette (Neon Cyberpunk) ---
C_RED    = "#FF6B78"
C_YELLOW = "#FFD166"
C_GREEN  = "#21F3A2"
C_CYAN   = "#13D9FF"
C_MUTED  = "#8FAFC6"
C_PURPLE = "#FF4FD8"

def _cv(v: str) -> str:
    """Color a verdict."""
    if v == "CONFIRMED": return f'<span style="color:{C_RED};font-weight:bold;">{v}</span>'
    if v == "PROBABLE":  return f'<span style="color:{C_YELLOW};font-weight:bold;">{v}</span>'
    if v == "CLEAN":     return f'<span style="color:{C_GREEN};font-weight:bold;">{v}</span>'
    if v == "RETRACTED": return f'<span style="color:{C_MUTED};">{v}</span>'
    return v

def _cs(s: str) -> str:
    """Color a severity."""
    if s == "CRITICAL": return f'<span style="color:{C_RED};font-weight:bold;">{s}</span>'
    if s == "HIGH":     return f'<span style="color:{C_RED};">{s}</span>'
    if s == "MEDIUM":   return f'<span style="color:{C_YELLOW};">{s}</span>'
    if s == "LOW":      return f'<span style="color:{C_MUTED};">{s}</span>'
    return s

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
    s = table.get(e.get("kind"), "?")
    if s == "definitive": return f'<span style="color:{C_PURPLE};font-weight:bold;">{s}</span>'
    if s == "strong":     return f'<span style="color:{C_CYAN};">{s}</span>'
    return s

def _ts(x: Optional[float]) -> str:
    if not x:
        return "?"
    return datetime.fromtimestamp(x, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")

def build_markdown_report(scan: dict, ai_narrative: bool = True) -> str:
    """scan: dict from ScanResult.to_dict() (already AI-triaged or not)."""
    pv = scan.get("php_version", {})
    out: list[str] = []
    w = out.append

    # ---------------- Header --------------------------------------------
    w("# 🛡️ php_Archangel Scan Report")
    w("")
    w(f"**Target:** `{scan.get('target')}`  ")
    w(f"**Scanned:** {_ts(scan.get('started'))} — finished {_ts(scan.get('finished'))}  ")
    w(f"**PHP version:** ~{pv.get('estimate') or 'unknown'} "
      f"(confidence {pv.get('confidence', 0):.2f}) — SAPI: {pv.get('sapi_guess') or 'unknown'}  ")
    w(f"**Evidence fingerprint:** `{scan.get('fingerprint', '')}`")
    w("")
    w("---")
    w("")

    # ---------------- Executive Summary ---------------------------------
    findings = scan.get("findings", [])
    confirmed = [f for f in findings if f.get("verdict") == "CONFIRMED"]
    probable  = [f for f in findings if f.get("verdict") == "PROBABLE"]
    retracted = [f for f in findings if f.get("verdict") == "RETRACTED"]
    clean    = [f for f in findings if f.get("verdict") == "CLEAN"]
    
    w("## 🎯 Executive Summary")
    w("")
    if confirmed:
        w(f"> [!CAUTION]")
        w(f"> **{len(confirmed)} CONFIRMED finding(s)** — verified by deterministic " 
          "oracle against the live target. Immediate remediation recommended.")
    elif probable:
        w(f"> [!WARNING]")
        w(f"> **{len(probable)} PROBABLE finding(s)** — strong evidence, confirmation " 
          "oracle not run (safe mode). Run `archangel scan --auto-confirm` to " 
          "convert to CONFIRMED (a vulnerable worker may crash and auto-restart).")
    else:
        w("> [!NOTE]")
        w("> No vulnerable-path findings. Patch-floor posture is reported below "
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
        w(f"| {idx} | `{cve}` | {_cv(f.get('verdict'))} | {_cs(f.get('severity'))} |")
        idx += 1
    w("")

    # ---------------- Findings Detail ------------------------------------
    for i, f in enumerate(sorted([*confirmed, *probable], key=lambda x:
            _SEV_ORDER.index(x.get("severity", "LOW"))
            if x.get("severity") in _SEV_ORDER else 4), 1):
        
        icon = "🚨" if f.get("verdict") == "CONFIRMED" else "⚠️"
        w(f"### {icon} Finding {i}: {f.get('cve_id') or 'Informational'} — {f.get('title', '')}")
        w("")
        w(f"**Verdict:** {_cv(f.get('verdict'))} &nbsp;&nbsp; **Severity:** {_cs(f.get('severity'))}")
        w("")
        
        if f.get("verdict") == "CONFIRMED":
            w("> [!CAUTION]")
            w("> **Deterministically confirmed:** the verification oracle reproduced " 
              "the vulnerable behavior against the live target.")
            w("")
            
        desc = f.get("description") or ""
        if desc:
            w(desc)
            w("")
        if f.get("ai_note"):
            w(f"> **🤖 AI Triage ({f.get('ai_risk') or 'n/a'}):** {f['ai_note']}")
            w("")
        rem = f.get("remediation") or f.get("ai_remediation")
        if rem:
            w(f"**🔧 Remediation:** {rem}")
            w("")
            
        w("**🔍 Evidence chain:**")
        w("")
        w("| Kind | Strength | Key detail |")
        w("|------|----------|------------|")
        for e in f.get("evidence", []):
            d = e.get("detail", {})
            key = ", ".join(f"{k}={str(v)[:60]}" for k, v in list(d.items())[:3])
            w(f"| `{e.get('kind')}` | {_ev_strength(e)} | {key} |")
        w("")

    # ---------------- Retraction Log -------------------------------------
    if retracted:
        w("## 🔕 Retracted Suspicions")
        w("")
        w("Suspected findings the verification pipeline could not prove. "
          "Kept visible for auditability — an honest tool retracts loudly.")
        w("")
        for f in retracted:
            w(f"- **{f.get('cve_id') or 'info'}**: {f.get('retraction_reason')}")
        w("")

    if clean:
        w("## ✅ Clean Checks")
        w("")
        for f in clean:
            w(f"- `{f.get('cve_id')}` — **{_cv('CLEAN')}** ({f.get('retraction_reason') or 'version above fix'})")
        w("")

    # ---------------- Components -----------------------------------------
    comps = scan.get("components", [])
    if comps:
        w("## 🧩 Detected Components")
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
        w("*Embedded PHP components: resolve the actual runtime for each — a CMS does not determine the PHP version beneath it.*")
        w("")

    # ---------------- Notes ----------------------------------------------
    notes = scan.get("notes", [])
    if notes:
        w("## 📝 Operational Notes")
        w("")
        for n in notes:
            w(f"- {n}")
        w("")

    # ---------------- Methodology ----------------------------------------
    w("## 🔬 Methodology")
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
        w(f"- **AI spend:** {spend.get('calls')} calls / {spend.get('tokens')} tokens.")
    w("")
    
    w("## ⚠️ Limitations")
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
    w(f"*Generated by [php_Archangel](https://github.com/tarbo03/php_Archangel) — authorized-security-testing use. Report object: {json.dumps({'target': scan.get('target')})}*")
    return "\n".join(out)
