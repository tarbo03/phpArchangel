"""
Pipeline orchestrator: recon -> reconciliation -> findings -> FP filters.

The SecPipe doctrine in one place: findings are computed from evidence;
the AI never sees the target directly — only structured evidence JSON;
unverified suspicions surface as PROBABLE, never CONFIRMED.
"""
from __future__ import annotations

import json
import time
from importlib import resources
from typing import Optional

from .core.models import (Evidence, Finding, ScanResult, Severity, Verdict)
from .http.client import TargetClient
from .recon import easteregg, entry_probe, components, changelog_delta, jsanalyze
from .recon.reconcile import reconcile_version, apply_fp_filters


def _signature_db() -> dict:
    return json.loads(
        (resources.files("php_archangel.signatures")
         .joinpath("vulnerabilities.json")).read_text(encoding="utf-8"))


def _version_gate(version: Optional[str], branch_fixed: dict) -> Optional[bool]:
    """None = unknown; True = vulnerable-by-version; False = fixed-by-version."""
    if not version:
        return None
    import re
    m = re.match(r"(\d+)\.(\d+)", version)
    if not m:
        return None
    br = f"{m.group(1)}.{m.group(2)}"
    entry = branch_fixed.get(br)
    if not entry or entry.get("fixed_in") is None:
        return True if entry is not None else None   # EOL branch = vulnerable
    from packaging.version import Version, InvalidVersion
    try:
        return Version(version) < Version(entry["fixed_in"])
    except InvalidVersion:
        return None


def run_scan(target_url: str, aggressive: bool = False, js_deep: bool = False,
             changelog_probes: bool = True, verify_mode: str = "safe",
             verbose: bool = True, on_event=None) -> ScanResult:
    """on_event: optional callback(phase_name) — progress UI listens here."""

    result = ScanResult(target=target_url)
    sig_db = _signature_db()

    with TargetClient(target_url, verbose=verbose) as client:
        # ---- Stage 1: recon (all non-destructive) -----------------------
        if verbose:
            print(f"[*] {target_url} — recon sweep")
        ev_entry = entry_probe.probe_entry(client, verbose=verbose)
        if on_event: on_event('entry')
        ev_egg = easteregg.probe_easteregg(client, verbose=verbose)
        if on_event: on_event('easteregg')
        ev_comp, comps = components.probe_components(client, verbose=verbose)
        if on_event: on_event('components')
        ev_js, js_comps = jsanalyze.analyze_javascript(client, deep=js_deep,
                                                       verbose=verbose)
        if on_event: on_event('js')

        all_evidence: list[Evidence] = ev_entry + ev_egg + ev_comp + ev_js
        all_components = comps + js_comps

        for comp in all_components:
            if comp not in result.components:
                result.components.append(comp)

        # SAPI guess from evidence
        for e in ev_entry:
            if e.kind == "sapi_inferred":
                result.sapi_guess = e.detail["sapi"]
                break

        # ---- Stage 2+3: version reconciliation + verdicts --------------
        if on_event: on_event('reconcile')
        version, conf = reconcile_version(all_evidence)
        result.php_version_estimate = version
        result.php_version_confidence = conf
        if verbose:
            print(f"[*] PHP version: ~{version} (confidence {conf:.2f}) "
                  f"[SAPI: {result.sapi_guess or '?'}]")

        # changelog-delta probes (active by default) — need version-unknown
        # or in-window targets; they refine bands and add preconditions
        if changelog_probes and version is None or _in_window(version):
            if verbose and version is None:
                print("[*] version unknown — running delta/precondition probes")
            for e in changelog_delta.probe_error_bands(client, verbose=verbose):
                all_evidence.append(e)
            for e in changelog_delta.probe_upload_progress_dead(client):
                all_evidence.append(e)
                if result.sapi_guess is None:
                    pass
            version, conf = reconcile_version(all_evidence)  # re-fuse
            result.php_version_estimate = version
            result.php_version_confidence = conf
            if on_event: on_event('changelog')

        # ---- findings from the signature DB ------------------------------
        for sig in sig_db.get("vulnerabilities", []):
            gate = _version_gate(version, sig["affected"]["branches"])
            f = Finding(cve_id=sig["cve"], title=sig["title"],
                        description=sig.get("remediation", ""),
                        severity=Severity(sig.get("severity", "MEDIUM")),
                        target_url=target_url,
                        affected_versions=json.dumps(sig["affected"]),
                        remediation=sig.get("remediation"))
            # attach the best evidence supporting THIS CVE's computation
            f.evidence = [e for e in all_evidence
                          if e.kind in ("header_xpoweredby", "easteregg_hash",
                                        "easteregg_credits", "composer_lock",
                                        "behavioral_quirk", "setcookie_phpsessid",
                                        "error_text_versionband")]
            if gate is True:
                # vulnerable by version — but EOL nuance in branch table
                branch = next((k for k, v in sig["affected"]["branches"].items()
                               if version and version.startswith(k)), None)
                note = sig["affected"]["branches"].get(branch, {}).get("note")
                if note:
                    result.notes.append(f"{sig['cve']}: branch note — {note}")
                f.verdict = Verdict.PROBABLE
            elif gate is False:
                f.verdict = Verdict.CLEAN
                f.retraction_reason = f"version {version} >= fixed-in for branch"
            elif gate is None:
                f.verdict = Verdict.PROBABLE    # unknown version: probable, weak
                f.notes = ["version undetermined — verdict pending oracle"]
            result.findings.append(f)

        # ---- patch-floor informational finding ---------------------------
        floor = sig_db.get("patch_floor")
        if floor and version:
            from packaging.version import Version, InvalidVersion
            try:
                if Version(version) < Version(floor["reference_version"]):
                    pf = Finding(cve_id=None,
                                 title="Patch-floor: memory-safety fixes exist above "
                                       f"your version ({floor['reference_version']})",
                                 description="CVE-pending fixes: " +
                                            "; ".join(floor["fixed_in_reference"]),
                                 severity=Severity.LOW,
                                 target_url=target_url)
                    result.findings.append(pf)
            except InvalidVersion:
                pass

        if on_event: on_event('verdicts')
    # ---- FP filters run last -------------------------------------------
    result.findings = apply_fp_filters(result.findings, version)
    result.finished = time.time()
    return result


def _in_window(version: str) -> bool:
    """Delta probes matter for pre-8.5.12 targets; cheap check."""
    try:
        from packaging.version import Version
        return Version(version) < Version("8.5.12")
    except Exception:
        return True
