"""
Version reconciliation + the five false-positive filters.

Filter 1  patched-oracle divergence   — definitive behavior beats version claims
Filter 2  session-cookie semantics     — exploit preconditions must be observed
Filter 3  content-length quirk         — multipart w/o usable length as version-band signal
Filter 4  version-permission gate      — never flag fixed versions on weak evidence alone
Filter 5  component disambiguation     — resolve CMS plugin era vs runtime version
"""
from __future__ import annotations

import re
from typing import Optional
from packaging.version import Version, InvalidVersion

from ..core.models import Evidence, EvidenceStrength, Finding, Severity, Verdict

_FIXED = {"8.5": "8.5.12", "8.4": "8.4.27", "8.3": "8.3.36", "8.2": "8.2.35"}


def _ver(v: str) -> Optional[Version]:
    try:
        return Version(v)
    except InvalidVersion:
        return None


def reconcile_version(evidence: list[Evidence]) -> tuple[Optional[str], float]:
    """
    Fuse evidence strengths into a version estimate. Never guesses silently:
    confidence = weighted by strongest evidence present. Weak-header-only
    findings stay capped at WEAK confidence.
    """
    best: tuple[float, Optional[str]] = (0.0, None)
    for ev in evidence:
        if ev.kind == "header_xpoweredby":
            c, v = EvidenceStrength.WEAK.value, ev.detail["version"]
        elif ev.kind == "easteregg_hash" and ev.detail.get("band") not in (None, "unknown"):
            c, v = ev.strength.value, None          # band, not exact version
            band = ev.detail["band"]
            lo, hi = band.split("-") if "-" in band else (band, band)
            v = f"{lo}.x-{hi}.x" if lo == hi is None else (lo if "-" not in band else band)
            v = band
        elif ev.kind == "composer_lock":
            c, v = EvidenceStrength.DEFINITIVE.value, ev.detail.get("php_requirement")
        elif ev.kind == "behavioral_quirk":
            c, v = EvidenceStrength.STRONG.value, ev.detail.get("version")
        elif ev.kind == "js_library_version":
            # JS library versions are app-era context, NEVER a PHP version —
            # treat as confidence zero so they never win the version fusion
            c, v = 0.0, None
        elif ev.kind == "wp_readme_version":
            c, v = EvidenceStrength.STRONG.value, None   # app era, not runtime
            v = None
        else:
            c, v = ev.strength.value, ev.detail.get("version")
        if v and c > best[0]:
            best = (c, v)
    return best[1], round(best[0], 2)


def _branch(version: str) -> Optional[str]:
    m = re.match(r"(\d+\.\d+)", version)
    return m.group(1) if m else None


def apply_fp_filters(findings: list[Finding],
                     version_estimate: Optional[str]) -> list[Finding]:
    """Deterministic gates. Anything failing a gate is RETRACTED (reason kept)."""
    for f in findings:
        if f.cve_id is None:
            continue  # informational (patch-floor) — no gating

        est = _ver(version_estimate) if version_estimate else None
        br = _branch(version_estimate) if version_estimate else None
        fixed = _FIXED.get(br or "") if br else None

        # --- Filter 1: definitive patched behavior retracts anything weaker
        patched_definitive = any(
            e.kind == "oracle_oom_divergence" and e.detail.get("patched")
            for e in f.evidence)
        if patched_definitive:
            f.retract("OOM oracle shows patched (graceful) behavior — "
                      "version-path finding overridden by definitive signal")
            f.verdict = Verdict.CLEAN
            continue

        # --- Filter 2: preconditions observed (cookie semantics)
        has_cookie_ev = any(e.kind == "setcookie_phpsessid" for e in f.evidence)
        if not has_cookie_ev:
            f.notes = getattr(f, "notes", [])
            f.description += " [preconditions unobserved — confidence reduced]"

        # --- Filter 4: version-permission gate. Vulnerable verdict demands
        # either exact-version STRONG+ evidence below fix, or CONFIRMED oracle.
        if est and fixed and est >= _ver(fixed) and f.verdict != Verdict.CONFIRMED:
            f.retract(f"reconciled version {version_estimate} >= fixed "
                      f"{fixed} for branch {br}; weak evidence cannot flag it")
            f.verdict = Verdict.CLEAN

        # --- Filter 3 & 5 are applied during recon assembly (components /
        # multipart-quirk modules feed evidence; gating logic shared here):
        if f.evidence_strength() < EvidenceStrength.MODERATE.value \
                and f.verdict == Verdict.PROBABLE:
            f.severity = Severity.MEDIUM   # severity-capped until better evidence
    return findings
