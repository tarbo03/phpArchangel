"""
Core data model — SecPipe doctrine encoded in types.

Every finding carries an evidence chain. A finding that reaches a report has
deterministic evidence behind it: a captured request/response, a replay that
reproduced behavior, or a passing oracle check. Suspicions that fail
verification become RETRACTED with a human-readable reason — never hidden.
"""
from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"      # deterministic oracle passed
    PROBABLE  = "PROBABLE"      # strong evidence, oracle not run (safe mode)
    RETRACTED = "RETRACTED"     # suspected, verification failed — reason kept
    CLEAN     = "CLEAN"         # deterministically not affected


class Severity(str, Enum):
    INFO      = "INFO"
    LOW       = "LOW"
    MEDIUM    = "MEDIUM"
    HIGH      = "HIGH"
    CRITICAL  = "CRITICAL"


class EvidenceStrength(float, Enum):
    WEAK      = 0.25   # single soft signal (e.g. header alone, easily spoofed)
    MODERATE  = 0.55   # version-band narrowing (error text, plugin era)
    STRONG    = 0.80   # easter-egg hash match, deterministic quirk
    DEFINITIVE= 0.97   # oracle behavioral divergence, composer.lock ground truth


@dataclass
class Evidence:
    """One atomic observation with its full provenance."""
    kind: str                          # e.g. "header", "easteregg_hash", "oracle"
    detail: dict[str, Any]             # probe-specific payload
    request: Optional[dict] = None     # captured request  (method, url, headers, body_ref)
    response: Optional[dict] = None    # captured response (status, headers, body_ref, timing)
    timestamp: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    @property
    def strength(self) -> EvidenceStrength:
        return EVIDENCE_STRENGTH_MAP.get(self.kind, EvidenceStrength.WEAK)


# Deterministic strength table — evidence kinds never invented by the AI tier.
EVIDENCE_STRENGTH_MAP: dict[str, EvidenceStrength] = {
    "header_xpoweredby":       EvidenceStrength.WEAK,
    "header_server":           EvidenceStrength.WEAK,
    "setcookie_phpsessid":     EvidenceStrength.MODERATE,
    "error_text_versionband":   EvidenceStrength.MODERATE,
    "easteregg_hash":          EvidenceStrength.STRONG,
    "easteregg_credits":       EvidenceStrength.MODERATE,
    "behavioral_quirk":        EvidenceStrength.STRONG,
    "composer_lock":           EvidenceStrength.DEFINITIVE,
    "wp_readme_version":       EvidenceStrength.STRONG,
    "oracle_oom_divergence":   EvidenceStrength.DEFINITIVE,
    "oracle_worker_affinity":  EvidenceStrength.DEFINITIVE,
    "changelog_delta_probe":   EvidenceStrength.STRONG,
}


@dataclass
class RetryPolicy:
    connect_retries: int = 3
    read_retries: int = 2
    backoff_base: float = 0.4


@dataclass
class Finding:
    """A finding is only as good as its weakest evidence link — by design."""
    cve_id: Optional[str]                 # None for informational findings (patch-floor)
    title: str
    description: str
    evidence: list[Evidence] = field(default_factory=list)
    verdict: Verdict = Verdict.PROBABLE
    severity: Severity = Severity.MEDIUM
    retraction_reason: Optional[str] = None
    remediation: Optional[str] = None
    target_url: str = ""
    affected_versions: Optional[str] = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def promote(self, ev: Evidence, verdict: Verdict = Verdict.CONFIRMED) -> None:
        """Only deterministic evidence promotes; AI tier calls this, evidence decides."""
        if ev.strength >= EvidenceStrength.DEFINITIVE:
            self.verdict = verdict
        self.evidence.append(ev)

    def retract(self, reason: str) -> None:
        self.verdict = Verdict.RETRACTED
        self.retraction_reason = reason

    def evidence_strength(self) -> float:
        return max((e.strength.value for e in self.evidence), default=0.0)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        d["severity"] = self.severity.value
        # Evidence.strength is a @property, not a dataclass field — asdict
        # skips it. Inject it here so downstream consumers (AI triage, the
        # markdown report) can see evidence strength instead of reading 0.
        for ed, eobj in zip(d.get("evidence", []), self.evidence):
            ed["strength"] = eobj.strength.value
        return d


@dataclass
class ScanResult:
    target: str
    started: float = field(default_factory=time.time)
    finished: Optional[float] = None
    php_version_estimate: Optional[str] = None      # reconciled, e.g. "8.4.2x"
    php_version_confidence: float = 0.0
    sapi_guess: Optional[str] = None                # mod_php / fpm / cgi / frankenphp
    components: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary_line(self) -> str:
        n = {v.value: 0 for v in Verdict}
        for f in self.findings:
            n[f.verdict.value] = n.get(f.verdict.value, 0) + 1
        return (f"{self.target}: PHP~{self.php_version_estimate or '?'} "
                f"(conf {self.php_version_confidence:.2f}) "
                f"confirmed={n['CONFIRMED']} probable={n['PROBABLE']} "
                f"retracted={n['RETRACTED']}")

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started": self.started,
            "finished": self.finished,
            "php_version": {
                "estimate": self.php_version_estimate,
                "confidence": self.php_version_confidence,
                "sapi_guess": self.sapi_guess,
            },
            "components": self.components,
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
        }

    def fingerprint_hash(self) -> str:
        """Stable hash of the deterministic evidence set — report reproducibility proof."""
        blob = "|".join(sorted(f"{e.kind}:{e.detail}" .replace(" ", "")
                               for f in self.findings for e in f.evidence))
        return hashlib.sha256(blob.encode()).hexdigest()[:16]
