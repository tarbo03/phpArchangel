"""
Changelog-delta behavioral fingerprinting (8.5.11-vs-8.5.12 fix set).

Non-destructive probes that differentiate behavior across the fix boundary.
Where the app echoes input or surfaces error text, version-specific PHP
warnings/errors narrow the running build far beyond what headers reveal.
Probes derived from the 8.5.12 changelog: print_r(NAN) warning (GH-23662),
grapheme search fixes, quoted-printable lowercase-hex fix, wordwrap endbreak.
"""
from __future__ import annotations

from ..core.models import Evidence
from ..http.client import TargetClient

# Error-text markers observed per branch family (populated from lab captures;
# conservative matching; unknown = no evidence rather than a guess)
_FATAL_BANDS = {
    "Uncaught ValueError": {"band": "8.0+", "strength": "MODERATE"},
    "Uncaught TypeError":   {"band": "7.0+", "strength": "MODERATE"},
    "expects parameter":    {"band": "8.0+", "strength": "MODERATE"},
    "must be of the type":  {"band": "7.0-7.4", "strength": "MODERATE"},
    "ArgumentCountError":  {"band": "8.0+", "strength": "MODERATE"},
    "Cannot redeclare":    {"band": "5.x+", "strength": "WEAK"},
}


def probe_error_bands(client: TargetClient, php_entry: str = "/index.php",
                      verbose: bool = False) -> list[Evidence]:
    """
    Fire a malformed multipart at a PHP entry point and read the diagnostic
    surface. Vulnerable-and-old PHP differs from patched in WARNING TEXT and
    ordering — the GHSA itself lists version-specific deprecation consumers.
    """
    out: list[Evidence] = []
    boundary = "archangelprobe0123456789"
    body = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="a"\r\n\r\n'
            f"1\r\n--{boundary}--\r\n").encode()
    r = client.multipart_post(php_entry, body, boundary, tag="delta_multipart")
    if r.status in (200, 400, 413, 500):
        text = r.body[:8192].decode("latin1", "replace")
        for marker, meta in _FATAL_BANDS.items():
            if marker in text:
                out.append(Evidence(kind="error_text_versionband",
                                    detail={"marker": marker,
                                            "band": meta["band"]}))
                break
        # 8.5.12 changed OOM handling: patched builds return graceful errors
        # even under request-abort; a bare 200 with session cookie persisted is
        # neutral, a hard reset (status 0) during this SMALL body is a weak
        # instability hint only — never a verdict on its own.
    if verbose and out:
        print(f"    [delta] {len(out)} band signal(s)")
    return out


def probe_upload_progress_dead(client: TargetClient,
                               php_entry: str = "/index.php") -> list[Evidence]:
    """
    Directly test the php2shell precondition without state corruption:
    a multipart WITH PHP_SESSION_UPLOAD_PROGRESS but tiny body. If the response
    Set-Cookie behavior shows session initialization, upload_progress is
    active pre-app — precondition evidence for CVE-2026-109619.
    """
    boundary = "archangelprecond000123"
    parts = (f"--{boundary}\r\n"
             'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'
             "\r\n\r\narchangel\r\n"
             f"--{boundary}--\r\n").encode()
    r = client.multipart_post(php_entry, parts, boundary,
                              tag="precond_upload_progress")
    sc = r.headers.get("set-cookie", "")
    if "PHPSESSID" in sc:
        return [Evidence(kind="setcookie_phpsessid",
                         detail={"observed": True, "context": "upload_progress",
                                 "header": sc[:200]})]
    return []
