"""
Entry probe: first-contact recon. Establishes reachability, SAPI guess,
session-cookie semantics (exploit preconditions), and header version signals.
Everything evidence-captured; nothing destructive.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..core.models import Evidence
from ..http.client import TargetClient


def probe_entry(client: TargetClient, verbose: bool = False) -> list[Evidence]:
    out: list[Evidence] = []

    root = client.root_path if client.root_path != "" else "/"
    r = client.get(root, tag="entry_root")
    if r.status == 0:
        return out  # unreachable; pipeline handles this

    # --- headers -----------------------------------------------------
    xp = r.headers.get("x-powered-by", "")
    m = re.match(r"PHP/(\d+\.\d+\.\d+)", xp, re.I)
    if m:
        out.append(Evidence(kind="header_xpoweredby",
                            detail={"version": m.group(1), "raw": xp}))
    srv = r.headers.get("server", "")
    if srv:
        out.append(Evidence(kind="header_server", detail={"server": srv}))

    # --- SAPI inference ----------------------------------------------
    sapi = None
    if srv.startswith("Apache"):
        sapi = "mod_php"          # X-Powered-By via Apache usually = mod_php
    elif srv.startswith("nginx"):
        sapi = "fpm"              # nginx serves PHP through FPM/LSAPI
    elif srv.startswith("Caddy"):
        sapi = "frankenphp"
    elif "LiteSpeed" in srv:
        sapi = "litespeed"
    if sapi:
        out.append(Evidence(kind="sapi_inferred",
                            detail={"sapi": sapi, "server": srv}))

    # --- session semantics (exploit preconditions, Filter 2 feed) ----
    if "phpsessid" in {k.lower() for k in r.headers}:
        out.append(Evidence(kind="setcookie_phpsessid",
                            detail={"observed": True,
                                    "header": r.headers.get("set-cookie", "")}))
    # PHP SESSION use was exercised even on a plain GET if auto_start; if the
    # response sets a cookie with path=/ and HttpOnly we treat as compliant.
    elif "set-cookie" in r.headers:
        sc = r.headers.get("set-cookie", "")
        if "PHPSESSID" in sc:
            out.append(Evidence(kind="setcookie_phpsessid",
                                detail={"observed": True, "header": sc}))

    # --- try to find a .php entry (extension probing, HEAD-first) ------
    for cand in ("/index.php",):
        h = client.head(cand, )
        if h.status in (200, 405):  # 405: HEAD not allowed but exists
            out.append(Evidence(kind="php_entrypoint",
                                detail={"path": cand, "status": h.status}))

    # --- error-page version band (404 text often leaks framework/PHP era)
    r404 = client.get("/php_archangel-nonexist-" + "x" * 8, tag="probe_404")
    if r404.status in (404, 500):
        text = r404.body[:4096].decode("latin1", "replace")
        for marker, band in (("Fatal error", "php-errorpage"),
                            ("WordPress", "wordpress-errorpage"),
                            ("Drupal", "drupal-errorpage"),
                            ("Warning: ", "php-warningpage")):
            if marker in text:
                out.append(Evidence(kind="error_text_versionband",
                                    detail={"marker": marker, "band": band}))
                break

    if verbose:
        print(f"    [entry] {len(out)} evidence item(s)")
    return out


def normalize_target(url: str) -> tuple[str, str]:
    """Return (scheme://netloc, entry_path). Defaults https + /."""
    u = urlsplit(url if "://" in url else f"https://{url}")
    scheme = u.scheme or "https"
    return f"{scheme}://{u.netloc}", u.path or "/"
