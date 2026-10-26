"""
JS asset analysis tier (requirement #7) — pure HTTP first; the optional
Playwright deep pass slots in later behind deep=True.

Extracts from every <script> asset:
  - AJAX/form endpoints that hit PHP directly (admin-ajax.php, api paths)
  - wp-content plugin/theme paths -> component enumeration without brute force
  - JS library versions (jQuery etc.) -> app-era constraint on PHP era
  - sourcemap references -> build paths / internal structure leaks
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from ..core.models import Evidence
from ..http.client import TargetClient

_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_JQUERY_VER = re.compile(r"jQuery v?(\d+\.\d+\.\d+)")
_WPCONTENT  = re.compile(r"/(wp-content/(?:plugins|themes)/([a-z0-9\-_]+))")
_AJAX_EP    = re.compile(r'["\'](/[A-Za-z0-9_/\.\-]*(?:admin-ajax\.php|api/[a-z]+|ajax\.php)[^"\']*)["\']')
_SOURCEMAP  = re.compile(r'//# sourceMappingURL=([^\s]+)')


def _absolute(client: TargetClient, src: str) -> str:
    if src.startswith("//"):
        return "https:" + src
    if src.startswith("/"):
        return src
    if src.startswith("http"):
        return src
    return urljoin(client.root_path or "/", src)


def analyze_javascript(client: TargetClient, deep: bool = False,
                       verbose: bool = False) -> tuple[list[Evidence], list[dict]]:
    out: list[Evidence] = []
    comps: list[dict] = []

    root = client.get(client.root_path if client.root_path != "/" else "/",
                      tag="js_root")
    html = root.body[:500_000].decode("latin1", "replace")
    srcs = list(dict.fromkeys(_SCRIPT_SRC.findall(html)))[:24]  # cap for OPSEC

    endpoints: set[str] = set()
    for src in srcs:
        path = _absolute(client, src)
        r = client.get(path, tag=f"js_asset")
        if r.status != 200:
            continue
        text = r.body[:800_000].decode("latin1", "replace")

        m = _JQUERY_VER.search(text)
        if m:
            comps.append({"name": "jquery", "version": m.group(1),
                          "source": "js-comment"})
            out.append(Evidence(kind="js_library_version",
                                detail={"library": "jquery",
                                        "version": m.group(1)}))
        for pm in _WPCONTENT.finditer(text):
            comps.append({"name": f"wp:{pm.group(2)}", "version": "?",
                          "source": "js-bundle"})
        for am in _AJAX_EP.finditer(text):
            ep = am.group(1)
            if not any(x in ep for x in ("googletagmanager", "fontawesome")):
                endpoints.add(ep.split("?")[0])
        for sm in _SOURCEMAP.finditer(text):
            out.append(Evidence(kind="js_sourcemap_ref",
                                detail={"sourcemap": sm.group(1)[:120],
                                        "note": "may disclose build structure"}))

    # PHP-RPC endpoint confirmation: HEAD the discovered endpoints (no state change)
    for ep in sorted(endpoints)[:12]:
        h = client.head(ep)
        if h.status in (200, 405):
            out.append(Evidence(kind="php_rpc_endpoint",
                                detail={"endpoint": ep, "status": h.status}))

    if verbose:
        print(f"    [js] {len(srcs)} assets, {len(endpoints)} endpoints, "
              f"{len(comps)} component(s)")
    return out, comps
