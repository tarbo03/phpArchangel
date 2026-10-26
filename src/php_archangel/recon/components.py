"""
Embedded-component discovery: find PHP even when the app hides it.

Tiers:
  1. composer.json / composer.lock  — ground-truth platform + component versions
  2. CMS fingerprints                — WordPress / Drupal / Joomla / Magento
  3. Plugin/version artifacts        — readme.txt headers, changelogs, manifests
  4. Exposed vendor trees            — /vendor/ directory listings
Yields Evidence + ScanResult.components entries (requirement #8).
"""
from __future__ import annotations

import json
import re

from ..core.models import Evidence
from ..http.client import TargetClient

# (path, parser_tag) — parser_tag routes response handling
PROBES: list[tuple[str, str]] = [
    ("/composer.json",  "composer_json"),
    ("/composer.lock",  "composer_lock"),
    ("/wp-login.php",   "wp"),
    ("/wp-links-opml.php", "wp_opml"),
    ("/readme.html",    "wp_readme"),
    ("/administrator/manifests/files/joomla.xml", "joomla"),
    ("/misc/drupal.js", "drupal_legacy"),
    ("/core/CHANGELOG.txt", "drupal"),
    ("/includes/bootstrap.inc", "drupal_legacy2"),
    ("/RELEASE_NOTES.txt", "magento"),
    ("/vendor/",        "vendor_listing"),
    ("/.well-known/security.txt", "security_txt"),
]

_WP_VERSION_RE = re.compile(r"wp-emoji|wp-includes|wp-content")
_WP_README_VER = re.compile(r"Version\s+(\d+\.\d+[\.\d]*)")
_JOOMLA_VER = re.compile(r"<version>([\d\.]+)</version>")
_DRUPAL_VER = re.compile(r"Drupal\s+([\d\.]+)", re.I)
_MAGENTO_VER = re.compile(r"([\d]+\.[\d]+\.[\d]+)")


def probe_components(client: TargetClient, verbose: bool = False
                     ) -> tuple[list[Evidence], list[dict]]:
    out: list[Evidence] = []
    comps: list[dict] = []

    for path, tag in PROBES:
        r = client.head(path) if tag != "vendor_listing" else client.get(path)
        if r.status not in (200, 405):
            continue
        if tag in ("composer_json", "composer_lock") and r.status == 200:
            r = client.get(path, tag=tag)
            try:
                data = json.loads(r.body[:2_000_000])
            except (ValueError, json.JSONDecodeError):
                continue
            if tag == "composer_json":
                req = data.get("require", {}).get("php", "")
                if req:
                    out.append(Evidence(kind="composer_lock",
                                        detail={"php_requirement": req,
                                                "source": "composer.json"}))
                for pkg, ver in data.get("require", {}).items():
                    comps.append({"name": pkg, "version": ver,
                                  "source": "composer.json"})
            else:  # composer.lock — component ground truth
                for pkg in data.get("packages", []) + data.get("packages-dev", []):
                    comps.append({"name": pkg.get("name", "?"),
                                  "version": pkg.get("version", "?"),
                                  "source": "composer.lock"})
                plat = data.get("platform", {}).get("php", "")
                if plat:
                    out.append(Evidence(kind="composer_lock",
                                        detail={"php_requirement": plat,
                                                "source": "composer.lock"}))
        elif tag == "wp" and r.status in (200, 405):
            comps.append({"name": "wordpress", "version": "?", "source": "wp-login"})
            out.append(Evidence(kind="cms_detected",
                                detail={"cms": "wordpress"}))
        elif tag == "wp_opml":
            r = client.get(path, tag=tag)
            m = re.search(r"generator=WordPress ([\d\.]+)", r.body[:2000].decode("latin1", "replace"))
            v = m.group(1) if m else "?"
            comps.append({"name": "wordpress", "version": v, "source": "opml"})
            if m:
                out.append(Evidence(kind="wp_readme_version",
                                    detail={"cms": "wordpress", "version": v}))
        elif tag == "wp_readme":
            r = client.get(path, tag=tag)
            text = r.body[:2048].decode("latin1", "replace")
            m = _WP_README_VER.search(text)
            if m:
                comps.append({"name": "wordpress", "version": m.group(1),
                              "source": "readme.html"})
                out.append(Evidence(kind="wp_readme_version",
                                    detail={"cms": "wordpress",
                                            "version": m.group(1)}))
        elif tag == "joomla":
            r = client.get(path, tag=tag)
            m = _JOOMLA_VER.search(r.body[:4096].decode("latin1", "replace"))
            if m:
                comps.append({"name": "joomla", "version": m.group(1),
                              "source": "manifest"})
                out.append(Evidence(kind="cms_detected",
                                    detail={"cms": "joomla",
                                            "version": m.group(1)}))
        elif tag in ("drupal", "drupal_legacy"):
            body = r.body[:8192].decode("latin1", "replace")
            m = _DRUPAL_VER.search(body)
            if m:
                comps.append({"name": "drupal", "version": m.group(1),
                              "source": path})
                out.append(Evidence(kind="cms_detected",
                                    detail={"cms": "drupal",
                                            "version": m.group(1)}))
        elif tag == "vendor_listing":
            if b"Index of" in r.body[:512]:
                out.append(Evidence(kind="vendor_exposed",
                                    detail={"path": "/vendor/",
                                            "note": "directory listing exposes packages"}))

    # WordPress plugin enumeration via any wp-content path seen in root HTML
    root = client.get(client.root_path if client.root_path != "/" else "/")
    for m in re.finditer(rb"/wp-content/plugins/([a-z0-9\-_]+)/",
                         root.body[:200_000]):
        plugin = m.group(1).decode()
        rd = client.get(f"/wp-content/plugins/{plugin}/readme.txt")
        if rd.status == 200:
            txt = rd.body[:2048].decode("latin1", "replace")
            vm = re.search(r"Stable tag:\s*([\w\.\-]+)", txt)
            comps.append({"name": f"wp-plugin:{plugin}",
                          "version": vm.group(1) if vm else "?",
                          "source": "readme.txt"})
    if verbose:
        print(f"    [components] {len(comps)} component(s), "
              f"{len(out)} evidence item(s)")
    return out, comps
