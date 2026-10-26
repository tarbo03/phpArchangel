"""
Easter-egg fingerprinting, done correctly.

Correction baked into design: the logo GUID only responds when expose_php=On;
with it Off the asset is absent. Its real expert value is not "bypassing
expose_php" but NARROW version-banding: each PHP generation shipped different
binary bytes for these assets, so a body-hash match is strong version evidence.
Combined with the credits page (contributor-era dating), this yields bands far
narrower than any header.
"""
from __future__ import annotations

import hashlib
import json
import re
from importlib import resources
from typing import Optional

from ..core.models import Evidence
from ..http.client import TargetClient, CapturedResponse

_GUIDS = {
    "logo_php":  "=PHPE9568F36-D428-11d2-A769-00AA001ACF42",
    "logo_zend": "=PHPE9568F35-D428-11d2-A769-00AA001ACF42",
    "logo_bug":  "=PHPE9568F34-D428-11d2-A769-00AA001ACF42",
    "credits":   "=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000",
}


def _load_corpus() -> dict:
    return json.loads(
        (resources.files("php_archangel.signatures") / "corpus" / "easteregg_hashes.json")
        .read_text(encoding="utf-8"))


def is_image(resp: CapturedResponse) -> bool:
    ct = resp.headers.get("content-type", "")
    return resp.status == 200 and ("image/" in ct or resp.body[:4] in (
        b"GIF8", b"\x89PNG", b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1"))


def probe_easteregg(client: TargetClient, path: str = "/index.php",
                    verbose: bool = False) -> list[Evidence]:
    """Fire all four GUID probes; hash hits against the corpus."""
    corpus = _load_corpus()
    bands: dict[str, list] = corpus["bands"]
    credits_markers: dict[str, str] = corpus["credits_markers"]
    out: list[Evidence] = []

    for name, guid in _GUIDS.items():
        resp = client.get(f"{path}?{guid}", tag=f"easteregg_{name}")
        if resp.status != 200 or not resp.body:
            continue

        if name == "credits":
            # credits page is text — era date via contributor-group markers
            text = resp.body[:20000].decode("latin1", "replace")
            for marker, label in credits_markers.items():
                if marker in text:
                    out.append(Evidence(
                        kind="easteregg_credits",
                        detail={"guid": name, "marker": marker, "era": label}))
                    break
            continue

        if not is_image(resp):
            continue
        h = hashlib.sha256(resp.body).hexdigest()
        match = bands.get(h)
        if match:
            out.append(Evidence(
                kind="easteregg_hash",
                detail={"guid": name, "hash": h[:16], "band": match["version_band"],
                        "label": match["label"], "expose_php": True}))
        else:
            # Unknown-to-corpus asset: still proves expose_php=On (weak band)
            out.append(Evidence(
                kind="easteregg_hash",
                detail={"guid": name, "hash": h[:16], "band": "unknown",
                        "label": "unmatched-hash", "expose_php": True,
                        "note": "run scripts/corpus_build.py to extend corpus"}))

    if verbose:
        print(f"    [easteregg] {len(out)} evidence item(s)")
    return out


def php_tag_from_headers(resp: CapturedResponse) -> Optional[Evidence]:
    """X-Powered-By: PHP/8.4.26 — weak (proxy-strippable/spoofable), still useful fusion input."""
    xp = resp.headers.get("x-powered-by", "")
    m = re.match(r"PHP/(\d+\.\d+\.\d+)", xp, re.I)
    if m:
        return Evidence(kind="header_xpoweredby",
                        detail={"version": m.group(1), "raw": xp})
    return None
