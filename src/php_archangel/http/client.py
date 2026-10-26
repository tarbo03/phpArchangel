"""
HTTP layer: one client, two duties — transport and evidence capture.

Engineered for worker-affinity (CVE-2026-109619 confirmation):
  - HTTP/1.1 keep-alive pinning: sequential requests on one TCP connection
    frequently land on the same prefork/FPM worker.
  - request tagging: every request/response pair is captured into an
    evidence store keyed by evidence id, so findings reference bodies
    without inflating the in-memory result object.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

import httpx

USER_AGENT = "php-archangel/1.0 (+authorized-testing)"

# Easter-egg / known-static resources are immutable — cache within a scan.
_IMMUTABLE_PREFIXES = ("?=PHP", "?=php")


@dataclass
class CapturedResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed: float
    url: str


class EvidenceStore:
    """Bodies live here; Evidence objects carry body_ref = store key."""

    def __init__(self) -> None:
        self._bodies: dict[str, bytes] = {}
        self._requests: dict[str, dict] = {}

    def put_body(self, body: bytes) -> str:
        key = uuid.uuid4().hex[:12]
        self._bodies[key] = body
        return key

    def get_body(self, key: str) -> Optional[bytes]:
        return self._bodies.get(key)

    def put_request_meta(self, meta: dict) -> str:
        key = uuid.uuid4().hex[:12]
        self._requests[key] = meta
        return key

    def stats(self) -> dict:
        return {"stored_bodies": len(self._bodies),
                "stored_bytes": sum(len(b) for b in self._bodies.values())}


class TargetClient:
    """
    Thin wrapper over httpx.Client with:
      - consistent UA / header hygiene
      - VIEW-CAPTURE: every exchange recorded into EvidenceStore
      - KEEP-ALIVE PINNING: connection pool of 1 pinned stream for affinity
      - timing recorded per request (per-worker jitter fingerprinting input)
    """

    def __init__(self, target_url: str, timeout: float = 20.0,
                 verify_tls: bool = True, verbose: bool = False):
        u = urlsplit(target_url if "://" in target_url else f"https://{target_url}")
        self.base = f"{u.scheme or 'https'}://{u.netloc}"
        self.root_path = u.path or "/"
        self.verbose = verbose
        self.store = EvidenceStore()
        # Pool limits: single connection = worker affinity; pool = parallel scans.
        self._client = httpx.Client(
            base_url=self.base,
            timeout=httpx.Timeout(timeout, connect=10.0),
            verify=verify_tls,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
            follow_redirects=True,
        )
        self._pin: Optional[httpx.Client] = None  # 1-conn affinity client, lazy
        self.request_log: list[dict] = []

    def close(self) -> None:
        self._client.close()
        if self._pin:
            self._pin.close()

    def __enter__(self) -> "TargetClient":
        return self

    def __exit__(self, *a) -> None:
        self.close()

    # ------------------------------------------------------------------ core

    def request(self, method: str, path: str, *, headers: Optional[dict] = None,
                content: Optional[bytes] = None, tag: str = "",
                pinned: bool = False, read_body: bool = True,
                timeout: float | None = None) -> CapturedResponse:
        client = self._pinned_client() if pinned else self._client
        t0 = time.perf_counter()
        req_headers = dict(headers or {})
        try:
            r = client.request(method, path, headers=req_headers,
                              content=content,
                              timeout=timeout if timeout is not None else self._client.timeout)
            body = r.content if read_body else b""
            resp = CapturedResponse(r.status_code,
                                    {k.lower(): v for k, v in r.headers.items()},
                                    body, time.perf_counter() - t0, str(r.url))
        except httpx.HTTPError as e:
            resp = CapturedResponse(0, {}, str(e).encode(), time.perf_counter() - t0, path)

        # capture -> store; return object keeps only refs
        meta = {"method": method, "path": path, "tag": tag,
                "request_id": self.store.put_request_meta(
                    {"method": method, "path": path, "headers": req_headers,
                     "content_len": len(content) if content else 0})}
        resp_entry = {
            "status": resp.status,
            "headers": dict(resp.headers),
            "body_ref": self.store.put_body(resp.body[:512 * 1024]) if resp.body else None,
            "body_len": len(resp.body), "elapsed": round(resp.elapsed, 4),
            "url": resp.url,
        }
        self.request_log.append({**meta, "response": resp_entry})
        return resp

    def get(self, path: str, **kw) -> CapturedResponse:
        return self.request("GET", path, **kw)

    def post(self, path: str, body: bytes, content_type: str, **kw) -> CapturedResponse:
        kw.setdefault("headers", {})["Content-Type"] = content_type
        return self.request("POST", path, content=body, **kw)

    def multipart_post(self, path: str, body: bytes, boundary: str,
                      **kw) -> CapturedResponse:
        return self.post(path, body, f"multipart/form-data; boundary={boundary}", **kw)

    def head(self, path: str) -> CapturedResponse:
        return self.request("HEAD", path, read_body=False)

    # -------------------------------------------------------------- affinity

    def _pinned_client(self) -> httpx.Client:
        """Single keep-alive connection so consecutive requests land on the
        same prefork worker — required for CVE-2026-109619 producer/consumer."""
        if self._pin is None:
            self._pin = httpx.Client(
                base_url=self.base, timeout=httpx.Timeout(30.0, connect=10.0),
                headers={"User-Agent": USER_AGENT},
                limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
                follow_redirects=False,
            )
        return self._pin

    def pinned(self, method: str, path: str, **kw) -> CapturedResponse:
        kw["pinned"] = True
        return self.request(method, path, **kw)

    # ------------------------------------------------------------ fingerprint

    def timing_jitter(self) -> list[float]:
        """Per-worker response timing samples — input for pool-size inference."""
        return [e["response"]["elapsed"] for e in self.request_log
                if e["response"]["status"] > 0]

    def pinned_POST_multipart(self, path: str, body: bytes, boundary: bytes,
                             tag: str = "") -> CapturedResponse:
        """POST over the single pinned keep-alive connection (same-worker pair)."""
        return self.request("POST", path, content=body, tag=tag or "pinned_multipart",
                            headers={"Content-Type":
                                     f"multipart/form-data; boundary={boundary.decode()}"},
                            pinned=True)
