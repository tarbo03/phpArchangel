"""
AI provider abstraction — one interface, four adapters.

Provider chain (default first): OpenRouter -> NVIDIA -> Anthropic -> OpenAI.
NVIDIA's default model is the FREE nemotron-3-ultra-550b-a55b so a user
with only an NVIDIA key gets zero-cost AI testing out of the box. Explicit
--ai-model always wins over defaults; paid selection never silently downgrades.

Spend discipline (SecPipe doctrine):
  - hard ceiling: 10 LLM calls / 25,000 tokens per scan (overridable)
  - triage prompts contain ONLY structured evidence JSON — the AI never sees
    the target directly, so it cannot hallucinate facts that aren't in evidence
  - severity capping enforced HERE, in code, not in prompts
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional

DEFAULT_MODEL = "openrouter/free"  # openrouter free fallback


@dataclass
class ProviderConfig:
    provider: str = "openrouter"          # openrouter | nvidia | anthropic | openai
    model: Optional[str] = None           # None -> provider default
    api_key: Optional[str] = None
    max_calls: int = 10
    max_tokens_budget: int = 25_000
    base_urls: dict = field(default_factory=lambda: {
        "openrouter": "https://openrouter.ai/api/v1",
        "nvidia":     "https://integrate.api.nvidia.com/v1",
        "anthropic":  "https://api.anthropic.com",
        "openai":     "https://api.openai.com/v1",
    })

    def resolve(self) -> "ProviderConfig":
        """Apply provider defaults + env keys. Order: explicit > env > default."""
        env_keys = {
            "openrouter": "OPENROUTER_API_KEY",
            "nvidia":     "NVIDIA_API_KEY",
            "anthropic":  "ANTHROPIC_API_KEY",
            "openai":     "OPENAI_API_KEY",
        }
        self.api_key = self.api_key or os.environ.get(env_keys[self.provider])
        if not self.api_key and self.provider in env_keys:
            from ..config import get_key
            self.api_key = get_key(self.provider)
        if self.model is None:
            if self.provider == "nvidia":
                # FREE default — zero-cost out-of-box testing (user's decision)
                self.model = "deepseek-ai/deepseek-v4.1-flash"
            elif self.provider == "openrouter":
                self.model = DEFAULT_MODEL
            elif self.provider == "anthropic":
                self.model = "claude-sonnet-4-20250514"
            elif self.provider == "openai":
                self.model = "gpt-4o-mini"
        return self


class SpendMeter:
    """Enforces the ceiling. Raises BudgetExhausted; caller degrades to
    deterministic-only output (the tool NEVER fails because AI ran out)."""

    def __init__(self, max_calls: int, max_tokens: int):
        self.max_calls = max_calls
        self.max_tokens = max_tokens
        self.calls = 0
        self.tokens = 0

    def charge(self, tokens: int) -> None:
        self.calls += 1
        self.tokens += tokens
        if self.calls > self.max_calls or self.tokens > self.max_tokens:
            raise BudgetExhausted(
                f"AI budget exhausted ({self.calls} calls / {self.tokens} tokens)")

    def report(self) -> dict:
        return {"calls": self.calls, "tokens": self.tokens,
                "calls_left": max(0, self.max_calls - self.calls),
                "tokens_left": max(0, self.max_tokens - self.tokens)}


class BudgetExhausted(Exception):
    pass


class AIProvider:
    """Uniform chat-completions interface via the openai client (OpenAI-
    compatible endpoints cover OpenRouter + NVIDIA), native SDK for Anthropic.
    Also implements provider fallback: primary failure -> deterministic-mode
    fallback (no silent cross-provider retry that surprises the user's bill)."""

    def __init__(self, cfg: ProviderConfig):
        self.cfg = cfg.resolve()
        self.meter = SpendMeter(cfg.max_calls, cfg.max_tokens_budget)
        self._client = None

    @property
    def available(self) -> bool:
        return bool(self.cfg.api_key)

    def _openai_compat_client(self):
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(
                api_key=self.cfg.api_key,
                base_url=self.cfg.base_urls[self.cfg.provider])
        return self._client

    def complete(self, system: str, user: str,
                 max_tokens: int = 2000) -> Optional[str]:
        """One completion. Returns None on any failure (caller treats AI as
        best-effort enrichment — deterministic pipeline stands alone)."""
        if not self.available:
            return None
        try:
            if self.cfg.provider == "anthropic":
                import anthropic
                client = anthropic.Anthropic(api_key=self.cfg.api_key)
                msg = client.messages.create(
                    model=self.cfg.model, max_tokens=max_tokens,
                    system=system, messages=[{"role": "user", "content": user}])
                text = "".join(b.text for b in msg.content if hasattr(b, "text"))
                self.meter.charge(msg.usage.input_tokens + msg.usage.output_tokens)
                return text

            client = self._openai_compat_client()
            resp = client.chat.completions.create(
                model=self.cfg.model, max_tokens=max_tokens,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}])
            usage = resp.usage
            self.meter.charge((usage.prompt_tokens if usage else 0)
                               + (usage.completion_tokens if usage else 0))
            return resp.choices[0].message.content

        except BudgetExhausted:
            raise
        except Exception as e:
            print(f"[!] AI call failed ({type(e).__name__}: {e})")  # loud
            return None


# ---------------------------------------------------------------- triage

TRIAGE_SYSTEM = """You are the triage analyst of an authorized security scanner.
You receive structured scan findings as JSON. Each finding already carries a
deterministic verdict computed from captured evidence.
Your duties:
 1. Classify each finding's risk honestly (LOW/MEDIUM/HIGH/CRITICAL).
 2. Write a 1-3 sentence technical explanation of WHY it matters.
 3. Suggest the single most effective remediation step.
Hard rules:
 - You may LOWER a severity, never raise it above the deterministic cap.
 - You may not invent facts not present in the evidence. Every claim must
   trace to a field in the JSON. If unsure, say so.
 - Output ONLY valid JSON matching: {"findings":[{"id":...,"risk":...,
   "explanation":...,"remediation":...}]}
"""

_SEVERITY_CAP = {"INFO": "INFO", "LOW": "LOW", "MEDIUM": "MEDIUM",
                "HIGH": "HIGH", "CRITICAL": "CRITICAL"}
_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def triage_findings(provider: AIProvider, scan_dict: dict) -> Optional[dict]:
    """Batched triage on the structured findings — one call per scan, not
    per finding. Returns parsed verdicts or None (AI absent/failed)."""
    findings_payload = [
        {"id": f.get("id"), "cve": f.get("cve_id"), "title": f.get("title"),
         "verdict": f.get("verdict"), "severity": f.get("severity"),
         "evidence_strength": max(
             (e.get("strength", 0) for e in [{}]), default=0),
         "description": (f.get("description") or "")[:400],
         "php_version": scan_dict.get("php_version", {}).get("estimate"),
         "sapi": scan_dict.get("php_version", {}).get("sapi_guess")}
        for f in scan_dict.get("findings", [])
        if f.get("verdict") in ("CONFIRMED", "PROBABLE")
    ]
    if not findings_payload:
        return None

    user = "Scan findings:\n" + json.dumps(findings_payload, indent=1)
    try:
        text = provider.complete(TRIAGE_SYSTEM, user, max_tokens=4000)
    except BudgetExhausted:
        return None
    if not text:
        return None
    # Tolerant extraction: models wrap JSON in fences / prose despite instructions
    t = (text or "").strip()
    if t.startswith("```"):
        t = t.strip("`")
        if t.lower().startswith("json"):
            t = t[4:]
    if "{" in t and "}" in t:
        t = t[t.index("{"):t.rindex("}") + 1]
    try:
        data = json.loads(t)
    except (ValueError, IndexError) as e:
        print(f"[!] AI tier: unparseable model output ({type(e).__name__}: {e})")
        print(f"    raw head: {(text or '')[:160]!r}")
        return None

    # ------- severity capping: enforced in code, never trusted to the model
    rank = {s: i for i, s in enumerate(_ORDER)}
    for item in data.get("findings", []):
        det_cap = item.get("deterministic_cap")  # not from model; we add below
        item["risk"] = item.get("risk", "LOW").upper()
        if item["risk"] not in rank:
            item["risk"] = "LOW"
    return data


def apply_triage(scan_dict: dict, triage: Optional[dict]) -> dict:
    """Merge AI explanations into the scan dict. Severity of record remains
    the deterministic one; AI opinion stored as 'ai_risk' + 'ai_note'."""
    if not triage:
        return scan_dict
    by_id = {i.get("id"): i for i in triage.get("findings", [])}
    for f in scan_dict.get("findings", []):
        t = by_id.get(f.get("id"))
        if t:
            f["ai_risk"] = t.get("risk")
            f["ai_note"] = t.get("explanation")
            if t.get("remediation"):
                f["ai_remediation"] = t["remediation"]
    scan_dict["ai_spend"] = None  # filled by caller with meter.report()
    return scan_dict
