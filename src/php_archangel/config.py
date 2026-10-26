"""
User key management — 'clone and go' setup.

  php_archangel config            interactive: choose provider, paste key(s)
  php_archangel config --show     display stored config (keys masked)

Keys persist in ~/.config/php_archangel/keys (chmod 600, INI format).
Precedence everywhere: environment variable > config file > unset.
Both paths feed ProviderConfig.resolve() so CI (env) and humans (config)
coexist without surprises.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional

ENV_VARS = {
    "openrouter": "OPENROUTER_API_KEY",
    "nvidia":     "NVIDIA_API_KEY",
    "anthropic":  "ANTHROPIC_API_KEY",
    "openai":     "OPENAI_API_KEY",
}

CFG_DIR = Path.home() / ".config" / "php_archangel"
CFG_FILE = CFG_DIR / "keys"


def _read() -> dict[str, str]:
    out: dict[str, str] = {}
    if not CFG_FILE.exists():
        return out
    for line in CFG_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip().lower()] = v.strip()
    return out


def _write(cfg: dict[str, str]) -> None:
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    lines = ["# php_archangel AI provider keys",
             "# provider = key   (env vars override this file)"]
    lines += [f"{k} = {v}" for k, v in cfg.items() if v]
    CFG_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    CFG_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)   # 600 — user-only


def get_key(provider: str) -> Optional[str]:
    """env var first, then config file."""
    env = os.environ.get(ENV_VARS[provider])
    if env:
        return env
    return _read().get(provider) or None


def interactive_setup() -> None:
    print("php_Archangel — AI provider setup")
    print(f"Keys are stored in {CFG_FILE} (chmod 600).")
    print("Press Enter to keep the current value; leave blank to skip.\n")
    existing = _read()
    new: dict[str, str] = {}
    for prov, env in ENV_VARS.items():
        cur = existing.get(prov, "")
        masked = (cur[:4] + "..." + cur[-4:]) if len(cur) > 8 else (cur or "-")
        v = input(f"{env} [{prov}] (stored: {masked}): ").strip()
        new[prov] = v if v else cur
    _write(new)
    print("\n[+] saved. Providers available:",
          ", ".join(p for p in new if new[p]) or "none (tool runs deterministic)")


def show_masked() -> None:
    cfg = _read()
    for prov in ENV_VARS:
        env = os.environ.get(ENV_VARS[prov])
        stored = cfg.get(prov)
        if env:
            print(f"{prov}: ENV ({env[:4]}...{env[-4:]})")
        elif stored:
            print(f"{prov}: file ({stored[:4]}...{stored[-4:]})")
        else:
            print(f"{prov}: not set")
    print(f"config file: {CFG_FILE}")
