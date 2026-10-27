"""
Plain-CLI presentation layer — ANSI + print only. No Rich dependency.

Design invariants:
  * Color auto-disables when stdout is not a TTY or NO_COLOR/ARCHANGEL_NO_COLOR
    is set — so piping to a file or running under a programmatic caller is safe.
  * The banner uses ANSI Shadow ASCII art, centered and colorized.
"""
from __future__ import annotations

import os
import re
import shutil
import sys


# ============================================================ colour system

class Style:
    """ANSI constants. Empty strings when colour is off so call sites can
    interpolate unconditionally: f"{S.CYAN}{text}{S.RESET}" is a no-op
    when disabled."""
    _on: bool = (
        sys.stdout.isatty()
        and not os.getenv("NO_COLOR")
        and not os.getenv("ARCHANGEL_NO_COLOR")
    )

    CYAN    = "\033[96m" if _on else ""
    GREEN   = "\033[92m" if _on else ""
    YELLOW  = "\033[93m" if _on else ""
    RED     = "\033[91m" if _on else ""
    MAGENTA = "\033[95m" if _on else ""
    BORDER  = "\033[36m" if _on else ""
    MUTED   = "\033[90m" if _on else ""
    WHITE   = "\033[97m" if _on else ""
    BOLD    = "\033[1m"  if _on else ""
    DIM     = "\033[2m"  if _on else ""
    RESET   = "\033[0m"  if _on else ""


S = Style

_VERDICT_STYLE = {
    "CONFIRMED": S.RED + S.BOLD,
    "PROBABLE":  S.YELLOW + S.BOLD,
    "RETRACTED": S.MUTED,
    "CLEAN":     S.GREEN + S.BOLD,
}


# ============================================================ geometry

_ANSI_RE = re.compile("\x1b\\[[0-9;]*m")


def _visible_len(s: str) -> int:
    """Character width of an ANSI-styled string (escape sequences excluded)."""
    return len(_ANSI_RE.sub("", s))


def _term_width() -> int:
    """Live terminal width with a wide, stable fallback for non-TTY contexts."""
    try:
        return shutil.get_terminal_size(fallback=(100, 24)).columns
    except OSError:
        return 100


def _blank(inner: int) -> str:
    return "\u2551" + " " * inner + "\u2551"


def _center(text: str, inner: int) -> str:
    """Interior of exactly `inner` chars, text centred (odd remainder right)."""
    pad = inner - len(text)
    if pad < 0:
        text = text[:inner]
        pad = 0
    left = pad // 2
    return "\u2551" + " " * left + text + " " * (pad - left) + "\u2551"


# ============================================================ banner

def _build_banner(width: int | None = None) -> str:
    """GANDOKI-style ASCII block banner (left-aligned)."""
    if width is None:
        width = _term_width()

    _ART = [
        "██████╗ ██╗  ██╗██████╗       █████╗ ██████╗  ██████╗██╗  ██╗ █████╗ ███╗   ██╗ ██████╗ ███████╗██╗     ",
        "██╔══██╗██║  ██║██╔══██╗     ██╔══██╗██╔══██╗██╔════╝██║  ██║██╔══██╗████╗  ██║██╔════╝ ██╔════╝██║     ",
        "██████╔╝███████║██████╔╝     ███████║██████╔╝██║     ███████║███████║██╔██╗ ██║██║  ███╗█████╗  ██║     ",
        "██╔═══╝ ██╔══██║██╔═══╝      ██╔══██║██╔══██╗██║     ██╔══██║██╔══██║██║╚██╗██║██║   ██║██╔══╝  ██║     ",
        "██║     ██║  ██║██║          ██║  ██║██║  ██║╚██████╗██║  ██║██║  ██║██║ ╚████║╚██████╔╝███████╗███████╗",
        "╚═╝     ╚═╝  ╚═╝╚═╝          ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝"
    ]
    
    art_width = max(len(line) for line in _ART)

    if width < art_width:
        # Fallback for narrow terminals
        return f"\n{S.CYAN}{S.BOLD}PHP-ARCHANGEL{S.RESET}\n{S.MUTED}PHP vulnerability discovery · CVE-2026-109618/109619{S.RESET}\n"

    lines = []
    for line in _ART:
        lines.append(f"{S.CYAN}{S.BOLD}{line}{S.RESET}")

    rule = f"{S.CYAN}{'─' * art_width}{S.RESET}"

    t1 = "PHP vulnerability discovery · CVE-2026-109618/109619"
    t2 = f"v1.0.0  ·  Author: Godwin Tarbo  ·  github.com/tarbo03"

    out = "\n".join(lines)
    out += "\n\n" + rule + "\n"
    out += f"    {S.MUTED}{t1}{S.RESET}\n"
    out += f"    {S.CYAN}{t2}{S.RESET}\n"
    out += rule
    return out


def _banner_should_print() -> bool:
    """Suppress banner in machine-output contexts (piped, redirected, quiet)."""
    if not sys.stdout.isatty():
        return False
    if os.getenv("NO_COLOR") or os.getenv("ARCHANGEL_NO_BANNER"):
        return False
    return True


def print_banner() -> None:
    if not _banner_should_print():
        return
    print(_build_banner())
    print()


# ============================================================ panels

def _panel(title: str, lines: list[str], *, width: int | None = None) -> str:
    """Double-bordered panel with title embedded in the top border."""
    if width is None:
        width = _term_width()
    inner = width - 2

    if title:
        vlen = _visible_len(title)
        label = f" {title} "
        side = max(1, (inner - vlen - 2) // 2)
        right = inner - side - vlen - 2
        if right < 1:
            right = 1
        top = "\u2554" + "\u2550" * side + label + "\u2550" * right + "\u2557"
    else:
        top = "\u2554" + "\u2550" * inner + "\u2557"

    rows = [top]
    for ln in lines:
        vl = _visible_len(ln)
        if vl > inner - 2:
            ln = _ANSI_RE.sub("", ln)[: inner - 2]
            vl = len(ln)
        pad = inner - 2 - vl
        rows.append("\u2551 " + ln + " " * pad + " \u2551")
    rows.append("\u255a" + "\u2550" * inner + "\u255d")

    return "\n".join(rows)


def print_target_panel(
    target: str,
    sapi: str | None,
    version: str | None,
    confidence: float,
) -> None:
    lines = [
        f"    {S.CYAN}{S.BOLD}Target{S.RESET}  {target}",
        f"      {S.CYAN}{S.BOLD}SAPI{S.RESET}  {sapi or 'unknown'}",
        f"       {S.CYAN}{S.BOLD}PHP{S.RESET}  {version or '?'}",
        f"{S.CYAN}{S.BOLD}Confidence{S.RESET}  {confidence:.2f}",
    ]
    title = f"{S.CYAN}{S.BOLD}\u25c8 TARGET{S.RESET}"
    print(_panel(title, lines))


def gate(title: str, detail: str) -> None:
    label = f"{S.YELLOW}{S.BOLD}\u25c6 {title}{S.RESET}"
    print()
    print(_panel(label, [detail], width=min(_term_width(), 100)))


def rce_proof(proof: str, path: str) -> None:
    label = f"{S.MAGENTA}{S.BOLD}\u25c8 RCE PROVEN \u25c8{S.RESET}"
    print()
    print(
        _panel(
            label,
            ["", proof, f"{S.MUTED}{path}{S.RESET}"],
            width=min(_term_width(), 100),
        )
    )


# ============================================================ phase rules

def phase(title: str) -> None:
    W = _term_width()
    label = f" {title} "
    side = max(0, (W - len(label)) // 2)
    left = "\u2500" * side
    right = "\u2500" * (W - side - len(label))
    print()
    print(f"{S.BORDER}{left}{S.CYAN}{S.BOLD}{label}{S.RESET}{S.BORDER}{right}{S.RESET}")
    print()


# ============================================================ findings table

def finding_row(f: dict, width: int | None = None) -> str:
    if width is None:
        width = _term_width()
    v = f.get("verdict", "?")
    v_style = _VERDICT_STYLE.get(v, S.MUTED)
    sev = f.get("severity", "?")
    sev_style = (
        S.RED + S.BOLD if sev == "CRITICAL"
        else S.YELLOW + S.BOLD if sev == "HIGH"
        else S.MUTED
    )
    cve = f.get("cve_id") or "info"
    fixed = 2 + 10 + 9 + 2 + len(cve) + 2
    title_max = max(20, width - fixed - 1)
    title = (f.get("title") or "")[:title_max]
    return (
        f"  {v_style}{v:<10}{S.RESET}"
        f"{sev_style}{sev:<9}{S.RESET}"
        f"{S.CYAN}::{cve}{S.RESET}  "
        f"{title}"
    )


def findings_table(findings: list[dict], title: str = "FINDINGS") -> None:
    if not findings:
        print(f"  {S.MUTED}no findings{S.RESET}")
        return
    print(
        f"  {S.BORDER}\u256d\u2500{S.RESET} {S.BOLD}VERDICT{S.RESET}   "
        f"{S.BORDER}\u2502{S.RESET} {S.BOLD}SEVERITY{S.RESET}  "
        f"{S.BORDER}\u2502{S.RESET} {S.BOLD}FINDING{S.RESET}"
    )
    width = _term_width()
    for f in findings:
        print(finding_row(f, width))

    counts: dict[str, int] = {}
    for f in findings:
        counts[f.get("verdict", "?")] = counts.get(f.get("verdict", "?"), 0) + 1
    parts = []
    for k in ("CONFIRMED", "PROBABLE", "RETRACTED", "CLEAN"):
        if counts.get(k):
            style = _VERDICT_STYLE.get(k, S.MUTED)
            parts.append(f"{style}{k}:{counts[k]}{S.RESET}")
    if parts:
        print("  " + "  ".join(parts))


# ============================================================ status lines

def intel_line(key: str, value: str) -> None:
    print(f"  {S.YELLOW}{S.BOLD}\u26a1 INTEL{S.RESET} {S.MUTED}{key}{S.RESET} {value}")


def ok(msg: str) -> None:
    print(f"  {S.GREEN}{S.BOLD}\u2713{S.RESET} {msg}")


def warn(msg: str) -> None:
    print(f"  {S.YELLOW}\u26a0{S.RESET} {msg}")


def error(msg: str) -> None:
    print(f"  {S.RED}{S.BOLD}\u2717{S.RESET} {msg}")


def info(msg: str) -> None:
    print(f"  {S.CYAN}\u2192{S.RESET} {msg}")
