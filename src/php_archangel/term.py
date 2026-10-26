"""
php_Archangel terminal chrome — the expert CLI face.

Rich-powered: banner, target panel, phase headers, findings table,
verdict box, proof box. Colors follow a strict semantic system:
cyan=brand, green=confirmed/clean, yellow=probable/intel, red=error/vuln,
magenta=RCE proof. No GUI. One console, one truth source.
"""
from __future__ import annotations

BANNER = r"""
   ██████╗ ██╗  ██╗██████╗  █████╗ ███╗   ██╗ ██████╗ ███╗   ██╗ █████╗ ██╗
  ██╔═══██╗██║  ██║██╔══██╗██╔══██╗████╗  ██║██╔═══██╗████╗  ██║██╔══██╗██║
  ██║   ██║███████║██████╔╝███████║██╔██╗ ██║██║   ██║██╔██╗ ██║███████║██║
  ██║   ██║██╔══██║██╔══██╗██╔══██║██║╚██╗██║██║   ██║██║╚██╗██║██╔══██║██║
  ╚██████╔╝██║  ██║██║  ██║██║  ██║██║ ╚████║╚██████╔╝██║ ╚████║██║  ██║██║
   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝
"""

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.rule import Rule

console = Console()

CYAN = "#13D9FF"; GREEN = "#21F3A2"; YELLOW = "#FFD166"
RED = "#FF6B78"; MUTED = "#8FAFC6"; MAGENTA = "#FF4FD8"
BORDER = "#0876A8"

_VERDICT_STYLE = {
    "CONFIRMED": f"bold {RED}", "PROBABLE": f"bold {YELLOW}",
    "RETRACTED": MUTED, "CLEAN": f"bold {GREEN}",
}


def print_banner() -> None:
    console.print(Text.from_markup(BANNER))


def print_target_panel(target: str, sapi: str | None,
                       version: str | None, confidence: float) -> None:
    info = Table.grid(padding=(0, 2))
    info.add_column(style=f"bold {CYAN}", justify="right")
    info.add_column(style="white")
    info.add_row("Target", f"[bold white]{target}[/]")
    info.add_row("SAPI", sapi or "[muted]unknown[/]")
    v = version or "?"
    info.add_row("PHP", f"{v}")
    info.add_row("Confidence", f"{confidence:.2f}")
    console.print(Panel(info, title="[bold cyan]◈ TARGET[/]",
                        border_style=BORDER, box=box.DOUBLE, padding=(0, 1)))


def phase(title: str) -> None:
    console.print()
    console.print(Rule(f"[bold cyan]{title}[/]", style=BORDER))
    console.print()


def finding_row(f: dict) -> Text:
    v = f.get("verdict", "?")
    style = _VERDICT_STYLE.get(v, MUTED)
    sev = f.get("severity", "?")
    sev_style = f"bold {RED}" if sev == "CRITICAL" else (
        f"bold {YELLOW}" if sev == "HIGH" else MUTED)
    t = Text()
    t.append(f"  {v:<10}", style=style)
    t.append(f"{sev:<9}", style=sev_style)
    t.append(f"::{f.get('cve_id') or 'info'}", style=f"{CYAN}")
    t.append(f"  {f.get('title', '')[:58]}", style="white")
    return t


def findings_table(findings: list[dict], title: str = "FINDINGS") -> None:
    if not findings:
        console.print(f"  [muted]no findings[/]")
        return
    console.print(f"  [bold {CYAN}]╭─[/] [bold]VERDICT[/]   "
                   f"[bold {CYAN}]│[/] [bold]SEVERITY[/]  [bold {CYAN}]│[/] [bold]FINDING[/]")
    for f in findings:
        console.print(finding_row(f))
    # summary line
    counts = {}
    for f in findings:
        counts[f.get("verdict")] = counts.get(f.get("verdict"), 0) + 1
    s = "  "
    for k in ("CONFIRMED", "PROBABLE", "RETRACTED", "CLEAN"):
        if counts.get(k):
            s += f"[{_VERDICT_STYLE[k]}]{k}:{counts[k]}[/]  "
    console.print(s)


def intel_line(key: str, value: str) -> None:
    console.print(f"  [bold {YELLOW}]⚡ INTEL[/] [muted]{key}[/] "
                  f"[bold white]{value}[/]")


def gate(title: str, detail: str) -> None:
    console.print()
    console.print(Panel(
        f"[bold white]{detail}[/]",
        title=f"[bold {YELLOW}]◆ {title}[/]",
        border_style=YELLOW, box=box.SINGLE, padding=(0, 1)))


def rce_proof(proof: str, path: str) -> None:
    console.print()
    console.print(Panel(
        f"[bold {MAGENTA}]◈ RCE PROVEN ◈[/]\n\n"
        f"[bold white]{proof}[/]\n"
        f"[muted]{path}[/]",
        border_style=MAGENTA, box=box.DOUBLE, padding=(1, 2)))


def error(msg: str) -> None:
    console.print(f"  [bold {RED}]✗[/] {msg}")


def ok(msg: str) -> None:
    console.print(f"  [bold {GREEN}]✓[/] {msg}")


def info(msg: str) -> None:
    console.print(f"  [bold {CYAN}]→[/] {msg}")
