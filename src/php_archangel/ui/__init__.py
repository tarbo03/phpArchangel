"""phpArchangel Rich hybrid UI — the fourth face on the php_Archangel core."""
from .dashboard import ArchangelDashboard, ScanResult, Finding, archangel_scan

__all__ = ["ArchangelDashboard", "ScanResult", "Finding", "archangel_scan"]


def run_dashboard(target_url: str | None = None, splash: bool = False) -> None:
    """Entry from `php_archangel ui [url] [--splash]`."""
    ui = ArchangelDashboard()
    if target_url:
        print(f"Target armed: {target_url} (select [1] then Enter to accept it)")
    ui.run(splash=splash)
