"""Phase-based CLI progress bar for archangel.

Design invariants:
  * Live spinner thread (80ms tick) so even sub-second scans visibly animate.
  * Per-phase minimum display time (150ms) so instantaneous phases are
    perceivable — real targets naturally exceed this, fast localhost scans
    are paced so the operator sees progress.
  * Single-line in-place redraw via \\r + \\x1b[K. A threading.Lock serializes
    writes between the spinner thread and phase-advance ticks.
  * Every method is a no-op when disabled (non-TTY, NO_COLOR, env override).
"""
from __future__ import annotations

import os
import sys
import threading
import time

from .term import S


_BAR_WIDTH          = 22
_LABEL_WIDTH        = 7
_PHASE_WIDTH        = 20
_SPINNER_INTERVAL   = 0.08   # 80ms per braille frame — smooth, low CPU
_MIN_PHASE_DURATION = 0.15   # 150ms per phase minimum — perceptible


class ProgressBar:
    """Live single-line phase bar. ``enabled`` auto-detects on construction."""

    FILLED = "\u25b0"    # ▰
    EMPTY  = "\u25b1"    # ▱
    OK     = "\u2713"    # ✓
    FAIL   = "\u2717"    # ✗
    SPINNER_FRAMES = [
        "\u280b", "\u2819", "\u2839", "\u2838", "\u283c",
        "\u2834", "\u2826", "\u2827", "\u2807", "\u280f",
    ]

    def __init__(self, phases: list[str], label: str = "WORK",
                 enabled: bool | None = None):
        self.phases = list(phases)
        self.total  = max(1, len(self.phases))
        self.current = 0
        self.label   = label
        self.last_phase: str | None = None
        self.current_phase: str = self.phases[0] if self.phases else "working"
        self.enabled = (
            enabled if enabled is not None
            else (
                sys.stdout.isatty()
                and not os.getenv("NO_COLOR")
                and not os.getenv("ARCHANGEL_NO_PROGRESS")
            )
        )
        self.start_time    = 0.0
        self._phase_started = 0.0
        self._spin_frame   = 0
        self._lock         = threading.Lock()
        self._stop         = threading.Event()
        self._thread: threading.Thread | None = None

    # ---------------------------------------------------------- lifecycle
    def start(self, first_message: str = "") -> None:
        if not self.enabled:
            return
        self.start_time     = time.time()
        self._phase_started = self.start_time
        self.current_phase  = first_message or self.current_phase
        with self._lock:
            self._render()
        self._thread = threading.Thread(target=self._spin_loop, daemon=True)
        self._thread.start()

    def tick(self, phase: str) -> None:
        """Called as each phase completes."""
        if not self.enabled:
            return
        elapsed = time.time() - self._phase_started
        if elapsed < _MIN_PHASE_DURATION:
            time.sleep(_MIN_PHASE_DURATION - elapsed)
        if self.last_phase == "js" and phase == "reconcile":
            self.current += 1
        self.current += 1
        self.last_phase     = phase
        self.current_phase  = self._next_after(phase)
        self._phase_started = time.time()
        with self._lock:
            self._render()

    def done(self, msg: str | None = None) -> None:
        if not self.enabled:
            return
        elapsed = time.time() - self._phase_started
        if elapsed < _MIN_PHASE_DURATION:
            time.sleep(_MIN_PHASE_DURATION - elapsed)
        self._halt_thread()
        self._finalize(final=True, done_msg=msg)

    def fail(self, msg: str = "failed") -> None:
        if not self.enabled:
            return
        self._halt_thread()
        self._finalize(final=False, fail_msg=msg)

    # --------------------------------------------------------- rendering
    def _halt_thread(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=0.5)
            self._thread = None

    def _spin_loop(self) -> None:
        while not self._stop.wait(_SPINNER_INTERVAL):
            self._spin_frame = (self._spin_frame + 1) % len(self.SPINNER_FRAMES)
            with self._lock:
                self._render()

    def _render(self) -> None:
        elapsed = time.time() - self.start_time
        filled  = self.current * _BAR_WIDTH // self.total
        bar     = self.FILLED * filled + self.EMPTY * (_BAR_WIDTH - filled)
        pct     = int(self.current * 100 / self.total)
        spin    = self.SPINNER_FRAMES[self._spin_frame]
        spin_c  = f"{S.CYAN}{spin}{S.RESET}"
        lbl     = f"{S.CYAN}{S.BOLD}{self.label:<{_LABEL_WIDTH}}{S.RESET}"
        bar_c   = f"{S.GREEN}{bar}{S.RESET}" if pct else bar
        ctr     = f"{self.current}/{self.total}"
        phase   = self.current_phase[:_PHASE_WIDTH].ljust(_PHASE_WIDTH)
        ph_c    = f"{S.MUTED}{phase}{S.RESET}"
        el      = self._fmt_elapsed(elapsed)
        line = (
            f"  {spin_c} {lbl} [{bar_c}] "
            f"{pct:3d}%  {ctr:>6}  {ph_c}  {S.MUTED}{el}{S.RESET}"
        )
        sys.stdout.write("\r" + line + "\x1b[K")
        sys.stdout.flush()

    def _finalize(self, final: bool, fail_msg: str = "",
                  done_msg: str | None = None) -> None:
        elapsed = time.time() - self.start_time
        el = self._fmt_elapsed(elapsed)
        if final:
            # If the caller passed an explicit message, honour it (e.g. "1/3 tiers")
            # and only fill the bar to actual progress — never fake 100%.
            if done_msg is not None:
                filled = self.current * _BAR_WIDTH // self.total
                bar = self.FILLED * filled + self.EMPTY * (_BAR_WIDTH - filled)
                bar = f"{S.GREEN}{bar}{S.RESET}"
                tail = f"{S.GREEN}{done_msg}{S.RESET} in {S.MUTED}{el}{S.RESET}"
            else:
                bar   = f"{S.GREEN}{self.FILLED * _BAR_WIDTH}{S.RESET}"
                tail  = f"{S.GREEN}complete{S.RESET} in {S.MUTED}{el}{S.RESET}"
            glyph = f"{S.GREEN}{S.BOLD}{self.OK}{S.RESET}"
            lbl   = f"{S.GREEN}{S.BOLD}{self.label:<{_LABEL_WIDTH}}{S.RESET}"
        else:
            filled = self.current * _BAR_WIDTH // self.total
            bar    = self.FILLED * filled + self.EMPTY * (_BAR_WIDTH - filled)
            bar    = f"{S.RED}{bar}{S.RESET}"
            glyph  = f"{S.RED}{S.BOLD}{self.FAIL}{S.RESET}"
            lbl    = f"{S.RED}{S.BOLD}{self.label:<{_LABEL_WIDTH}}{S.RESET}"
            tail   = f"{S.RED}{fail_msg}{S.RESET}"
        line = f"  {glyph} {lbl} [{bar}] {tail}"
        sys.stdout.write("\r" + line + "\x1b[K\n")
        sys.stdout.flush()

    # ----------------------------------------------------------- helpers
    def _next_after(self, current: str) -> str:
        try:
            i = self.phases.index(current)
        except ValueError:
            return "..."
        return self.phases[i + 1] if i + 1 < len(self.phases) else "done"

    @staticmethod
    def _fmt_elapsed(secs: float) -> str:
        if secs < 60:
            return f"{secs:5.1f}s"
        m, s = divmod(int(secs), 60)
        return f"{m:2d}m{s:02d}s"


class Spinner:
    """Indefinite spinner — for processes with unknown duration (AI triage, etc).

    Usage:
        sp = Spinner("AI-TRIAGE")
        sp.start()
        try:
            ...work...
        finally:
            sp.stop()
    """
    SPINNER_FRAMES = ProgressBar.SPINNER_FRAMES

    def __init__(self, label: str, enabled: bool | None = None):
        self.label = label
        self.enabled = (
            enabled if enabled is not None
            else (
                sys.stdout.isatty()
                and not os.getenv("NO_COLOR")
                and not os.getenv("ARCHANGEL_NO_PROGRESS")
            )
        )
        self._spin_frame = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.start_time = 0.0

    def start(self) -> None:
        if not self.enabled:
            return
        self.start_time = time.time()
        with self._lock:
            self._render()
        self._thread = threading.Thread(target=self._spin_loop, daemon=True)
        self._thread.start()

    def stop(self, msg: str = "done") -> None:
        if not self.enabled:
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=0.5)
            self._thread = None
        elapsed = time.time() - self.start_time
        el = ProgressBar._fmt_elapsed(elapsed)
        line = (
            f"  {S.GREEN}{S.BOLD}{ProgressBar.OK}{S.RESET} "
            f"{S.GREEN}{S.BOLD}{self.label:<{_LABEL_WIDTH}}{S.RESET} "
            f"{S.GREEN}{msg}{S.RESET} in {S.MUTED}{el}{S.RESET}"
        )
        sys.stdout.write("\r" + line + "\x1b[K\n")
        sys.stdout.flush()

    def _spin_loop(self) -> None:
        while not self._stop.wait(_SPINNER_INTERVAL):
            self._spin_frame = (self._spin_frame + 1) % len(self.SPINNER_FRAMES)
            with self._lock:
                self._render()

    def _render(self) -> None:
        elapsed = time.time() - self.start_time
        spin = self.SPINNER_FRAMES[self._spin_frame]
        el = ProgressBar._fmt_elapsed(elapsed)
        line = (
            f"  {S.CYAN}{spin}{S.RESET} "
            f"{S.CYAN}{S.BOLD}{self.label:<{_LABEL_WIDTH}}{S.RESET} "
            f"{S.MUTED}{el}{S.RESET}"
        )
        sys.stdout.write("\r" + line + "\x1b[K")
        sys.stdout.flush()
