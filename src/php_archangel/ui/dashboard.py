"""phpArchangel Rich hybrid dashboard — integrated with the php_Archangel core.

Their chrome (hero art, nav, activity) preserved; the menu is OUR tool:
Scan / Findings / Confirm oracle / Exploit (SWORD) / Hardening / Reports /
Components. The scanner seam runs the real pipeline; the two doctrine gates
are Rich-native Confirm prompts — SWORD asks before it strikes.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.text import Text

from .artwork import pixel_art, inline_splash, ASSET

def _has_live(scanner) -> bool:
    import inspect
    try:
        return 'live' in inspect.signature(scanner).parameters
    except (TypeError, ValueError):
        return False


CYAN = '#13D9FF'; BLUE = '#2687FF'; GREEN = '#21F3A2'; MUTED = '#8FAFC6'; BORDER = '#0876A8'
MENU = ['Scan Target', 'Findings', 'Confirm (Oracle)', 'Exploit (SWORD)',
        'Hardening', 'Reports', 'Components', 'Help', 'Exit']


@dataclass
class Finding:
    title: str
    severity: str
    detail: str = ''


@dataclass
class ScanResult:
    target: str
    findings: list = field(default_factory=list)
    summary: str = ''
    completed_at: str = field(default_factory=
                              lambda: datetime.now().astimezone().strftime('%Y-%m-%d %H:%M'))
    core: dict | None = None      # full pipeline payload for gates/reports


def archangel_scan(target: str, live=None) -> ScanResult:
    """Adapter: run the REAL core pipeline (safe mode). live(phase) is called
    by the pipeline itself at every tier boundary — the progress truth source."""
    import contextlib, io
    from ..pipeline import run_scan
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        result = run_scan(target, verbose=True, on_event=live)
    d = result.to_dict()
    d['fingerprint'] = result.fingerprint_hash()
    d['_captured_log'] = buf.getvalue().splitlines()[-6:]
    fs = [Finding(title=f"{f.get('cve_id') or 'info'} — {(f.get('title') or '')[:56]}",
                  severity=f"{f.get('severity', '?')}",
                  detail=f"{f.get('verdict', '?')} | {(f.get('description') or '')[:76]}")
          for f in d.get('findings', [])]
    return ScanResult(target=target, findings=fs, summary=result.summary_line(),
                     core=d)


def _has_live(scanner) -> bool:
    import inspect
    try:
        return 'live' in inspect.signature(scanner).parameters
    except (TypeError, ValueError):
        return False


CYAN = '#13D9FF'; BLUE = '#2687FF'; GREEN = '#21F3A2'; MUTED = '#8FAFC6'; BORDER = '#0876A8'
MENU = ['Scan Target', 'Findings', 'Confirm (Oracle)', 'Exploit (SWORD)',
        'Hardening', 'Reports', 'Components', 'Help', 'Exit']


@dataclass
class Finding:
    title: str
    severity: str
    detail: str = ''


@dataclass
class ScanResult:
    target: str
    findings: list = field(default_factory=list)
    summary: str = ''
    completed_at: str = field(default_factory=
                              lambda: datetime.now().astimezone().strftime('%Y-%m-%d %H:%M'))
    core: dict | None = None      # full pipeline payload for gates/reports


def archangel_scan(target: str, live=None) -> ScanResult:
    """Adapter: run the REAL core pipeline (safe mode) and map to the view model.
    live: optional callback(str) receiving pipeline print-lines as they occur —
    used by the UI to drive the progress bar without corrupting the redraw."""
    import contextlib, io, sys
    from ..pipeline import run_scan
    buf = io.StringIO()
    if live is None:
        sink = buf
    else:
        class _Tap(io.StringIO):
            def write(self, s):
                buf.write(s)
                if s.strip():
                    live(s.rstrip("\n"))
                return len(s)
        sink = _Tap()
    class _Both:
        def write(self, s):
            sink.write(s)
        def flush(self):
            buf.flush() if hasattr(buf, 'flush') else None
    with contextlib.redirect_stdout(_Both()), contextlib.redirect_stderr(_Both()):
        result = run_scan(target, verbose=True)
    d = result.to_dict()
    d['fingerprint'] = result.fingerprint_hash()
    d['_captured_log'] = buf.getvalue().splitlines()[-6:]
    fs = [Finding(title=f"{f.get('cve_id') or 'info'} — {(f.get('title') or '')[:56]}",
                  severity=f"{f.get('severity', '?')}",
                  detail=f"{f.get('verdict', '?')} | {(f.get('description') or '')[:76]}")
          for f in d.get('findings', [])]
    return ScanResult(target=target, findings=fs, summary=result.summary_line(),
                     core=d)


class ArchangelDashboard:
    def __init__(self, scanner=None, version='1.0.0',
                 repository='github.com/tarbo03/php_Archangel',
                 author='Godwin Tarbo', console: Console | None = None):
        self.scanner = scanner or archangel_scan
        self.version, self.repository, self.author = version, repository, author
        self.console = console or Console()
        self.history: list[ScanResult] = []
        self.message = 'Ready. No scan performed yet. Select [1] Scan Target.'
        self.selected = 0
        self.report_preview: list[str] = []

    def _hero(self, width: int) -> Panel:
        art_w = min(160, max(30, width - 8))
        art = pixel_art(width=art_w, height=min(20, 18 + (art_w - 40)//12),
                        path=ASSET.with_name('archangel_figure.png'))
        strip = Table.grid(padding=(0, 2))
        strip.add_column(style=CYAN); strip.add_column(style='white')
        for key, val in [('Version', self.version), ('Author', self.author),
                         ('Project', self.repository),
                         ('SWORD + SHIELD', 'Scan | Confirm | Exploit | Report')]:
            strip.add_row(key, str(val))
        info = Group(Text('phpArchangel', style=f'bold {CYAN}'),
                     Text('PHP VULNERABILITY SECURITY TOOL — Detect | Defend | Hunt',
                          style=MUTED), strip)
        return Panel(Group(art, info), title='phpArchangel',
                     border_style=BORDER, box=box.DOUBLE_EDGE)

    def _nav(self) -> Panel:
        t = Table.grid(padding=(0, 1)); t.add_column(width=3); t.add_column()
        for idx, item in enumerate(MENU):
            chosen = idx == self.selected
            style = f'bold {CYAN}' if chosen else 'white'
            num = idx + 1 if idx < len(MENU) - 1 else 0
            t.add_row(Text(f'{num:>2}', style=style),
                      Text(('❯ ' if chosen else '  ') + item, style=style))
        return Panel(t, title='NAVIGATION', border_style=BORDER, box=box.ROUNDED)

    def _activity(self) -> Panel:
        table = Table(box=box.SIMPLE_HEAVY, expand=True, header_style=CYAN)
        table.add_column('Target', overflow='fold')
        table.add_column('Findings', justify='right')
        table.add_column('Completed')
        for scan in reversed(self.history[-5:]):
            counts = {}
            for f in (scan.core or {}).get('findings', []):
                counts[f.get('verdict')] = counts.get(f.get('verdict'), 0) + 1
            table.add_row(scan.target,
                         f"C{counts.get('CONFIRMED',0)} P{counts.get('PROBABLE',0)}",
                         scan.completed_at)
        if not self.history:
            table.add_row('No scans yet', '—', '—')
        return Panel(table, title='RECENT SCAN ACTIVITY', border_style=BORDER)

    # ------------------------------------------------------------- views
    def _main(self) -> Panel:
        title = MENU[self.selected]
        last = self.history[-1] if self.history else None
        core = last.core if last else None

        if self.selected == 0:
            body = Group(Text('Target URL', style=CYAN),
                         Text('Select [1] and enter an authorized target.', style=MUTED),
                         Text('Safe mode: recon + verdicts only. Gates ask before strikes.',
                              style=GREEN))
        elif self.selected == 1:
            tbl = Table(expand=True, header_style=CYAN)
            tbl.add_column('Severity'); tbl.add_column('Finding'); tbl.add_column('Verdict')
            for f in (last.findings if last else []):
                color = ('red' if 'CONFIRMED' in f.detail else
                         'yellow' if 'PROBABLE' in f.detail else MUTED)
                tbl.add_row(Text(f.severity, style=color), f.title, f.detail[:48])
            if not last:
                tbl.add_row('—', 'No findings yet — run a scan', '')
            body = tbl
        elif self.selected in (2, 3):      # gates documented in the panel
            gate = ('Oracle: confirms CVE-2026-109618 by state-corruption\n'
                    'signature. A vulnerable worker may crash and restart\n'
                    '(disclosed cost). Works from safe/probable findings.'
                    if self.selected == 2 else
                    'SWORD: full angel-sword chain (RCE as web user).\n'
                    'Only offered when a finding is CONFIRMED. Authorized\n'
                    'engagements only — the gate always asks.')
            body = Text(gate, style=MUTED)
        elif self.selected == 4:
            tbl = Table(expand=True, header_style=CYAN)
            tbl.add_column('CVE'); tbl.add_column('Remediation')
            for f in (core or {}).get('findings', []):
                if f.get('remediation'):
                    tbl.add_row(f.get('cve_id') or 'info', f['remediation'][:84])
            if not core:
                tbl.add_row('—', 'Run a scan for hardening advice')
            body = tbl
        elif self.selected == 5:
            if self.report_preview:
                body = Group(*[Text(' ' + ln[:100]) for ln in self.report_preview[:14]],
                             Text(f'\n full report: {self.report_path}', style=GREEN))
            else:
                body = Text('No report yet — run [6] from the menu after a scan\n'
                            '(AI triage via free OpenRouter, deterministic fallback).',
                            style=MUTED)
        elif self.selected == 6:
            tbl = Table(expand=True, header_style=CYAN)
            tbl.add_column('Component'); tbl.add_column('Version', justify='right'); tbl.add_column('Source')
            for c in (core or {}).get('components', [])[:14]:
                tbl.add_row(c.get('name', '?'), c.get('version', '?'), c.get('source', '?'))
            if not core:
                tbl.add_row('—', '—', 'Run a scan')
            body = tbl
        else:
            body = Text(' 1–7: sections · 0: exit\n'
                         ' [1] target → [2] findings → [3] oracle confirm →\n'
                         ' [4] exploit (CONFIRMED only) → [6] AI report\n'
                         ' Scanner, oracle, weapon, triage: all real, all gated.',
                         style=MUTED)
        return Panel(body, title=title.upper(), border_style=BORDER, box=box.ROUNDED)

    def draw(self) -> None:
        self.console.clear()
        # blink: some emulators reset attrs on clear; cycle visibility to
        # force the terminal to re-apply cursor attributes including blink
        try:
            self.console.file.write("\x1b[?12;25h")   # blink + visible
            self.console.file.flush()
        except Exception:
            pass
        width = self.console.size.width
        self.console.print(self._hero(width))
        if width < 80:
            self.console.print(self._nav()); self.console.print(self._main())
            self.console.print(self._activity())
        else:
            layout = Layout()
            layout.split_row(Layout(name='left', size=29),
                             Layout(name='center', ratio=3), Layout(name='right', ratio=2))
            layout['left'].update(self._nav()); layout['center'].update(self._main())
            layout['right'].update(self._activity())
            self.console.print(layout)
        self.console.print(Panel(Text(self.message, style=GREEN), title='STATUS',
                                 border_style=BORDER))

    # ------------------------------------------------------ gates/actions
    def _run_with_spinner(self, label, fn):
        """ANY long process gets a live spinner: oracle, AI report, SWORD."""
        from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
        import threading, time as _time
        holder = {}
        def work():
            try:
                holder['r'] = fn()
            except Exception as exc:
                holder['e'] = exc
        with Progress(SpinnerColumn(),
                      TextColumn('[cyan]{task.description}[/cyan]'),
                      TimeElapsedColumn(),
                      transient=True, console=self.console) as prog:
            prog.add_task(label, total=None)
            th = threading.Thread(target=work, daemon=True)
            th.start()
            while th.is_alive():
                _time.sleep(0.08)
        if 'e' in holder:
            raise holder['e']
        return holder['r']

    def _do_scan(self):
        target = Prompt.ask('[cyan]Authorized target[/cyan]').strip()
        if not target:
            self.message = 'Empty target — scan cancelled.'; return
        try:
            from rich.progress import (Progress, SpinnerColumn, BarColumn,
                                        TextColumn, TimeElapsedColumn)
            import threading, time as _time
            PHASES = ['entry', 'easteregg', 'components', 'js',
                      'reconcile', 'verdicts']
            state = {'i': 0}
            holder = {}

            def tap(phase):
                # worker-thread safe: only mutate the shared dict here.
                # The main loop (below) applies prog.update on the UI thread.
                if phase in PHASES:
                    idx = PHASES.index(phase) + 1
                    if idx > state['i']:
                        state['i'] = idx
                        state['label'] = phase

            def work():
                try:
                    holder['r'] = self.scanner(target, live=tap)
                except Exception as exc:
                    holder['e'] = exc

            with Progress(SpinnerColumn(),
                          TextColumn('[cyan]{task.description}[/cyan]'),
                          BarColumn(bar_width=32),
                          TextColumn('[muted]{task.percentage:.0f}%[/muted]'),
                          TimeElapsedColumn(),
                          transient=True, console=self.console,
                          refresh_per_second=10, auto_refresh=True) as prog:
                task = prog.add_task('phase: connecting', total=len(PHASES))
                bar_t0 = _time.perf_counter()
                th = threading.Thread(target=work, daemon=True)
                th.start()
                while th.is_alive():
                    _time.sleep(0.08)
                    # apply pending phase transitions ON THE UI THREAD
                    if state.get('label'):
                        prog.update(task, completed=state['i'],
                                    description='phase: ' + state['label'])
                        state['label'] = None
                    elif state['i'] == 0:   # honest creep pre-first-phase
                        prog.update(task,
                                    completed=min(0.9, (_time.perf_counter() - bar_t0) / 8.0),
                                    description='phase: connecting')

            if 'e' in holder:
                raise holder['e']
            result = holder['r']
            if not isinstance(result, ScanResult):
                raise TypeError('scanner must return ScanResult')
            self.history.append(result)
            self.selected = 1
            self.message = f'Scan complete: {result.summary} · next: [3] confirm or [6] report'
        except Exception as exc:
            self.message = f'Scanner error: {type(exc).__name__}: {exc}'

    def _resync(self, r: 'ScanResult') -> None:
        self.history.append(r)
        self.history = self.history[-5:]

    def _do_confirm(self):
        last = self.history[-1] if self.history else None
        if not last or not last.core:
            self.message = 'Run a scan first.'; return
        if not Confirm.ask('Run OOM oracle? (vulnerable worker may crash & restart)',
                           default=False):
            self.message = 'Oracle gate declined — findings stay PROBABLE.'; return
        import contextlib, io
        from ..core.models import ScanResult as SR, Finding as F, Severity, Verdict
        from ..verify.oom_oracle import confirm_findings
        r = SR(target=last.target)
        for fd in last.core.get('findings', []):
            f = F(cve_id=fd.get('cve_id'), title=fd.get('title', ''),
                  description=fd.get('description', ''),
                  severity=Severity(fd.get('severity', 'MEDIUM')),
                  target_url=last.target)
            f.verdict = Verdict(fd.get('verdict', 'PROBABLE'))
            r.findings.append(f)
        def _oracle_work():
            with contextlib.redirect_stdout(io.StringIO()):
                return confirm_findings(r, mode='oom')
        r = self._run_with_spinner('oracle: 3-tier probing…', _oracle_work)
        last.core = r.to_dict(); last.core['_done'] = True
        last.findings = [Finding(title=f"{f.cve_id} — {f.title}",
                                 severity=f.severity.value,
                                 detail=(f"{f.verdict.value}"
                                         + (f" | REASON: {f.retraction_reason}"
                                            if f.retraction_reason else " | oracle")))
                         for f in r.findings]
        oracle_ev = [e for fi in r.findings for e in fi.evidence
                     if e.kind == 'oracle_oom_divergence']
        learned_note = ''
        if oracle_ev and oracle_ev[0].detail.get("learned"):
            learned = oracle_ev[0].detail["learned"]
            parts_ = []
            if learned.get("memory_limit_bytes"):
                parts_.append(f"memory_limit={learned['memory_limit_bytes']//1024//1024}M")
            if learned.get("post_max_size_bytes"):
                parts_.append(f"post_max_size={learned['post_max_size_bytes']//1024//1024}M")
            if parts_:
                learned_note = ' · learned ' + ', '.join(parts_)
        self.message = 'Oracle complete: ' + r.summary_line() + learned_note

    def _do_exploit(self):
        last = self.history[-1] if self.history else None
        confirmed = [f for f in (last.core or {}).get('findings', [])
                     if f.get('verdict') == 'CONFIRMED'] if last else []
        if not confirmed:
            self.message = 'No CONFIRMED finding — run [3] oracle first. SWORD stays sheathed.'
            return
        if not Confirm.ask('Fire angel-sword (executes a test command on target)?',
                           default=False):
            self.message = 'SWORD gate declined.'; return
        import contextlib, io
        from ..core.models import ScanResult as SR, Finding as F, Severity, Verdict
        from ..exploit.angel_sword import exploit_confirmed
        r = SR(target=last.target)
        for fd in last.core.get('findings', []):
            f = F(cve_id=fd.get('cve_id'), title=fd.get('title', ''),
                  description=fd.get('description', ''),
                  severity=Severity(fd.get('severity', 'MEDIUM')),
                  target_url=last.target)
            f.verdict = Verdict(fd.get('verdict', 'PROBABLE'))
            r.findings.append(f)
        def _sword_work():
            import contextlib as _c
            with _c.redirect_stdout(io.StringIO()):
                return exploit_confirmed(r)
        r = self._run_with_spinner('SWORD: firing angel-sword…', _sword_work)
        self.message = 'SWORD fired (chain executed): ' + '; '.join(r.notes[-2:])

    def _do_report(self):
        last = self.history[-1] if self.history else None
        if not last or not last.core:
            self.message = 'Run a scan first.'
            return

        def _gen():
            from ..ai.provider import (AIProvider, ProviderConfig,
                                       triage_findings, apply_triage)
            from ..reporting.markdown import build_markdown_report
            d = {k: v for k, v in last.core.items() if not k.startswith('_')}
            ai = AIProvider(ProviderConfig(provider='openrouter'))
            if ai.available:
                t = triage_findings(ai, d)
                if t:
                    d = apply_triage(d, t)
                    d['ai_spend'] = ai.meter.report()
            return build_markdown_report(d, ai_narrative=True)

        try:
            md = self._run_with_spinner('report: AI triage…', _gen)
            out = Path(f"./archangel-out/{last.target.replace('://', '_').replace('/', '')}")
            out.mkdir(parents=True, exist_ok=True)
            p = out / 'report.md'
            p.write_text(md, encoding='utf-8')
            self.report_path = p
            self.report_preview = md.splitlines()
            self.selected = 5
            self.message = f'Report written: {p}'
        except Exception as exc:
            self.message = f'Report error: {type(exc).__name__}: {exc}'


    def run(self, splash: bool = False) -> None:
        self.console.file.write("\x1b[?12h")   # cursor: blink on
        self.console.file.flush()
        if splash:
            inline_splash('auto')
            Prompt.ask('Press Enter to open dashboard', default='', console=self.console)
        while True:
            self.draw()
            choice = Prompt.ask('[cyan]Select 1–8 or 0 to exit[/cyan]',
                                default='1').strip()
            if choice == '0':
                break
            if not choice.isdigit() or not 1 <= int(choice) <= 8:
                self.message = 'Choose 1–8 or 0.'; continue
            self.selected = int(choice) - 1
            if self.selected == 0:
                self._do_scan()
            elif self.selected == 2:
                self._do_confirm()
            elif self.selected == 3:
                self._do_exploit()
            elif self.selected == 5:
                self._do_report()
        self.console.file.write("\x1b[?12l")   # cursor: blink off
        self.console.file.flush()
        self.console.print('[cyan]phpArchangel closed.[/cyan]')
