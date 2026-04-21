"""
cli/ui.py
---------
Fixed-frame terminal dashboard showing the exact 19 training features.

Rendering strategy
------------------
Uses ANSI cursor-home + per-line erase to overwrite the previous frame
in-place without touching the scroll buffer.  The user can scroll up
past the dashboard to see the shell prompt that launched the tool.

    \033[H   — cursor to top-left  (no erase)
    \033[K   — erase from cursor to end of current line
    \033[J   — erase from cursor to bottom of screen

All history is written to dns_windows.tsv.
The terminal shows only the last N non-empty windows that fit on screen.

Column abbreviations (match training feature names)
---------------------------------------------------
  Pkt   avg_packet_length       sPkt  std_packet_length
  Ent   avg_entropy             xEnt  max_entropy
  QLen  avg_qname_len           xQL   max_qname_len
  DR    avg_digit_ratio         SR    avg_special_ratio
  USub  unique_subdomains       UQt   unique_qtypes
  TXT%  txt_ratio               LR%   large_resp_ratio
  TTL   avg_ttl                 ML    avg_max_label_len
  AnsΣ  answer_sum              RLen  resp_len_avg
  Ev    event_count
  Label  /  Cf (confidence)
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from io import StringIO

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cli.features import WindowFeatures
from shared.config import cli as cli_cfg

logger = logging.getLogger(__name__)

_HEADER_LINES      = 5   # panel border + 3 content lines + border
_TABLE_HEADER_LINES = 2   # column headers + separator


# ── Label styles ──────────────────────────────────────────────────────────────

_LABEL_STYLE: dict[str, tuple[str, str]] = {
    "benign":    ("[green]✅ benign[/green]",      "green"),
    "malicious": ("[red]❌ malicious[/red]",        "red"),
    "unknown":   ("[cyan]❓ unknown[/cyan]",         "cyan"),
    "pending":   ("[dim]⏳ pending[/dim]",          "dim"),
}


# ── Window row model ──────────────────────────────────────────────────────────

@dataclass
class WindowRow:
    """All data needed to render one dashboard row."""
    window_id:          str
    window_time:        datetime
    # training features
    query_count:        int
    response_count:     int
    avg_packet_length:  float
    std_packet_length:  float
    avg_entropy:        float
    max_entropy:        float
    avg_qname_len:      float
    max_qname_len:      float
    avg_digit_ratio:    float
    avg_special_ratio:  float
    unique_subdomains:  int
    unique_qtypes:      int
    txt_ratio:          float
    large_resp_ratio:   float
    avg_ttl:            float
    avg_max_label_len:  float
    answer_sum:         int
    resp_len_avg:       float
    event_count:        int
    # result
    label:              str   = "pending"
    confidence:         float = 0.0

    @classmethod
    def from_features(cls, f: WindowFeatures, window_id: str) -> "WindowRow":
        return cls(
            window_id=window_id,
            window_time=f.window_end,
            query_count=f.query_count,
            response_count=f.response_count,
            avg_packet_length=f.avg_packet_length,
            std_packet_length=f.std_packet_length,
            avg_entropy=f.avg_entropy,
            max_entropy=f.max_entropy,
            avg_qname_len=f.avg_qname_len,
            max_qname_len=f.max_qname_len,
            avg_digit_ratio=f.avg_digit_ratio,
            avg_special_ratio=f.avg_special_ratio,
            unique_subdomains=f.unique_subdomains,
            unique_qtypes=f.unique_qtypes,
            txt_ratio=f.txt_ratio,
            large_resp_ratio=f.large_resp_ratio,
            avg_ttl=f.avg_ttl,
            avg_max_label_len=f.avg_max_label_len,
            answer_sum=f.answer_sum,
            resp_len_avg=f.resp_len_avg,
            event_count=f.event_count,
        )


# ── Terminal helper ───────────────────────────────────────────────────────────

def _term_size() -> tuple[int, int]:
    try:
        s = os.get_terminal_size()
        return s.columns, s.lines
    except OSError:
        return 140, 40


def _render(renderable, *, width: int) -> list[str]:
    """Render a Rich renderable to a list of plain text lines."""
    buf = StringIO()
    con = Console(file=buf, width=width, highlight=False, markup=True)
    con.print(renderable)
    return buf.getvalue().splitlines()


# ── Dashboard ─────────────────────────────────────────────────────────────────

class Dashboard:
    """
    Fixed-frame dashboard showing all 19 training features per window row.

    Thread safety: _lock protects _rows and _index.
    """

    def __init__(
        self,
        sniffer_ref,
        agent_id:   str,
        api_url:    str,
        refresh_s:  float = cli_cfg.ui_refresh_s,
    ) -> None:
        self._sniffer   = sniffer_ref
        self._agent_id  = agent_id
        self._api_url   = api_url
        self._refresh_s = refresh_s
        self._start     = datetime.now()
        self._running   = False

        self._lock  = threading.Lock()
        self._rows:  deque[WindowRow]     = deque(maxlen=500)
        self._index: dict[str, WindowRow] = {}

    # ── public API ────────────────────────────────────────────────────────────

    def add_window(self, features: WindowFeatures, window_id: str) -> None:
        row = WindowRow.from_features(features, window_id)
        with self._lock:
            self._rows.append(row)
            self._index[window_id] = row

    def update_result(self, window_id: str, label: str, confidence: float) -> None:
        with self._lock:
            row = self._index.get(window_id)
            if row is not None:
                row.label      = label
                row.confidence = confidence

    def start(self) -> None:
        self._running = True
        sys.stdout.write("\033[?25l")   # hide cursor
        sys.stdout.flush()
        t = threading.Thread(target=self._render_loop, daemon=True, name="ui")
        t.start()
        logger.info("Dashboard started.")

    def stop(self) -> None:
        self._running = False
        time.sleep(self._refresh_s + 0.1)
        sys.stdout.write("\033[?25h")   # restore cursor
        sys.stdout.flush()

    def print_summary(self) -> None:
        with self._lock:
            rows = list(self._rows)
        total     = len(rows)
        benign    = sum(1 for r in rows if r.label == "benign")
        malicious = sum(1 for r in rows if r.label == "malicious")

        con = Console()
        con.print()
        con.rule("[bold red]DNS Monitor Stopped[/bold red]")
        con.print(
            f"[bold]Session summary[/bold]  "
            f"[cyan]Windows: {total}[/cyan]  "
            f"[green]Benign: {benign}[/green]  "
            f"[red]Malicious: {malicious}[/red]  "
            f"Uptime: {self._uptime()}"
        )
        con.print("[dim]Full history → dns_windows.tsv[/dim]")
        con.print()

    # ── rendering ─────────────────────────────────────────────────────────────

    def _uptime(self) -> str:
        d      = datetime.now() - self._start
        h, rem = divmod(int(d.total_seconds()), 3600)
        m, s   = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def _counts(self) -> dict[str, int]:
        with self._lock:
            rows = list(self._rows)
        return {
            "total":     len(rows),
            "benign":    sum(1 for r in rows if r.label == "benign"),
            "malicious": sum(1 for r in rows if r.label == "malicious"),
            "pending":   sum(1 for r in rows if r.label == "pending"),
        }

    def _build_header(self, width: int) -> Panel:
        pkts   = getattr(self._sniffer, "packet_count", 0)
        counts = self._counts()

        line1 = Text.assemble(
            ("  🛡  DNS MONITOR v3  ",                "bold white"),
            ("│  WINDOW-BASED ANOMALY DETECTION  │  ", "dim"),
            ("● RUNNING",                              "bold green"),
        )
        line2 = Text.assemble(
            ("  Agent: ",    "dim"), (self._agent_id, "cyan"),
            ("   API: ",     "dim"), (self._api_url,  "dim cyan"),
            ("   Uptime: ",  "dim"), (self._uptime(), "cyan"),
            ("   Packets: ", "dim"), (f"{pkts:,}",    "cyan"),
        )
        line3 = Text.assemble(
            ("  Windows: ",     "dim"), (str(counts["total"]),     "cyan"),
            ("   ✅ Benign: ",  "dim"), (str(counts["benign"]),    "green"),
            ("   ❌ Malicious: ","dim"), (str(counts["malicious"]), "red"),
            ("   ⏳ Pending: ", "dim"), (str(counts["pending"]),   "dim"),
            ("   History → dns_windows.tsv", "dim"),
        )
        return Panel(
            Text("\n").join([line1, line2, line3]),
            border_style="bright_blue",
            padding=(0, 1),
        )

    def _build_table(self, max_rows: int) -> Table:
        tbl = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold bright_blue",
            show_edge=False,
            padding=(0, 1),
            expand=True,
        )

        # ── Columns ───────────────────────────────────────────────────────────
        tbl.add_column("Time",   style="dim",      width=9,  no_wrap=True)
        tbl.add_column("Q",      justify="right",  width=5,  no_wrap=True)   # query_count
        tbl.add_column("R",      justify="right",  width=5,  no_wrap=True)   # response_count
        tbl.add_column("Pkt",    justify="right",  width=6,  no_wrap=True)   # avg_packet_length
        tbl.add_column("sPkt",   justify="right",  width=5,  no_wrap=True)   # std_packet_length
        tbl.add_column("Ent",    justify="right",  width=5,  no_wrap=True)   # avg_entropy
        tbl.add_column("xEnt",   justify="right",  width=5,  no_wrap=True)   # max_entropy
        tbl.add_column("QLen",   justify="right",  width=5,  no_wrap=True)   # avg_qname_len
        tbl.add_column("xQL",    justify="right",  width=4,  no_wrap=True)   # max_qname_len
        tbl.add_column("DR",     justify="right",  width=5,  no_wrap=True)   # avg_digit_ratio
        tbl.add_column("SR",     justify="right",  width=5,  no_wrap=True)   # avg_special_ratio
        tbl.add_column("USub",   justify="right",  width=5,  no_wrap=True)   # unique_subdomains
        tbl.add_column("UQt",    justify="right",  width=4,  no_wrap=True)   # unique_qtypes
        tbl.add_column("TXT%",   justify="right",  width=5,  no_wrap=True)   # txt_ratio
        tbl.add_column("LR%",    justify="right",  width=5,  no_wrap=True)   # large_resp_ratio
        tbl.add_column("TTL",    justify="right",  width=6,  no_wrap=True)   # avg_ttl
        tbl.add_column("ML",     justify="right",  width=5,  no_wrap=True)   # avg_max_label_len
        tbl.add_column("AnsΣ",   justify="right",  width=5,  no_wrap=True)   # answer_sum
        tbl.add_column("RLen",   justify="right",  width=5,  no_wrap=True)   # resp_len_avg
        tbl.add_column("Ev",     justify="right",  width=4,  no_wrap=True)   # event_count
        tbl.add_column("Label",  width=14,         no_wrap=True)
        tbl.add_column("Cf",     justify="right",  width=5,  no_wrap=True)   # confidence

        with self._lock:
            visible = list(self._rows)[-max_rows:]

        for row in visible:
            markup, _ = _LABEL_STYLE.get(row.label, ("?", "white"))
            cf = f"{row.confidence:.2f}" if row.label not in ("pending", "unknown") else "—"
            tbl.add_row(
                row.window_time.strftime("%H:%M:%S"),
                str(row.query_count),
                str(row.response_count),
                f"{row.avg_packet_length:.0f}",
                f"{row.std_packet_length:.0f}",
                f"{row.avg_entropy:.2f}",
                f"{row.max_entropy:.2f}",
                f"{row.avg_qname_len:.1f}",
                f"{row.max_qname_len:.0f}",
                f"{row.avg_digit_ratio:.2f}",
                f"{row.avg_special_ratio:.2f}",
                str(row.unique_subdomains),
                str(row.unique_qtypes),
                f"{row.txt_ratio:.2f}",
                f"{row.large_resp_ratio:.2f}",
                f"{row.avg_ttl:.1f}",
                f"{row.avg_max_label_len:.1f}",
                str(row.answer_sum),
                f"{row.resp_len_avg:.0f}",
                str(row.event_count),
                Text.from_markup(markup),
                cf,
            )

        return tbl

    def _render_loop(self) -> None:
        """
        Cursor-home fixed-frame render loop.

        \033[H   moves cursor to top-left (scroll buffer untouched)
        \033[K   erases each line to EOL  (handles line shortening)
        \033[J   erases below last line   (handles table shrinkage)
        """
        while self._running:
            try:
                cols, rows = _term_size()
                data_rows  = max(1, rows - _HEADER_LINES - _TABLE_HEADER_LINES - 2)

                header_lines = _render(self._build_header(cols),       width=cols)
                table_lines  = _render(self._build_table(data_rows),   width=cols)
                all_lines    = header_lines + table_lines

                frame = "\033[H"
                for line in all_lines[:rows - 1]:
                    frame += line + "\033[K\n"
                frame += "\033[J"

                sys.stdout.write(frame)
                sys.stdout.flush()

            except Exception as exc:
                logger.debug("Render error (non-fatal): %s", exc)

            time.sleep(self._refresh_s)