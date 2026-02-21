from __future__ import annotations
import traceback
import csv
import html
import json
import os
import re
import sys
import webbrowser
from dataclasses import dataclass
from datetime import date, datetime
from typing import Dict, List, Optional, Set, Tuple

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt6.QtGui import QAction, QDesktopServices
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QProgressBar,
    QRadioButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from .models import Endpoint, Source, Article
from .sources_repo import load_sources, save_sources
from .tor_client import get_managed_tor_session
from .fetcher import (
    fetch_discovery_items,
    FETCH_MODE_ANY,
    FETCH_MODE_LATEST_N,
    FETCH_MODE_ON_DATE,
    FETCH_MODE_DATE_RANGE,
)
from .extractor import extract_article_metadata_and_text

# legacy storage
from .storage import save_articles_country_source, load_all_articles as load_all_articles_legacy

# keywords
from .keywords import (
    ensure_default_keyword_files,
    load_keywords_national,
    load_keywords_threat,
    save_keywords_national,
    save_keywords_threat,
    shortlist_articles_two_layer,
    ShortlistResult,
)

# analysis layers
try:
    from . import analysis_layers as al  # import module so we can log al.__file__
    HAS_ANALYSIS = True
except Exception:
    al = None  # type: ignore[assignment]
    HAS_ANALYSIS = False


APP_TITLE = "AI-based Threat Assessment of Pakistan"


# -----------------------
# Run storage helpers (unchanged)
# -----------------------
def _runs_root(base_dir: str) -> str:
    p = os.path.join(base_dir, "data", "runs")
    os.makedirs(p, exist_ok=True)
    return p


def create_run_dir(base_dir: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = os.path.join(_runs_root(base_dir), f"run_{ts}")
    os.makedirs(run_dir, exist_ok=True)
    os.makedirs(os.path.join(run_dir, "fetched"), exist_ok=True)
    os.makedirs(os.path.join(run_dir, "shortlisted"), exist_ok=True)
    return run_dir


def list_run_dirs(base_dir: str) -> List[str]:
    root = _runs_root(base_dir)
    items: List[str] = []
    try:
        for name in sorted(os.listdir(root)):
            p = os.path.join(root, name)
            if os.path.isdir(p) and name.startswith("run_"):
                items.append(p)
    except Exception:
        pass
    return items


def _safe_slug(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "source"


def _save_articles_grouped(root_dir: str, subfolder: str, articles: List[Article]) -> None:
    base = os.path.join(root_dir, subfolder)
    os.makedirs(base, exist_ok=True)

    grouped: Dict[Tuple[str, str], List[Article]] = {}
    for a in articles:
        key = (a.country or "UNKNOWN", _safe_slug(a.source_name or "source"))
        grouped.setdefault(key, []).append(a)

    for (country, source_slug), items in grouped.items():
        cdir = os.path.join(base, country)
        os.makedirs(cdir, exist_ok=True)
        path = os.path.join(cdir, f"{source_slug}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump([x.to_dict() for x in items], f, ensure_ascii=False, indent=2)


def load_articles_from_run(root_dir: str, subfolder: str = "fetched") -> List[Article]:
    base = os.path.join(root_dir, subfolder)
    out: List[Article] = []
    if not os.path.isdir(base):
        return out

    for country in os.listdir(base):
        cdir = os.path.join(base, country)
        if not os.path.isdir(cdir):
            continue
        for fn in os.listdir(cdir):
            if not fn.lower().endswith(".json"):
                continue
            path = os.path.join(cdir, fn)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for d in data:
                        try:
                            out.append(Article.from_dict(d))
                        except Exception:
                            continue
            except Exception:
                continue
    return out


# -----------------------
# Small UI helpers
# -----------------------
def _boxed(title: str, widget: QWidget) -> QGroupBox:
    box = QGroupBox(title)
    layout = QVBoxLayout(box)
    layout.addWidget(widget)
    return box


def _parse_yyyy_mm_dd(s: str) -> Optional[date]:
    s = (s or "").strip()
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None


def _iso_to_date(iso_s: Optional[str]) -> Optional[date]:
    if not iso_s:
        return None
    t = iso_s.strip()
    if not t:
        return None
    if re.match(r"^\d{4}-\d{2}-\d{2}$", t):
        try:
            return datetime.strptime(t, "%Y-%m-%d").date()
        except Exception:
            return None
    try:
        d = datetime.fromisoformat(t.replace("Z", "+00:00"))
        return d.date()
    except Exception:
        m = re.match(r"^(\d{4}-\d{2}-\d{2})", t)
        if m:
            try:
                return datetime.strptime(m.group(1), "%Y-%m-%d").date()
            except Exception:
                return None
    return None


def _open_path_in_file_manager(path: str) -> None:
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
    except Exception:
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))


def _open_url(url: str) -> None:
    url = (url or "").strip()
    if not url:
        return
    if not QDesktopServices.openUrl(QUrl(url)):
        webbrowser.open(url)


def _bucket_from_prepriority(v: Optional[float]) -> str:
    if v is None:
        return "NA"
    try:
        x = float(v)
    except Exception:
        return "NA"
    if x >= 80:
        return "CRITICAL"
    if x >= 60:
        return "HIGH"
    if x >= 40:
        return "MEDIUM"
    return "LOW"


def _get_kw_nat(a: Article) -> List[str]:
    # Prefer spec field, fall back to legacy/raw
    if getattr(a, "kw_national_hits", None):
        return list(a.kw_national_hits or [])
    if getattr(a, "keywords_national_matched", None):
        return list(a.keywords_national_matched or [])
    return list((a.raw or {}).get("kw_national_hits") or [])


def _get_kw_thr(a: Article) -> List[str]:
    if getattr(a, "kw_threat_hits", None):
        return list(a.kw_threat_hits or [])
    if getattr(a, "keywords_threat_matched", None):
        return list(a.keywords_threat_matched or [])
    return list((a.raw or {}).get("kw_threat_hits") or [])


def _is_shortlisted(a: Article) -> bool:
    if getattr(a, "shortlisted", None) is True:
        return True
    if (a.raw or {}).get("kw_shortlisted") is True:
        return True
    return False


# -----------------------
# Worker thread (fetch)
# -----------------------
@dataclass
class RunConfig:
    mode: str
    limit_items_per_source: int
    extract_full_text: bool
    on_date: Optional[date] = None
    from_date: Optional[date] = None
    to_date: Optional[date] = None


class WorkerFetch(QThread):
    progress = pyqtSignal(str)
    finished_ok = pyqtSignal(list, list, str)  # articles, logs, run_dir
    finished_fail = pyqtSignal(str)

    def __init__(self, base_dir: str, sources: List[Source], cfg: RunConfig) -> None:
        super().__init__()
        self.base_dir = base_dir
        self.sources = sources
        self.cfg = cfg
        self._stop = False

    def request_stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        try:
            logs: List[str] = []
            all_articles: List[Article] = []

            run_dir = create_run_dir(self.base_dir)
            logs.append(f"[RUN] {run_dir}")

            client = get_managed_tor_session(app_base_dir=self.base_dir)
            session = client.session
            try:
                for s in self.sources:
                    if self._stop:
                        logs.append("[STOP] user requested stop")
                        break
                    if not s.enabled:
                        continue

                    self.progress.emit(f"Discovering: {s.country} | {s.name}")

                    fetcher_mode = FETCH_MODE_ANY
                    kwargs = {}
                    if self.cfg.mode == "latest":
                        fetcher_mode = FETCH_MODE_LATEST_N
                        kwargs["latest_n"] = self.cfg.limit_items_per_source
                    elif self.cfg.mode == "on_date":
                        fetcher_mode = FETCH_MODE_ON_DATE
                        kwargs["on_date"] = self.cfg.on_date
                        kwargs["latest_n"] = self.cfg.limit_items_per_source
                    elif self.cfg.mode == "range":
                        fetcher_mode = FETCH_MODE_DATE_RANGE
                        kwargs["date_from"] = self.cfg.from_date
                        kwargs["date_to"] = self.cfg.to_date
                        kwargs["latest_n"] = self.cfg.limit_items_per_source

                    items, log_lines = fetch_discovery_items(
                        session=session,
                        source=s,
                        limit_items=self.cfg.limit_items_per_source,
                        timeout=30,
                        mode=fetcher_mode,
                        **kwargs,
                    )
                    logs.extend(log_lines)

                    if self.cfg.extract_full_text:
                        for i, a in enumerate(items):
                            if self._stop:
                                break
                            self.progress.emit(f"Extracting: {s.name} ({i+1}/{len(items)})")
                            title, author, published_iso, text, note = extract_article_metadata_and_text(
                                session, a.url, timeout=30
                            )
                            if title and (not a.title or a.title == a.url):
                                a.title = title
                            if author and not a.author:
                                a.author = author
                            if published_iso and not a.published_at:
                                a.published_at = published_iso
                            if text:
                                a.content_text = text
                                a.content_length = len(text)
                            if note:
                                a.extraction_notes.append(note)

                    if self.cfg.mode == "on_date" and self.cfg.on_date:
                        items = [x for x in items if _iso_to_date(x.published_at) == self.cfg.on_date]
                    elif self.cfg.mode == "range":
                        fd, td = self.cfg.from_date, self.cfg.to_date

                        def _in_range(a: Article) -> bool:
                            d = _iso_to_date(a.published_at)
                            if not d:
                                return False
                            if fd and d < fd:
                                return False
                            if td and d > td:
                                return False
                            return True

                        items = [x for x in items if _in_range(x)]

                    all_articles.extend(items)

                _save_articles_grouped(run_dir, "fetched", all_articles)
            finally:
                client.close()

            self.finished_ok.emit(all_articles, logs, run_dir)
        except Exception as ex:
            self.finished_fail.emit(f"{type(ex).__name__}: {ex}")


# -----------------------
# Worker thread (LLM analysis)
# -----------------------
class WorkerLLM(QThread):
    progress = pyqtSignal(str)
    finished_ok = pyqtSignal(int)  # count processed
    finished_fail = pyqtSignal(str)

    def __init__(self, articles: List[Article], model_path: str) -> None:
        super().__init__()
        self.articles = articles
        self.model_path = model_path

    def run(self) -> None:
        try:
            if not HAS_ANALYSIS or al is None:
                raise RuntimeError("analysis_layers module failed to import.")

            if not hasattr(al, "run_layer3_llm_scoring") or not hasattr(al, "compute_risk_index"):
                raise RuntimeError("analysis_layers.py is missing required functions.")

            if not self.model_path or not os.path.isfile(self.model_path):
                raise RuntimeError(f"Model file not found: {self.model_path}")

            def cb(msg: str) -> None:
                self.progress.emit(msg)

            cb(f"[LLM] analysis_layers loaded from: {getattr(al, '__file__', 'UNKNOWN')}")
            cb(f"[LLM] run_layer3_llm_scoring: {al.run_layer3_llm_scoring}")

            # Extra environment debug
            cb(f"[LLM] Python: {sys.version}")
            cb(f"[LLM] Platform: {sys.platform}")
            cb(f"[LLM] PID: {os.getpid()}")
            cb(f"[LLM] Model path: {self.model_path}")

            try:
                size_bytes = os.path.getsize(self.model_path)
                cb(f"[LLM] Model size (GB): {size_bytes / 1024 / 1024 / 1024:.2f}")
            except Exception as ex:
                cb(f"[LLM] Model size read failed: {type(ex).__name__}: {ex}")

            # Call into analysis with progress callback
            al.run_layer3_llm_scoring(self.articles, self.model_path, progress_cb=cb)
            al.compute_risk_index(self.articles)

            self.finished_ok.emit(len(self.articles))

        except Exception as ex:
            tb = traceback.format_exc()
            self.finished_fail.emit(f"{type(ex).__name__}: {ex}\n{tb}")




# -----------------------
# Source editor dialog
# -----------------------
class SourceEditorDialog(QDialog):
    def __init__(self, parent: QWidget, src: Optional[Source] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Source Editor")
        self._src = src

        self.country = QLineEdit(src.country if src else "")
        self.name = QLineEdit(src.name if src else "")
        self.enabled = QCheckBox("Enabled")
        self.enabled.setChecked(src.enabled if src else True)

        self.endpoints = QListWidget()
        if src:
            for ep in src.endpoints:
                self._add_endpoint_item(ep)

        btn_add_ep = QPushButton("Add Endpoint")
        btn_remove_ep = QPushButton("Remove Selected")
        btn_add_ep.clicked.connect(self._on_add_ep)
        btn_remove_ep.clicked.connect(self._on_remove_ep)

        btn_ok = QPushButton("Save")
        btn_cancel = QPushButton("Cancel")
        btn_ok.clicked.connect(self.accept)
        btn_cancel.clicked.connect(self.reject)

        form = QFormLayout()
        form.addRow("Country", self.country)
        form.addRow("Source Name", self.name)
        form.addRow("", self.enabled)

        ep_box = QGroupBox("Endpoints")
        ep_layout = QVBoxLayout(ep_box)
        ep_layout.addWidget(self.endpoints)

        ep_btns = QHBoxLayout()
        ep_btns.addWidget(btn_add_ep)
        ep_btns.addWidget(btn_remove_ep)
        ep_layout.addLayout(ep_btns)

        root = QVBoxLayout(self)
        root.addLayout(form)
        root.addWidget(ep_box)

        bottom = QHBoxLayout()
        bottom.addStretch(1)
        bottom.addWidget(btn_ok)
        bottom.addWidget(btn_cancel)
        root.addLayout(bottom)

    def _add_endpoint_item(self, ep: Endpoint) -> None:
        item = QListWidgetItem(f"{ep.type} | {ep.url} | {ep.note} | enabled={ep.enabled}")
        item.setData(Qt.ItemDataRole.UserRole, ep)
        self.endpoints.addItem(item)

    def _on_add_ep(self) -> None:
        d = QDialog(self)
        d.setWindowTitle("Add Endpoint")

        t = QLineEdit("RSS")
        u = QLineEdit()
        n = QLineEdit()
        en = QCheckBox("Enabled")
        en.setChecked(True)

        form = QFormLayout(d)
        form.addRow("Type (RSS/FEED_DIRECTORY/HTML_LISTING/SITEMAP_INDEX)", t)
        form.addRow("URL", u)
        form.addRow("Note", n)
        form.addRow("", en)

        btn = QPushButton("Add")
        btn.clicked.connect(d.accept)
        form.addRow(btn)

        if d.exec() == QDialog.DialogCode.Accepted:
            ep = Endpoint(type=t.text().strip(), url=u.text().strip(), note=n.text().strip(), enabled=en.isChecked())
            self._add_endpoint_item(ep)

    def _on_remove_ep(self) -> None:
        row = self.endpoints.currentRow()
        if row >= 0:
            self.endpoints.takeItem(row)

    def get_source(self) -> Source:
        eps: List[Endpoint] = []
        for i in range(self.endpoints.count()):
            ep = self.endpoints.item(i).data(Qt.ItemDataRole.UserRole)
            if isinstance(ep, Endpoint):
                eps.append(ep)
        return Source(
            country=self.country.text().strip(),
            name=self.name.text().strip(),
            enabled=self.enabled.isChecked(),
            endpoints=eps,
        )


# -----------------------
# Main window
# -----------------------
class MainWindow(QMainWindow):
    def __init__(self, base_dir: str) -> None:
        super().__init__()
        self.base_dir = base_dir
        self.setWindowTitle(APP_TITLE)

        ensure_default_keyword_files(self.base_dir)

        self.sources: List[Source] = load_sources(self.base_dir)
        self.articles_cache: List[Article] = []

        self.current_run_dir: Optional[str] = None
        self.current_view_subfolder: str = "fetched"

        self._last_selected_countries: Set[str] = set()
        self._last_selected_sources: Set[Tuple[str, str]] = set()

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.logs_box = QPlainTextEdit()
        self.logs_box.setReadOnly(True)

        self._build_menu()

        self.tab_run = self._build_run_tab()
        self.tab_browse = self._build_browse_tab()
        self.tab_analysis = self._build_analysis_tab()
        self.tab_sources = self._build_sources_tab()
        self.tab_keywords = self._build_keywords_tab()
        self.tab_logs = self._build_logs_tab()

        self.tabs.addTab(self.tab_run, "Run")
        self.tabs.addTab(self.tab_browse, "Browse")
        self.tabs.addTab(self.tab_analysis, "Analysis")
        self.tabs.addTab(self.tab_sources, "Sources")
        self.tabs.addTab(self.tab_keywords, "Keywords")
        self.tabs.addTab(self.tab_logs, "Logs")

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        self.status_label = QLabel("Idle")
        self.statusBar().addWidget(self.status_label, 1)
        self.statusBar().addPermanentWidget(self.progress)

        self.refresh_ui()

    # ---------------- Menu ----------------
    def _build_menu(self) -> None:
        bar = self.menuBar()

        file_menu = bar.addMenu("File")
        act_reload = QAction("Reload sources.json", self)
        act_reload.triggered.connect(self._on_reload_sources)
        file_menu.addAction(act_reload)

        act_open_data = QAction("Open data folder", self)
        act_open_data.triggered.connect(self._on_open_data_folder)
        file_menu.addAction(act_open_data)

        file_menu.addSeparator()
        act_quit = QAction("Quit", self)
        act_quit.triggered.connect(self.close)
        file_menu.addAction(act_quit)

        help_menu = bar.addMenu("Help")
        act_about = QAction("About", self)
        act_about.triggered.connect(self._on_about)
        help_menu.addAction(act_about)

    def _on_about(self) -> None:
        QMessageBox.information(
            self,
            "About",
            "Threat Assessment App\n\n"
            "Workflow:\n"
            "1) Select Sources\n"
            "2) Fetch (optionally extract full text)\n"
            "3) Run keyword shortlisting\n"
            "4) Layer-2 scoring + PrePriority\n"
            "5) LLM threat scoring + RiskIndex\n"
            "6) Browse / Export / Review\n",
        )

    def _on_open_data_folder(self) -> None:
        path = os.path.join(self.base_dir, "data")
        os.makedirs(path, exist_ok=True)
        _open_path_in_file_manager(path)

    def _on_reload_sources(self) -> None:
        self.sources = load_sources(self.base_dir)
        self.log("Reloaded sources from data/sources.json")
        self.refresh_ui()

    # ---------------- Logging ----------------
    def log(self, msg: str) -> None:
        self.logs_box.appendPlainText(msg)

    def _set_busy(self, busy: bool, status: str) -> None:
        self.progress.setVisible(busy)
        self.status_label.setText(status)

    # ---------------- Tabs ----------------
    def _build_run_tab(self) -> QWidget:
        w = QWidget()
        root = QVBoxLayout(w)

        mgr = QGroupBox("Run Manager")
        mgr_layout = QHBoxLayout(mgr)

        self.cmb_runs = QComboBox()
        self.cmb_runs.setMinimumWidth(520)

        btn_load_fetched = QPushButton("Load Fetched")
        btn_load_shortlisted = QPushButton("Load Shortlisted")
        btn_load_legacy = QPushButton("Load Legacy")
        btn_open_run = QPushButton("Open Run Folder")

        btn_load_fetched.clicked.connect(lambda: self._on_load_selected_run("fetched"))
        btn_load_shortlisted.clicked.connect(lambda: self._on_load_selected_run("shortlisted"))
        btn_load_legacy.clicked.connect(self._on_load_legacy)
        btn_open_run.clicked.connect(self._on_open_selected_run_folder)

        mgr_layout.addWidget(QLabel("Run:"))
        mgr_layout.addWidget(self.cmb_runs, 1)
        mgr_layout.addWidget(btn_load_fetched)
        mgr_layout.addWidget(btn_load_shortlisted)
        mgr_layout.addWidget(btn_load_legacy)
        mgr_layout.addWidget(btn_open_run)

        self.lbl_kpis = QLabel("Loaded: 0 | Shortlisted: 0 | Full-text: 0 | View: - | Storage: -")
        self.lbl_kpis.setWordWrap(True)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left = QWidget()
        left_l = QVBoxLayout(left)

        self.country_list = QListWidget()
        self.country_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.country_list.itemSelectionChanged.connect(self._refresh_sources_for_countries)

        self.source_list = QListWidget()
        self.source_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)

        sel_hint = QLabel("Tip: Select Countries then select Sources.\nOnly enabled sources will run.")
        sel_hint.setWordWrap(True)

        left_l.addWidget(sel_hint)
        left_l.addWidget(_boxed("Countries", self.country_list), 1)
        left_l.addWidget(_boxed("Sources", self.source_list), 2)

        right = QWidget()
        right_l = QVBoxLayout(right)

        controls = QGroupBox("Fetch Configuration")
        c = QFormLayout(controls)

        self.rad_latest = QRadioButton("Latest N per source")
        self.rad_on_date = QRadioButton("Only this date (YYYY-MM-DD)")
        self.rad_range = QRadioButton("Date range (YYYY-MM-DD)")
        self.rad_latest.setChecked(True)

        mode_box = QGroupBox("Mode")
        ml = QVBoxLayout(mode_box)
        ml.addWidget(self.rad_latest)
        ml.addWidget(self.rad_on_date)
        ml.addWidget(self.rad_range)

        self.spin_limit = QSpinBox()
        self.spin_limit.setRange(1, 2000)
        self.spin_limit.setValue(5)

        self.txt_on_date = QLineEdit()
        self.txt_on_date.setPlaceholderText("YYYY-MM-DD")

        self.txt_from = QLineEdit()
        self.txt_from.setPlaceholderText("YYYY-MM-DD")
        self.txt_to = QLineEdit()
        self.txt_to.setPlaceholderText("YYYY-MM-DD")

        range_widget = QWidget()
        rr = QHBoxLayout(range_widget)
        rr.setContentsMargins(0, 0, 0, 0)
        rr.addWidget(QLabel("From"))
        rr.addWidget(self.txt_from)
        rr.addWidget(QLabel("To"))
        rr.addWidget(self.txt_to)

        self.chk_fulltext = QCheckBox("Extract full article text (recommended)")
        self.chk_fulltext.setChecked(True)

        c.addRow(mode_box)
        c.addRow("N (per source)", self.spin_limit)
        c.addRow("Date", self.txt_on_date)
        c.addRow("Range", range_widget)
        c.addRow("", self.chk_fulltext)

        actions = QGroupBox("Actions")
        a = QVBoxLayout(actions)

        self.btn_fetch = QPushButton("1) Fetch Now")
        self.btn_fetch.setMinimumHeight(38)
        self.btn_fetch.clicked.connect(self._on_fetch)

        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._on_stop_fetch)

        self.btn_shortlist = QPushButton("2) Run Shortlisting on Loaded Articles")
        self.btn_shortlist.setMinimumHeight(34)
        self.btn_shortlist.clicked.connect(self._on_run_shortlisting)

        self.btn_go_browse = QPushButton("3) Browse Results")
        self.btn_go_browse.clicked.connect(lambda: self.tabs.setCurrentWidget(self.tab_browse))

        self.btn_go_analysis = QPushButton("4) Analysis")
        self.btn_go_analysis.clicked.connect(lambda: self.tabs.setCurrentWidget(self.tab_analysis))

        a.addWidget(self.btn_fetch)
        a.addWidget(self.btn_stop)
        a.addSpacing(8)
        a.addWidget(self.btn_shortlist)
        a.addWidget(self.btn_go_browse)
        a.addWidget(self.btn_go_analysis)

        helper_row = QHBoxLayout()
        btn_select_all_sources = QPushButton("Select All Sources")
        btn_clear_sources = QPushButton("Clear Selection")
        btn_select_all_sources.clicked.connect(self._on_select_all_sources)
        btn_clear_sources.clicked.connect(self._on_clear_source_selection)
        helper_row.addWidget(btn_select_all_sources)
        helper_row.addWidget(btn_clear_sources)
        helper_row.addStretch(1)

        right_l.addWidget(controls)
        right_l.addLayout(helper_row)
        right_l.addWidget(actions)
        right_l.addStretch(1)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([650, 650])

        root.addWidget(mgr)
        root.addWidget(self.lbl_kpis)
        root.addWidget(splitter, 1)
        return w

    def _build_browse_tab(self) -> QWidget:
        w = QWidget()
        root = QVBoxLayout(w)

        top = QHBoxLayout()

        self.cmb_country_filter = QComboBox()
        self.cmb_source_filter = QComboBox()
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Search title/summary/content/url...")
        self.chk_only_shortlisted = QCheckBox("Only shortlisted")
        self.chk_only_fulltext = QCheckBox("Only full-text")

        self.cmb_country_filter.currentIndexChanged.connect(self._refresh_browse)
        self.cmb_source_filter.currentIndexChanged.connect(self._refresh_browse)
        self.txt_search.textChanged.connect(self._refresh_browse)
        self.chk_only_shortlisted.stateChanged.connect(self._refresh_browse)
        self.chk_only_fulltext.stateChanged.connect(self._refresh_browse)

        btn_export_csv = QPushButton("Export CSV")
        btn_export_csv.clicked.connect(self._on_export_csv)

        btn_open_storage = QPushButton("Open Storage")
        btn_open_storage.clicked.connect(self._on_open_current_storage)

        top.addWidget(QLabel("Country"))
        top.addWidget(self.cmb_country_filter)
        top.addWidget(QLabel("Source"))
        top.addWidget(self.cmb_source_filter)
        top.addWidget(self.txt_search, 2)
        top.addWidget(self.chk_only_shortlisted)
        top.addWidget(self.chk_only_fulltext)
        top.addWidget(btn_export_csv)
        top.addWidget(btn_open_storage)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.tbl_articles = QTableWidget(0, 8)
        self.tbl_articles.setHorizontalHeaderLabels(
            ["Title", "Country", "Source", "Published", "Full?", "Nat hits", "Threat hits", "Shortlisted?"]
        )
        self.tbl_articles.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl_articles.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl_articles.setSortingEnabled(True)
        self.tbl_articles.itemSelectionChanged.connect(self._on_article_selected)
        self.tbl_articles.itemDoubleClicked.connect(self._on_article_double_click)

        header = self.tbl_articles.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, 8):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)

        self.detail = QTextBrowser()
        self.detail.setReadOnly(True)
        self.detail.setOpenExternalLinks(False)
        self.detail.anchorClicked.connect(lambda url: _open_url(url.toString()))

        splitter.addWidget(self.tbl_articles)
        splitter.addWidget(self.detail)
        splitter.setSizes([900, 500])

        root.addLayout(top)
        root.addWidget(splitter, 1)
        return w

    def _build_analysis_tab(self) -> QWidget:
        w = QWidget()
        root = QVBoxLayout(w)

        top = QHBoxLayout()

        self.btn_compute_layer2 = QPushButton("Compute Layer 2 (R,E,U,K,PrePriority)")
        self.btn_compute_layer2.clicked.connect(self._on_compute_layer2)

        self.cmb_llm_mode = QComboBox()
        self.cmb_llm_mode.addItems(["Shortlisted only", "Top N by PrePriority", "PrePriority >= threshold"])
        self.spin_llm_topn = QSpinBox()
        self.spin_llm_topn.setRange(1, 5000)
        self.spin_llm_topn.setValue(50)

        self.spin_llm_threshold = QSpinBox()
        self.spin_llm_threshold.setRange(0, 100)
        self.spin_llm_threshold.setValue(60)

        self.txt_model_path = QLineEdit()
        self.txt_model_path.setPlaceholderText("Path to GGUF model (qwen2.5-7b-instruct-q4_k_m.gguf)")
        default_model = os.path.join(self.base_dir, "data", "models", "qwen2.5-7b-instruct-q4_k_m.gguf")
        if os.path.isfile(default_model):
            self.txt_model_path.setText(default_model)

        btn_pick_model = QPushButton("Browse Model")
        btn_pick_model.clicked.connect(self._on_pick_model)

        self.btn_run_llm = QPushButton("Run Layer 3 (LLM Threat Scoring)")
        self.btn_run_llm.clicked.connect(self._on_run_llm)

        btn_refresh = QPushButton("Refresh Table")
        btn_refresh.clicked.connect(self._refresh_analysis_table)

        top.addWidget(self.btn_compute_layer2)
        top.addSpacing(10)
        top.addWidget(QLabel("LLM selection"))
        top.addWidget(self.cmb_llm_mode)
        top.addWidget(QLabel("Top N"))
        top.addWidget(self.spin_llm_topn)
        top.addWidget(QLabel("Threshold"))
        top.addWidget(self.spin_llm_threshold)
        top.addSpacing(10)
        top.addWidget(self.txt_model_path, 2)
        top.addWidget(btn_pick_model)
        top.addWidget(self.btn_run_llm)
        top.addWidget(btn_refresh)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.tbl_analysis = QTableWidget(0, 12)
        self.tbl_analysis.setHorizontalHeaderLabels(
            ["Title", "PrePriority", "Bucket", "R", "E", "U", "K", "T", "ThreatLevel", "Vector", "RiskIndex", "Published"]
        )
        self.tbl_analysis.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.tbl_analysis.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.tbl_analysis.setSortingEnabled(True)
        self.tbl_analysis.itemSelectionChanged.connect(self._on_analysis_selected)
        self.tbl_analysis.itemDoubleClicked.connect(self._on_analysis_double_click)

        h = self.tbl_analysis.horizontalHeader()
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, 12):
            h.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)

        self.analysis_detail = QTextBrowser()
        self.analysis_detail.setReadOnly(True)
        self.analysis_detail.setOpenExternalLinks(False)
        self.analysis_detail.anchorClicked.connect(lambda url: _open_url(url.toString()))

        splitter.addWidget(self.tbl_analysis)
        splitter.addWidget(self.analysis_detail)
        splitter.setSizes([950, 450])

        root.addLayout(top)
        root.addWidget(splitter, 1)
        return w

    def _build_sources_tab(self) -> QWidget:
        w = QWidget()
        root = QVBoxLayout(w)

        self.sources_list = QListWidget()
        self.sources_list.currentRowChanged.connect(self._on_sources_row_changed)

        btn_add = QPushButton("Add Source")
        btn_edit = QPushButton("Edit Selected")
        btn_remove = QPushButton("Remove Selected")
        btn_save = QPushButton("Save to data/sources.json")

        btn_add.clicked.connect(self._on_add_source)
        btn_edit.clicked.connect(self._on_edit_source)
        btn_remove.clicked.connect(self._on_remove_source)
        btn_save.clicked.connect(self._on_save_sources)

        btns = QHBoxLayout()
        btns.addWidget(btn_add)
        btns.addWidget(btn_edit)
        btns.addWidget(btn_remove)
        btns.addStretch(1)
        btns.addWidget(btn_save)

        self.source_preview = QPlainTextEdit()
        self.source_preview.setReadOnly(True)

        root.addWidget(self.sources_list, 2)
        root.addLayout(btns)
        root.addWidget(_boxed("Selected Source Preview", self.source_preview), 2)
        return w

    def _build_keywords_tab(self) -> QWidget:
        w = QWidget()
        root = QVBoxLayout(w)

        self.national_editor = QPlainTextEdit()
        self.threat_editor = QPlainTextEdit()

        btn_load = QPushButton("Load keywords")
        btn_save = QPushButton("Save keywords")
        btn_run = QPushButton("Run 2-layer shortlisting on loaded articles")

        btn_load.clicked.connect(self._on_keywords_load)
        btn_save.clicked.connect(self._on_keywords_save)
        btn_run.clicked.connect(self._on_run_shortlisting)

        row = QHBoxLayout()
        row.addWidget(btn_load)
        row.addWidget(btn_save)
        row.addStretch(1)
        row.addWidget(btn_run)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(_boxed("National keywords (Pakistan-related)", self.national_editor))
        split.addWidget(_boxed("Threat keywords (blast/bomb/etc.)", self.threat_editor))
        split.setSizes([600, 600])

        root.addLayout(row)
        root.addWidget(split, 1)
        return w

    def _build_logs_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.addWidget(self.logs_box)
        return w

    # ---------------- UI refresh ----------------
    def refresh_ui(self) -> None:
        self.country_list.clear()
        countries = sorted({s.country for s in self.sources if s.country})
        for c in countries:
            self.country_list.addItem(QListWidgetItem(c))

        self.sources_list.clear()
        for s in sorted(self.sources, key=lambda x: (x.country, x.name)):
            self.sources_list.addItem(f"{s.country} | {s.name} | enabled={s.enabled} | endpoints={len(s.endpoints)}")

        self._refresh_runs_combo()
        self._on_keywords_load()

        runs = list_run_dirs(self.base_dir)
        if runs:
            self.cmb_runs.setCurrentIndex(max(0, self.cmb_runs.count() - 1))
            self._on_load_selected_run("fetched", silent=True)
        else:
            self._on_load_legacy(silent=True)

        self._restore_country_source_selection()
        self._refresh_filters()
        self._refresh_browse()
        self._refresh_analysis_table()
        self._update_kpis()

    def _refresh_runs_combo(self) -> None:
        self.cmb_runs.blockSignals(True)
        self.cmb_runs.clear()
        runs = list_run_dirs(self.base_dir)
        for r in runs:
            self.cmb_runs.addItem(r)
        self.cmb_runs.blockSignals(False)

    # ---------------- Selection helpers ----------------
    def _refresh_sources_for_countries(self) -> None:
        selected_countries = {i.text() for i in self.country_list.selectedItems()}
        if selected_countries:
            self._last_selected_countries = set(selected_countries)

        self.source_list.clear()
        for s in sorted(self.sources, key=lambda x: (x.country, x.name)):
            if selected_countries and s.country not in selected_countries:
                continue
            item = QListWidgetItem(f"{s.country} | {s.name}")
            if not s.enabled:
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
                item.setToolTip("Disabled in sources.json")
            self.source_list.addItem(item)

        for i in range(self.source_list.count()):
            txt = self.source_list.item(i).text()
            if " | " in txt:
                c, n = txt.split(" | ", 1)
                key = (c.strip(), n.strip())
                if key in self._last_selected_sources:
                    self.source_list.item(i).setSelected(True)

    def _selected_sources(self) -> List[Source]:
        chosen: Set[Tuple[str, str]] = set()
        for item in self.source_list.selectedItems():
            txt = item.text()
            if " | " in txt:
                c, n = txt.split(" | ", 1)
                chosen.add((c.strip(), n.strip()))

        if chosen:
            self._last_selected_sources = set(chosen)

        return [s for s in self.sources if (s.country, s.name) in chosen and s.enabled]

    def _restore_country_source_selection(self) -> None:
        if not self._last_selected_countries:
            return
        for i in range(self.country_list.count()):
            it = self.country_list.item(i)
            if it.text() in self._last_selected_countries:
                it.setSelected(True)
        self._refresh_sources_for_countries()

    def _on_select_all_sources(self) -> None:
        for i in range(self.source_list.count()):
            it = self.source_list.item(i)
            if it.flags() & Qt.ItemFlag.ItemIsEnabled:
                it.setSelected(True)

    def _on_clear_source_selection(self) -> None:
        self.source_list.clearSelection()

    # ---------------- Config from UI ----------------
    def _config_from_ui(self) -> Optional[RunConfig]:
        mode = "latest"
        if self.rad_on_date.isChecked():
            mode = "on_date"
        elif self.rad_range.isChecked():
            mode = "range"

        limit_n = int(self.spin_limit.value())
        extract_full = bool(self.chk_fulltext.isChecked())

        on_d = None
        f_d = None
        t_d = None

        if mode == "on_date":
            on_d = _parse_yyyy_mm_dd(self.txt_on_date.text())
            if not on_d:
                QMessageBox.warning(self, "Invalid date", "Enter date as YYYY-MM-DD.")
                return None

        if mode == "range":
            f_d = _parse_yyyy_mm_dd(self.txt_from.text())
            t_d = _parse_yyyy_mm_dd(self.txt_to.text())
            if not f_d and not t_d:
                QMessageBox.warning(self, "Invalid range", "Enter at least one of From/To as YYYY-MM-DD.")
                return None
            if f_d and t_d and f_d > t_d:
                QMessageBox.warning(self, "Invalid range", "From date must be <= To date.")
                return None

        return RunConfig(
            mode=mode,
            limit_items_per_source=limit_n,
            extract_full_text=extract_full,
            on_date=on_d,
            from_date=f_d,
            to_date=t_d,
        )

    # ---------------- Fetch actions ----------------
    def _on_fetch(self) -> None:
        selected = self._selected_sources()
        if not selected:
            QMessageBox.warning(self, "Selection needed", "Select at least one enabled source.")
            return

        cfg = self._config_from_ui()
        if not cfg:
            return

        self.worker_fetch = WorkerFetch(self.base_dir, selected, cfg)
        self.worker_fetch.progress.connect(self._on_worker_progress)
        self.worker_fetch.finished_ok.connect(self._on_worker_fetch_ok)
        self.worker_fetch.finished_fail.connect(self._on_worker_fail)

        self._set_busy(True, "Fetching...")
        self.btn_fetch.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_shortlist.setEnabled(False)
        self.worker_fetch.start()

        self.log("=== FETCH START ===")
        self.log(
            f"Sources selected: {len(selected)} | mode={cfg.mode} | N={cfg.limit_items_per_source} | fulltext={cfg.extract_full_text}"
        )

    def _on_stop_fetch(self) -> None:
        if hasattr(self, "worker_fetch") and self.worker_fetch.isRunning():
            self.worker_fetch.request_stop()
            self.log("Stop requested...")

    def _on_worker_progress(self, msg: str) -> None:
        self.status_label.setText(msg)

    def _on_worker_fetch_ok(self, articles: list, logs: list, run_dir: str) -> None:
        self._set_busy(False, "Fetch complete.")
        self.btn_fetch.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_shortlist.setEnabled(True)

        for line in logs:
            self.log(line)

        self.current_run_dir = run_dir
        self.current_view_subfolder = "fetched"
        self.articles_cache = list(articles)

        self._refresh_runs_combo()
        idx = self.cmb_runs.findText(run_dir)
        if idx >= 0:
            self.cmb_runs.setCurrentIndex(idx)

        self._refresh_filters()
        self._refresh_browse()
        self._refresh_analysis_table()
        self._update_kpis()

        QMessageBox.information(self, "Fetch complete", f"Fetched & saved {len(articles)} items.\nRun: {run_dir}")

    def _on_worker_fail(self, err: str) -> None:
        self._set_busy(False, "Failed.")
        self.btn_fetch.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_shortlist.setEnabled(True)
        self.log(f"ERROR: {err}")
        QMessageBox.critical(self, "Error", err)

    # ---------------- Load runs / legacy ----------------
    def _on_open_selected_run_folder(self) -> None:
        run_dir = self.cmb_runs.currentText().strip() if self.cmb_runs.count() else ""
        if not run_dir or not os.path.isdir(run_dir):
            QMessageBox.warning(self, "No run", "No valid run selected.")
            return
        _open_path_in_file_manager(run_dir)

    def _on_open_current_storage(self) -> None:
        if self.current_run_dir and os.path.isdir(self.current_run_dir):
            _open_path_in_file_manager(self.current_run_dir)
        else:
            _open_path_in_file_manager(os.path.join(self.base_dir, "data", "news"))

    def _on_load_selected_run(self, subfolder: str, silent: bool = False) -> None:
        run_dir = self.cmb_runs.currentText().strip() if self.cmb_runs.count() else ""
        if not run_dir or not os.path.isdir(run_dir):
            if not silent:
                QMessageBox.warning(self, "No run", "No valid run selected.")
            return

        self.current_run_dir = run_dir
        self.current_view_subfolder = subfolder
        self.articles_cache = load_articles_from_run(run_dir, subfolder=subfolder)
        self.log(f"Loaded {len(self.articles_cache)} articles from {run_dir} ({subfolder})")

        self._refresh_filters()
        self._refresh_browse()
        self._refresh_analysis_table()
        self._update_kpis()
        if not silent:
            QMessageBox.information(self, "Loaded", f"Loaded {len(self.articles_cache)} items.")

    def _on_load_legacy(self, silent: bool = False) -> None:
        self.current_run_dir = None
        self.current_view_subfolder = "legacy"
        self.articles_cache = load_all_articles_legacy(self.base_dir)
        self.log("Loaded legacy articles from data/news")

        self._refresh_filters()
        self._refresh_browse()
        self._refresh_analysis_table()
        self._update_kpis()
        if not silent:
            QMessageBox.information(self, "Loaded", f"Loaded {len(self.articles_cache)} legacy items.")

    # ---------------- Keywords actions ----------------
    def _on_keywords_load(self) -> None:
        nat = load_keywords_national(self.base_dir)
        thr = load_keywords_threat(self.base_dir)
        self.national_editor.setPlainText("\n".join(nat))
        self.threat_editor.setPlainText("\n".join(thr))

    def _on_keywords_save(self) -> None:
        nat_lines = [x.strip() for x in self.national_editor.toPlainText().splitlines() if x.strip()]
        thr_lines = [x.strip() for x in self.threat_editor.toPlainText().splitlines() if x.strip()]
        save_keywords_national(self.base_dir, nat_lines)
        save_keywords_threat(self.base_dir, thr_lines)
        QMessageBox.information(self, "Saved", "Saved keywords_national.json and keywords_threat.json")
        self.log("Saved keyword JSON files.")

    def _on_run_shortlisting(self) -> None:
        if not self.articles_cache:
            QMessageBox.warning(self, "No data", "Load or fetch articles first.")
            return

        nat = [x.strip() for x in self.national_editor.toPlainText().splitlines() if x.strip()]
        thr = [x.strip() for x in self.threat_editor.toPlainText().splitlines() if x.strip()]

        res: ShortlistResult = shortlist_articles_two_layer(self.articles_cache, nat, thr)
        self.articles_cache = res.articles_all

        if self.current_run_dir and os.path.isdir(self.current_run_dir):
            _save_articles_grouped(self.current_run_dir, "fetched", self.articles_cache)
            shortlisted_only = [a for a in self.articles_cache if _is_shortlisted(a)]
            _save_articles_grouped(self.current_run_dir, "shortlisted", shortlisted_only)
            self.log(f"Saved shortlisted items to: {self.current_run_dir}/shortlisted")
        else:
            save_articles_country_source(self.base_dir, self.articles_cache)
            self.log("Saved to legacy data/news (no run selected)")

        QMessageBox.information(
            self,
            "Shortlisting done",
            f"National-pass: {len(res.national_pass)}\nThreat-pass: {len(res.threat_pass)}",
        )

        self._refresh_filters()
        self._refresh_browse()
        self._refresh_analysis_table()
        self._update_kpis()
        self.tabs.setCurrentWidget(self.tab_browse)

    # ---------------- Analysis tab actions ----------------
    def _on_pick_model(self) -> None:
        start_dir = os.path.join(self.base_dir, "data", "models")
        os.makedirs(start_dir, exist_ok=True)
        path, _ = QFileDialog.getOpenFileName(self, "Select GGUF Model", start_dir, "GGUF files (*.gguf)")
        if path:
            self.txt_model_path.setText(path)

    def _on_compute_layer2(self) -> None:
        if not self.articles_cache:
            QMessageBox.warning(self, "No data", "Load or fetch articles first.")
            return
        if not HAS_ANALYSIS or al is None or not hasattr(al, "compute_layer2_scores"):
            QMessageBox.critical(self, "Missing module", "analysis_layers.py is not ready yet.")
            return

        al.compute_layer2_scores(self.articles_cache)

        self.log("[ANALYSIS] Computed Layer 2 scores for loaded articles.")
        self._refresh_analysis_table()

        if self.current_run_dir and os.path.isdir(self.current_run_dir):
            _save_articles_grouped(self.current_run_dir, self.current_view_subfolder, self.articles_cache)
            self.log("[ANALYSIS] Saved Layer 2 results into current run storage.")

        QMessageBox.information(self, "Layer 2 complete", "Computed R, E, U, K, PrePriority for loaded articles.")

    def _on_run_llm(self) -> None:
        if not self.articles_cache:
            QMessageBox.warning(self, "No data", "Load or fetch articles first.")
            return
        if not HAS_ANALYSIS or al is None or not hasattr(al, "select_articles_for_llm"):
            QMessageBox.critical(self, "Missing module", "analysis_layers.py is not ready yet.")
            return

        model_path = (self.txt_model_path.text() or "").strip()
        if not model_path:
            QMessageBox.warning(self, "Model path missing", "Select the GGUF model file.")
            return
        if not os.path.isfile(model_path):
            QMessageBox.warning(self, "Model not found", f"File not found:\n{model_path}")
            return

        mode_txt = self.cmb_llm_mode.currentText()
        mode = "shortlisted"
        if "Top N" in mode_txt:
            mode = "top_n"
        elif "threshold" in mode_txt.lower():
            mode = "threshold"

        top_n = int(self.spin_llm_topn.value())
        threshold = float(self.spin_llm_threshold.value())

        chosen = al.select_articles_for_llm(self.articles_cache, mode=mode, top_n=top_n, threshold=threshold)
        if not chosen:
            QMessageBox.information(self, "Nothing selected", "No articles matched your LLM selection criteria.")
            return

        self.worker_llm = WorkerLLM(chosen, model_path)
        self.worker_llm.progress.connect(self._on_llm_progress)
        self.worker_llm.finished_ok.connect(self._on_llm_done)
        self.worker_llm.finished_fail.connect(self._on_llm_fail)

        self._set_busy(True, "Running LLM scoring...")
        self.btn_run_llm.setEnabled(False)
        self.btn_compute_layer2.setEnabled(False)
        self.worker_llm.start()

        self.log(f"[LLM] Starting Layer 3 scoring on {len(chosen)} articles.")
        self.tabs.setCurrentWidget(self.tab_analysis)

    def _on_llm_progress(self, msg: str) -> None:
        self.status_label.setText(msg)
        self.log(msg)


    def _on_llm_done(self, n: int) -> None:
        self._set_busy(False, "LLM complete.")
        self.btn_run_llm.setEnabled(True)
        self.btn_compute_layer2.setEnabled(True)

        self.log(f"[LLM] Completed threat scoring on {n} articles.")
        self._refresh_analysis_table()

        if self.current_run_dir and os.path.isdir(self.current_run_dir):
            _save_articles_grouped(self.current_run_dir, self.current_view_subfolder, self.articles_cache)
            self.log("[LLM] Saved Layer 3 results into current run storage.")

        QMessageBox.information(self, "LLM complete", f"Threat scoring complete for {n} articles.")

    def _on_llm_fail(self, err: str) -> None:
        self._set_busy(False, "LLM failed.")
        self.btn_run_llm.setEnabled(True)
        self.btn_compute_layer2.setEnabled(True)
        self.log(f"[LLM] ERROR: {err}")
        QMessageBox.critical(self, "LLM Error", err)

    def _refresh_analysis_table(self) -> None:
        items = list(self.articles_cache)

        def pre(a: Article) -> float:
            v = getattr(a, "prepriority_score", None)
            try:
                return float(v) if v is not None else -1.0
            except Exception:
                return -1.0

        items.sort(key=pre, reverse=True)

        was_sorting = self.tbl_analysis.isSortingEnabled()
        self.tbl_analysis.setSortingEnabled(False)

        try:
            self.tbl_analysis.clearContents()
            self.tbl_analysis.setRowCount(len(items))

            for row, a in enumerate(items):
                title = a.title if a.title and a.title != a.url else (a.url or "")
                pre_v = getattr(a, "prepriority_score", None)
                bucket = getattr(a, "prepriority_bucket", None) or _bucket_from_prepriority(pre_v)
                r = getattr(a, "relevance_score", None)
                e = getattr(a, "evidence_numeric", None)
                u = getattr(a, "urgency_score", None)
                k = getattr(a, "keyword_intensity", None)
                t = getattr(a, "threat_score", None)
                lvl = getattr(a, "threat_level", None) or ""
                vec = getattr(a, "threat_vector", None) or ""
                risk = getattr(a, "risk_index", None)

                it_title = QTableWidgetItem(title)
                it_title.setData(Qt.ItemDataRole.UserRole, a)
                it_title.setData(Qt.ItemDataRole.UserRole + 1, a.url or "")

                def _fmt(x) -> str:
                    if x is None:
                        return ""
                    try:
                        if isinstance(x, (int, float)):
                            return f"{float(x):.1f}"
                    except Exception:
                        pass
                    return str(x)

                self.tbl_analysis.setItem(row, 0, it_title)
                self.tbl_analysis.setItem(row, 1, QTableWidgetItem(_fmt(pre_v)))
                self.tbl_analysis.setItem(row, 2, QTableWidgetItem(str(bucket)))
                self.tbl_analysis.setItem(row, 3, QTableWidgetItem(_fmt(r)))
                self.tbl_analysis.setItem(row, 4, QTableWidgetItem(_fmt(e)))
                self.tbl_analysis.setItem(row, 5, QTableWidgetItem(_fmt(u)))
                self.tbl_analysis.setItem(row, 6, QTableWidgetItem(_fmt(k)))
                self.tbl_analysis.setItem(row, 7, QTableWidgetItem(_fmt(t)))
                self.tbl_analysis.setItem(row, 8, QTableWidgetItem(str(lvl)))
                self.tbl_analysis.setItem(row, 9, QTableWidgetItem(str(vec)))
                self.tbl_analysis.setItem(row, 10, QTableWidgetItem(_fmt(risk)))
                self.tbl_analysis.setItem(row, 11, QTableWidgetItem(a.published_at or ""))

            self.tbl_analysis.resizeRowsToContents()
        finally:
            self.tbl_analysis.setSortingEnabled(was_sorting)

    def _on_analysis_selected(self) -> None:
        rows = self.tbl_analysis.selectionModel().selectedRows()
        if not rows:
            self.analysis_detail.setHtml("")
            return

        row = rows[0].row()
        item = self.tbl_analysis.item(row, 0)
        if not item:
            self.analysis_detail.setHtml("<i>No item selected.</i>")
            return

        a_obj = item.data(Qt.ItemDataRole.UserRole)
        a: Optional[Article] = a_obj if isinstance(a_obj, Article) else None
        if a is None:
            self.analysis_detail.setHtml("<b>Could not load this article.</b>")
            return

        nat_hits = _get_kw_nat(a)
        thr_hits = _get_kw_thr(a)
        shortlisted = _is_shortlisted(a)

        lines: List[str] = []
        lines.append(a.title or a.url or "")
        lines.append("")
        lines.append(f"Country: {a.country}")
        lines.append(f"Source: {a.source_name}")
        lines.append(f"Published: {a.published_at}")
        lines.append(f"Shortlisted: {'YES' if shortlisted else 'NO'}")
        lines.append(f"URL: {a.url}")
        lines.append("")

        lines.append("Layer 2:")
        lines.append(f"  Relevance (R): {getattr(a, 'relevance_score', None)}")
        lines.append(f"  Evidence: {getattr(a, 'evidence_strength', None)} ({getattr(a, 'evidence_numeric', None)})")
        lines.append(f"  Urgency (U): {getattr(a, 'urgency_score', None)}")
        lines.append(f"  Keyword intensity (K): {getattr(a, 'keyword_intensity', None)}")
        lines.append(f"  PrePriority: {getattr(a, 'prepriority_score', None)} ({getattr(a, 'prepriority_bucket', None)})")
        lines.append("")

        lines.append("Layer 3 (LLM):")
        lines.append(f"  Threat score (T): {getattr(a, 'threat_score', None)}")
        lines.append(f"  Threat level: {getattr(a, 'threat_level', None)}")
        lines.append(f"  Threat vector: {getattr(a, 'threat_vector', None)}")
        one_liner = getattr(a, "one_liner_threat", None) or ""
        if one_liner:
            lines.append(f"  One-liner: {one_liner}")
        reasons = getattr(a, "reasons", None) or []
        if reasons:
            lines.append("  Reasons:")
            for r in reasons[:6]:
                lines.append(f"    - {r}")
        lines.append("")

        lines.append(f"Final RiskIndex: {getattr(a, 'risk_index', None)}")
        lines.append("")

        if nat_hits:
            lines.append(f"National hits ({len(nat_hits)}): {', '.join(nat_hits[:80])}")
            lines.append("")
        if thr_hits:
            lines.append(f"Threat hits ({len(thr_hits)}): {', '.join(thr_hits[:80])}")
            lines.append("")

        lines.append("CONTENT:")
        lines.append("")
        lines.append(a.content_text or a.summary or "[No content extracted]")

        content = "\n".join(lines)
        url = (a.url or "").strip()
        esc = html.escape(content)
        if url:
            url_esc = html.escape(url)
            esc = esc.replace(f"URL: {url_esc}", f"URL: <a href='{url_esc}'>{url_esc}</a>")
        self.analysis_detail.setHtml(f"<pre style='white-space: pre-wrap;'>{esc}</pre>")

    def _on_analysis_double_click(self, item: QTableWidgetItem) -> None:
        if item.column() != 0:
            return
        url = item.data(Qt.ItemDataRole.UserRole + 1)
        if isinstance(url, str) and url.strip():
            _open_url(url.strip())

    # ---------------- Browse tab ----------------
    def _refresh_filters(self) -> None:
        countries = sorted({a.country for a in self.articles_cache if a.country})
        sources = sorted({a.source_name for a in self.articles_cache if a.source_name})

        self.cmb_country_filter.blockSignals(True)
        self.cmb_source_filter.blockSignals(True)

        cur_c = self.cmb_country_filter.currentText() if self.cmb_country_filter.count() else "ALL"
        cur_s = self.cmb_source_filter.currentText() if self.cmb_source_filter.count() else "ALL"

        self.cmb_country_filter.clear()
        self.cmb_country_filter.addItem("ALL")
        for c in countries:
            self.cmb_country_filter.addItem(c)

        self.cmb_source_filter.clear()
        self.cmb_source_filter.addItem("ALL")
        for s in sources:
            self.cmb_source_filter.addItem(s)

        if cur_c and self.cmb_country_filter.findText(cur_c) >= 0:
            self.cmb_country_filter.setCurrentText(cur_c)
        if cur_s and self.cmb_source_filter.findText(cur_s) >= 0:
            self.cmb_source_filter.setCurrentText(cur_s)

        self.cmb_country_filter.blockSignals(False)
        self.cmb_source_filter.blockSignals(False)

    def _refresh_browse(self) -> None:
        items = list(self.articles_cache)

        c = self.cmb_country_filter.currentText() if self.cmb_country_filter.count() else "ALL"
        s = self.cmb_source_filter.currentText() if self.cmb_source_filter.count() else "ALL"
        q = (self.txt_search.text() or "").strip().lower()
        only_short = self.chk_only_shortlisted.isChecked()
        only_full = self.chk_only_fulltext.isChecked()

        if c != "ALL":
            items = [a for a in items if a.country == c]
        if s != "ALL":
            items = [a for a in items if a.source_name == s]

        if only_short:
            items = [a for a in items if _is_shortlisted(a)]

        if only_full:
            items = [a for a in items if a.content_text and len(a.content_text) > 200]

        if q:
            def ok(a: Article) -> bool:
                hay = " ".join([a.title or "", a.summary or "", a.content_text or "", a.url or ""]).lower()
                return q in hay
            items = [a for a in items if ok(a)]

        was_sorting = self.tbl_articles.isSortingEnabled()
        self.tbl_articles.setSortingEnabled(False)

        try:
            self.tbl_articles.clearContents()
            self.tbl_articles.setRowCount(len(items))

            for row, a in enumerate(items):
                title = a.title if a.title and a.title != a.url else (a.url or "")
                full = "YES" if a.content_text and len(a.content_text) > 200 else "NO"

                nat_hits = _get_kw_nat(a)
                thr_hits = _get_kw_thr(a)
                shortlisted = _is_shortlisted(a)

                it_title = QTableWidgetItem(title)
                it_title.setData(Qt.ItemDataRole.UserRole, a)
                it_title.setData(Qt.ItemDataRole.UserRole + 1, a.url or "")

                self.tbl_articles.setItem(row, 0, it_title)
                self.tbl_articles.setItem(row, 1, QTableWidgetItem(a.country or ""))
                self.tbl_articles.setItem(row, 2, QTableWidgetItem(a.source_name or ""))
                self.tbl_articles.setItem(row, 3, QTableWidgetItem(a.published_at or ""))
                self.tbl_articles.setItem(row, 4, QTableWidgetItem(full))
                self.tbl_articles.setItem(row, 5, QTableWidgetItem(str(len(nat_hits))))
                self.tbl_articles.setItem(row, 6, QTableWidgetItem(str(len(thr_hits))))
                self.tbl_articles.setItem(row, 7, QTableWidgetItem("YES" if shortlisted else "NO"))

            self.tbl_articles.resizeRowsToContents()
        finally:
            self.tbl_articles.setSortingEnabled(was_sorting)

    def _on_article_selected(self) -> None:
        rows = self.tbl_articles.selectionModel().selectedRows()
        if not rows:
            self.detail.setHtml("")
            return

        row = rows[0].row()
        item = self.tbl_articles.item(row, 0)
        if not item:
            self.detail.setHtml("<i>No item selected.</i>")
            return

        a_obj = item.data(Qt.ItemDataRole.UserRole)
        a: Optional[Article] = a_obj if isinstance(a_obj, Article) else None
        if a is None:
            self.detail.setHtml("<b>Could not load this article.</b>")
            return

        nat_hits = _get_kw_nat(a)
        thr_hits = _get_kw_thr(a)
        shortlisted = _is_shortlisted(a)

        lines: List[str] = []
        lines.append(a.title or a.url or "")
        lines.append("")
        lines.append(f"Country: {a.country}")
        lines.append(f"Source: {a.source_name}")
        lines.append(f"Published: {a.published_at}")
        lines.append(f"Author: {a.author}")
        lines.append(f"Shortlisted: {'YES' if shortlisted else 'NO'}")
        lines.append(f"URL: {a.url}")
        lines.append("")

        if nat_hits:
            lines.append(f"National hits ({len(nat_hits)}): {', '.join(nat_hits[:80])}")
            lines.append("")
        if thr_hits:
            lines.append(f"Threat hits ({len(thr_hits)}): {', '.join(thr_hits[:80])}")
            lines.append("")

        if a.extraction_notes:
            lines.append("Extraction notes:")
            for n in a.extraction_notes[:12]:
                lines.append(f"  - {n}")
            lines.append("")

        lines.append("CONTENT:")
        lines.append("")
        lines.append(a.content_text or a.summary or "[No content extracted]")

        content = "\n".join(lines)
        url = (a.url or "").strip()
        esc = html.escape(content)
        if url:
            url_esc = html.escape(url)
            esc = esc.replace(f"URL: {url_esc}", f"URL: <a href='{url_esc}'>{url_esc}</a>")
        self.detail.setHtml(f"<pre style='white-space: pre-wrap;'>{esc}</pre>")

    def _on_article_double_click(self, item: QTableWidgetItem) -> None:
        if item.column() != 0:
            return
        url = item.data(Qt.ItemDataRole.UserRole + 1)
        if isinstance(url, str) and url.strip():
            _open_url(url.strip())

    def _on_export_csv(self) -> None:
        if not self.articles_cache:
            QMessageBox.warning(self, "No data", "Nothing to export.")
            return

        default_name = "export.csv"
        if self.current_run_dir and os.path.isdir(self.current_run_dir):
            default_path = os.path.join(self.current_run_dir, default_name)
        else:
            default_path = os.path.join(self.base_dir, "data", default_name)

        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", default_path, "CSV files (*.csv)")
        if not path:
            return

        ids: List[str] = []
        for r in range(self.tbl_articles.rowCount()):
            it = self.tbl_articles.item(r, 0)
            if not it:
                continue
            a_obj = it.data(Qt.ItemDataRole.UserRole)
            if isinstance(a_obj, Article) and a_obj.id:
                ids.append(a_obj.id)

        idset = set(ids)
        rows = [a for a in self.articles_cache if a.id in idset] if idset else list(self.articles_cache)

        try:
            with open(path, "w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(
                    [
                        "title",
                        "country",
                        "source",
                        "published_at",
                        "url",
                        "shortlisted",
                        "national_hits",
                        "threat_hits",
                        "content_length",
                        "relevance_score",
                        "evidence_strength",
                        "evidence_numeric",
                        "urgency_score",
                        "keyword_intensity",
                        "prepriority_score",
                        "prepriority_bucket",
                        "threat_score",
                        "threat_level",
                        "threat_vector",
                        "one_liner_threat",
                        "reasons",
                        "risk_index",
                    ]
                )
                for a in rows:
                    nat_hits = _get_kw_nat(a)
                    thr_hits = _get_kw_thr(a)
                    shortlisted = _is_shortlisted(a)

                    reasons = getattr(a, "reasons", None) or []
                    w.writerow(
                        [
                            a.title or "",
                            a.country or "",
                            a.source_name or "",
                            a.published_at or "",
                            a.url or "",
                            "YES" if shortlisted else "NO",
                            ";".join(nat_hits),
                            ";".join(thr_hits),
                            str(len(a.content_text or "")),
                            getattr(a, "relevance_score", None),
                            getattr(a, "evidence_strength", None),
                            getattr(a, "evidence_numeric", None),
                            getattr(a, "urgency_score", None),
                            getattr(a, "keyword_intensity", None),
                            getattr(a, "prepriority_score", None),
                            getattr(a, "prepriority_bucket", None),
                            getattr(a, "threat_score", None),
                            getattr(a, "threat_level", None),
                            getattr(a, "threat_vector", None),
                            getattr(a, "one_liner_threat", None),
                            " | ".join([str(x) for x in reasons]),
                            getattr(a, "risk_index", None),
                        ]
                    )
            QMessageBox.information(self, "Exported", f"Saved CSV:\n{path}")
        except Exception as ex:
            QMessageBox.critical(self, "Export failed", f"{type(ex).__name__}: {ex}")

    # ---------------- KPI/Stats ----------------
    def _update_kpis(self) -> None:
        total = len(self.articles_cache)
        shortlisted = sum(1 for a in self.articles_cache if _is_shortlisted(a))
        fulltext = sum(1 for a in self.articles_cache if a.content_text and len(a.content_text) > 200)

        storage_hint = self.current_run_dir or "LEGACY:data/news"
        view = self.current_view_subfolder

        self.lbl_kpis.setText(
            f"Loaded: {total} | Shortlisted: {shortlisted} | Full-text: {fulltext} | View: {view} | Storage: {storage_hint}"
        )

    # ---------------- Sources tab actions ----------------
    def _on_sources_row_changed(self, row: int) -> None:
        ordered = sorted(self.sources, key=lambda x: (x.country, x.name))
        if row < 0 or row >= len(ordered):
            self.source_preview.setPlainText("")
            return
        s = ordered[row]
        lines = [
            f"Country: {s.country}",
            f"Name: {s.name}",
            f"Enabled: {s.enabled}",
            "Endpoints:",
        ]
        for ep in s.endpoints:
            lines.append(f"  - {ep.type} | enabled={ep.enabled} | {ep.url} | {ep.note}")
        self.source_preview.setPlainText("\n".join(lines))

    def _on_add_source(self) -> None:
        d = SourceEditorDialog(self, None)
        if d.exec() == QDialog.DialogCode.Accepted:
            s = d.get_source()
            if not s.country or not s.name:
                QMessageBox.warning(self, "Invalid", "Country and Source Name are required.")
                return
            self.sources.append(s)
            self.refresh_ui()

    def _on_edit_source(self) -> None:
        row = self.sources_list.currentRow()
        if row < 0:
            return
        ordered = sorted(self.sources, key=lambda x: (x.country, x.name))
        selected = ordered[row]
        d = SourceEditorDialog(self, selected)
        if d.exec() == QDialog.DialogCode.Accepted:
            new_s = d.get_source()
            for i, s in enumerate(self.sources):
                if s is selected:
                    self.sources[i] = new_s
                    break
            self.refresh_ui()

    def _on_remove_source(self) -> None:
        row = self.sources_list.currentRow()
        if row < 0:
            return
        ordered = sorted(self.sources, key=lambda x: (x.country, x.name))
        selected = ordered[row]
        self.sources = [s for s in self.sources if s is not selected]
        self.refresh_ui()

    def _on_save_sources(self) -> None:
        save_sources(self.base_dir, self.sources)
        QMessageBox.information(self, "Saved", "Saved to data/sources.json")
        self.log("Saved sources.json")


# -----------------------
# Optional: standalone run
# -----------------------
def run_gui(base_dir: Optional[str] = None) -> None:
    base_dir = base_dir or os.getcwd()
    app = QApplication([])
    app.setApplicationName(APP_TITLE)
    win = MainWindow(base_dir)
    win.resize(1400, 850)
    win.show()
    app.exec()
