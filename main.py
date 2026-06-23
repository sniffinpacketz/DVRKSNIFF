"""
DVRKSNIFF v2 — Advanced Network Intelligence Tool
Credited to @botnet1337 on IG
"""

import sys
import os
import json
import threading
import socket
import time
from datetime import datetime
from pathlib import Path

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTableWidget, QTableWidgetItem, QPushButton, QLabel,
    QLineEdit, QComboBox, QTextEdit, QSplitter, QFileDialog,
    QColorDialog, QSpinBox, QCheckBox, QGroupBox, QFormLayout,
    QProgressBar, QHeaderView, QStatusBar, QMessageBox, QFrame,
    QSlider, QScrollArea, QGridLayout, QSizePolicy
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import (
    QFont, QColor, QPixmap, QMovie, QPainter, QLinearGradient, QIcon
)

from profiles import SNIFFER_PROFILES
from engine import (
    SnifferEngine, get_adapters,
    icmp_ping, scan_ports, geoip_lookup, ssh_run
)

SETTINGS_FILE = Path.home() / ".dvrksniff_settings.json"
DEFAULT_SETTINGS = {
    "accent":       "#cc0000",
    "accent2":      "#ff3333",
    "bg_color":     "#0a0000",
    "bg_image":     "",
    "font_size":    10,
    "max_packets":  2000,
}


def load_settings():
    if SETTINGS_FILE.exists():
        try:
            s = DEFAULT_SETTINGS.copy()
            s.update(json.load(open(SETTINGS_FILE)))
            return s
        except Exception:
            pass
    return DEFAULT_SETTINGS.copy()


def save_settings(s):
    json.dump(s, open(SETTINGS_FILE, "w"), indent=2)


# ── Worker threads ─────────────────────────────────────────────────────────────

class PingWorker(QThread):
    result = pyqtSignal(list)
    def __init__(self, host, count):
        super().__init__()
        self.host = host; self.count = count
    def run(self):
        self.result.emit(icmp_ping(self.host, self.count))


class ScanWorker(QThread):
    progress = pyqtSignal(int, int, int)
    result   = pyqtSignal(list)
    def __init__(self, host, ports, timeout):
        super().__init__()
        self.host = host; self.ports = ports; self.timeout = timeout
    def run(self):
        self.result.emit(
            scan_ports(self.host, self.ports, self.timeout,
                       on_progress=lambda i,t,p: self.progress.emit(i,t,p))
        )


class GeoWorker(QThread):
    result = pyqtSignal(dict)
    def __init__(self, ip):
        super().__init__()
        self.ip = ip
    def run(self):
        self.result.emit(geoip_lookup(self.ip))


class SSHWorker(QThread):
    output = pyqtSignal(str, str)   # stdout, stderr
    error  = pyqtSignal(str)
    def __init__(self, host, user, password, port, command, key_path=""):
        super().__init__()
        self.host = host; self.user = user; self.password = password
        self.port = port; self.command = command; self.key_path = key_path
    def run(self):
        out, err, error = ssh_run(
            self.host, self.user, self.password,
            self.port, self.command, self.key_path
        )
        if error:
            self.error.emit(error)
        else:
            self.output.emit(out, err)


# ── Background Widget ──────────────────────────────────────────────────────────

class BackgroundWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._pixmap  = None
        self._movie   = None
        self._bg      = QColor("#0a0000")
        self._accent  = QColor("#cc0000")

    def set_bg_color(self, h):
        self._bg = QColor(h); self.update()

    def set_accent(self, h):
        self._accent = QColor(h); self.update()

    def set_image(self, path):
        self._pixmap = None
        self._movie  = None
        if not path:
            self.update(); return
        if path.lower().endswith(".gif"):
            self._movie = QMovie(path)
            self._movie.frameChanged.connect(lambda _: self.update())
            self._movie.start()
        else:
            self._pixmap = QPixmap(path)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        if self._movie and self._movie.isValid():
            frame = self._movie.currentPixmap()
            if not frame.isNull():
                p.drawPixmap(self.rect(), frame.scaled(
                    self.size(),
                    Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                    Qt.TransformationMode.SmoothTransformation))
            else:
                self._fill_gradient(p)
        elif self._pixmap and not self._pixmap.isNull():
            p.drawPixmap(self.rect(), self._pixmap.scaled(
                self.size(),
                Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation))
        else:
            self._fill_gradient(p)
        # Dark vignette for readability
        v = QLinearGradient(0, 0, 0, self.height())
        v.setColorAt(0,   QColor(0,0,0,170))
        v.setColorAt(0.5, QColor(0,0,0,60))
        v.setColorAt(1,   QColor(0,0,0,190))
        p.fillRect(self.rect(), v)
        p.end()

    def _fill_gradient(self, p):
        g = QLinearGradient(0, 0, 0, self.height())
        g.setColorAt(0,   self._bg)
        g.setColorAt(0.6, QColor("#100000"))
        g.setColorAt(1,   QColor("#000000"))
        p.fillRect(self.rect(), g)


# ── Main Window ────────────────────────────────────────────────────────────────

class DVRKSniff(QMainWindow):
    _pkt_sig    = pyqtSignal(dict)
    _status_sig = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.settings   = load_settings()
        self.engine     = SnifferEngine(
            on_packet=lambda p: self._pkt_sig.emit(p),
            on_status=lambda s: self._status_sig.emit(s),
        )
        self._pkt_sig.connect(self._on_packet)
        self._status_sig.connect(self._on_status)

        self.captured_ips = {}
        self.saved_ips    = []
        self._total_pkts  = 0
        self._total_bytes = 0
        self._adapters    = []

        self._init_ui()
        self._apply_theme()
        if self.settings.get("bg_image"):
            self._bg.set_image(self.settings["bg_image"])
        self._load_stored_ips()
        self._refresh_adapters()

    # ── UI Construction ────────────────────────────────────────────────────────

    def _init_ui(self):
        self.setWindowTitle("DVRKSNIFF v2  ·  @botnet1337")
        self.setMinimumSize(1300, 820)
        self.resize(1500, 950)

        icon_path = os.path.join(
            getattr(sys, "_MEIPASS", os.path.dirname(__file__)), "icon.ico"
        )
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self._bg = BackgroundWidget(self)
        self.setCentralWidget(self._bg)

        root = QVBoxLayout(self._bg)
        root.setContentsMargins(8, 6, 8, 6)
        root.setSpacing(4)

        # Header
        hdr = QHBoxLayout()
        self._title_lbl  = QLabel("◈ DVRKSNIFF")
        self._title_lbl.setFont(QFont("Consolas", 22, QFont.Weight.Bold))
        self._credit_lbl = QLabel("@botnet1337")
        self._credit_lbl.setFont(QFont("Consolas", 11))
        self._status_lbl = QLabel("● IDLE")
        self._status_lbl.setFont(QFont("Consolas", 10))
        hdr.addWidget(self._title_lbl)
        hdr.addWidget(self._credit_lbl)
        hdr.addStretch()
        hdr.addWidget(self._status_lbl)
        root.addLayout(hdr)

        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        self._tabs.setFont(QFont("Consolas", 10))
        root.addWidget(self._tabs)

        self._build_sniffer_tab()
        self._build_peers_tab()
        self._build_ip_log_tab()
        self._build_pinger_tab()
        self._build_portscanner_tab()
        self._build_geo_tab()
        self._build_storage_tab()
        self._build_ssh_tab()
        self._build_theme_tab()

    # ── Sniffer Tab ────────────────────────────────────────────────────────────

    def _build_sniffer_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)
        lay.setSpacing(5)

        # Row 1 — adapter + profile
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Adapter:"))
        self._adapter_combo = QComboBox()
        self._adapter_combo.setFont(QFont("Consolas", 10))
        self._adapter_combo.setMinimumWidth(280)
        btn_refresh = QPushButton("↻")
        btn_refresh.setFixedWidth(30)
        btn_refresh.setToolTip("Refresh adapter list")
        btn_refresh.clicked.connect(self._refresh_adapters)
        row1.addWidget(self._adapter_combo, 3)
        row1.addWidget(btn_refresh)

        row1.addWidget(QLabel("  Profile:"))
        self._profile_combo = QComboBox()
        self._profile_combo.addItems(list(SNIFFER_PROFILES.keys()))
        self._profile_combo.setFont(QFont("Consolas", 10))
        self._profile_combo.currentTextChanged.connect(self._on_profile_change)
        row1.addWidget(self._profile_combo, 3)
        lay.addLayout(row1)

        # Row 2 — filter + controls
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Filter:"))
        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("WinDivert filter — e.g.  udp and ip.SrcPort == 6672")
        self._filter_edit.setFont(QFont("Consolas", 10))
        row2.addWidget(self._filter_edit, 4)

        self._start_btn = QPushButton("▶  START")
        self._start_btn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        self._start_btn.setFixedWidth(110)
        self._start_btn.clicked.connect(self._toggle_sniff)
        self._clear_btn = QPushButton("✕  CLEAR")
        self._clear_btn.setFont(QFont("Consolas", 10))
        self._clear_btn.clicked.connect(self._clear_packets)
        self._export_btn = QPushButton("⬇  EXPORT")
        self._export_btn.setFont(QFont("Consolas", 10))
        self._export_btn.clicked.connect(self._export_packets)
        row2.addWidget(self._start_btn)
        row2.addWidget(self._clear_btn)
        row2.addWidget(self._export_btn)
        lay.addLayout(row2)

        self._profile_desc = QLabel("")
        self._profile_desc.setFont(QFont("Consolas", 9))
        lay.addWidget(self._profile_desc)

        # Splitter: packet table | IP summary
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self._pkt_table = QTableWidget(0, 8)
        self._pkt_table.setHorizontalHeaderLabels(
            ["Time", "Dir", "Proto", "Source IP", "SPort", "Dest IP", "DPort", "Bytes"])
        self._pkt_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._pkt_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._pkt_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._pkt_table.setFont(QFont("Consolas", 9))
        self._pkt_table.verticalHeader().setVisible(False)
        self._pkt_table.setAlternatingRowColors(True)
        self._pkt_table.cellDoubleClicked.connect(self._pkt_double_click)
        splitter.addWidget(self._pkt_table)

        ip_panel = QWidget()
        ip_lay   = QVBoxLayout(ip_panel)
        ip_lay.setSpacing(4)
        ip_lay.addWidget(QLabel("Unique Remote IPs"))
        self._ip_table = QTableWidget(0, 3)
        self._ip_table.setHorizontalHeaderLabels(["IP Address", "Pkts", "Last"])
        self._ip_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._ip_table.setFont(QFont("Consolas", 9))
        self._ip_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._ip_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._ip_table.verticalHeader().setVisible(False)
        ip_lay.addWidget(self._ip_table)

        ip_btns = QHBoxLayout()
        for lbl, fn in [("🌍 GeoIP", self._quick_geo),
                         ("💾 Save", self._save_selected_ip),
                         ("📡 Ping", self._quick_ping),
                         ("🔍 Scan", self._quick_scan)]:
            b = QPushButton(lbl)
            b.setFont(QFont("Consolas", 9))
            b.clicked.connect(fn)
            ip_btns.addWidget(b)
        ip_lay.addLayout(ip_btns)
        splitter.addWidget(ip_panel)
        splitter.setSizes([900, 360])
        lay.addWidget(splitter)

        # Stats
        stats = QHBoxLayout()
        self._pkt_count_lbl = QLabel("Packets: 0")
        self._ip_count_lbl  = QLabel("IPs: 0")
        self._bytes_lbl     = QLabel("Bytes: 0")
        self._mode_lbl      = QLabel("IDLE")
        for w in [self._pkt_count_lbl, self._ip_count_lbl,
                  self._bytes_lbl, self._mode_lbl]:
            w.setFont(QFont("Consolas", 9))
            stats.addWidget(w)
        stats.addStretch()
        lay.addLayout(stats)

        self._tabs.addTab(tab, "⚡ SNIFFER")
        self._on_profile_change(self._profile_combo.currentText())

    # ── Peers Tab (P2P focus) ──────────────────────────────────────────────────

    def _build_peers_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)

        info = QLabel(
            "P2P Peer IPs detected in your session — these are real remote players/callers "
            "connecting directly to your machine. Double-click to GeoIP."
        )
        info.setFont(QFont("Consolas", 9))
        info.setWordWrap(True)
        lay.addWidget(info)

        self._peers_table = QTableWidget(0, 6)
        self._peers_table.setHorizontalHeaderLabels(
            ["Peer IP", "Packets", "First Seen", "Last Seen", "Country", "ISP"])
        self._peers_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._peers_table.setFont(QFont("Consolas", 10))
        self._peers_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._peers_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._peers_table.verticalHeader().setVisible(False)
        self._peers_table.cellDoubleClicked.connect(self._peer_double_click)
        lay.addWidget(self._peers_table)

        btn_row = QHBoxLayout()
        geo_all  = QPushButton("🌍 GeoIP All Peers")
        geo_all.clicked.connect(self._geo_all_peers)
        save_all = QPushButton("💾 Save All Peers")
        save_all.clicked.connect(self._save_all_peers)
        clr_p    = QPushButton("✕ Clear")
        clr_p.clicked.connect(lambda: self._peers_table.setRowCount(0))
        btn_row.addWidget(geo_all)
        btn_row.addWidget(save_all)
        btn_row.addWidget(clr_p)
        btn_row.addStretch()
        lay.addLayout(btn_row)

        self._peers_data = {}  # ip -> {count, first, last, country, isp}
        self._tabs.addTab(tab, "👥 PEERS")

    # ── IP Log Tab ─────────────────────────────────────────────────────────────

    def _build_ip_log_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)
        lbl = QLabel("Live color-coded packet log  —  🔴 Inbound  ·  ⚪ Outbound  ·  🔵 TCP  ·  🟡 UDP")
        lbl.setFont(QFont("Consolas", 9))
        lay.addWidget(lbl)
        self._log_text = QTextEdit()
        self._log_text.setReadOnly(True)
        self._log_text.setFont(QFont("Consolas", 9))
        lay.addWidget(self._log_text)
        row = QHBoxLayout()
        for lbl2, fn in [("✕ Clear", self._log_text.clear),
                          ("⬇ Save", self._save_log)]:
            b = QPushButton(lbl2)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch()
        lay.addLayout(row)
        self._tabs.addTab(tab, "📋 IP LOG")

    # ── Pinger Tab ─────────────────────────────────────────────────────────────

    def _build_pinger_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)

        top = QHBoxLayout()
        self._ping_host  = QLineEdit()
        self._ping_host.setPlaceholderText("IP address or hostname  (e.g. 8.8.8.8)")
        self._ping_host.setFont(QFont("Consolas", 11))
        self._ping_host.returnPressed.connect(self._run_ping)
        self._ping_count = QSpinBox()
        self._ping_count.setRange(1, 100)
        self._ping_count.setValue(4)
        self._ping_timeout = QSpinBox()
        self._ping_timeout.setRange(500, 10000)
        self._ping_timeout.setValue(2000)
        self._ping_timeout.setSuffix(" ms")
        self._ping_btn = QPushButton("▶ PING")
        self._ping_btn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        self._ping_btn.clicked.connect(self._run_ping)
        top.addWidget(QLabel("Host:"))
        top.addWidget(self._ping_host, 3)
        top.addWidget(QLabel("Count:"))
        top.addWidget(self._ping_count)
        top.addWidget(QLabel("Timeout:"))
        top.addWidget(self._ping_timeout)
        top.addWidget(self._ping_btn)
        lay.addLayout(top)

        self._ping_result = QTextEdit()
        self._ping_result.setReadOnly(True)
        self._ping_result.setFont(QFont("Consolas", 11))
        lay.addWidget(self._ping_result)

        stats = QGroupBox("Ping Statistics")
        sl = QFormLayout(stats)
        self._ps_min = QLabel("—"); self._ps_max = QLabel("—")
        self._ps_avg = QLabel("—"); self._ps_loss = QLabel("—")
        for lbl, w in [("Min RTT", self._ps_min), ("Max RTT", self._ps_max),
                        ("Avg RTT", self._ps_avg), ("Packet Loss", self._ps_loss)]:
            sl.addRow(f"{lbl}:", w)
            w.setFont(QFont("Consolas", 11))
        lay.addWidget(stats)

        self._tabs.addTab(tab, "📡 PINGER")

    # ── Port Scanner Tab ───────────────────────────────────────────────────────

    def _build_portscanner_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)

        top = QHBoxLayout()
        self._scan_host = QLineEdit()
        self._scan_host.setPlaceholderText("Target IP or hostname")
        self._scan_host.setFont(QFont("Consolas", 11))
        self._scan_host.returnPressed.connect(self._run_scan)
        self._scan_ports_edit = QLineEdit()
        self._scan_ports_edit.setPlaceholderText("22,80,443  or  1-1024  (blank = common ports)")
        self._scan_ports_edit.setFont(QFont("Consolas", 10))
        self._scan_timeout_spin = QSpinBox()
        self._scan_timeout_spin.setRange(100, 5000)
        self._scan_timeout_spin.setValue(500)
        self._scan_timeout_spin.setSuffix(" ms")
        self._scan_btn = QPushButton("▶ SCAN")
        self._scan_btn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        self._scan_btn.clicked.connect(self._run_scan)
        top.addWidget(QLabel("Host:"))
        top.addWidget(self._scan_host, 2)
        top.addWidget(QLabel("Ports:"))
        top.addWidget(self._scan_ports_edit, 2)
        top.addWidget(QLabel("Timeout:"))
        top.addWidget(self._scan_timeout_spin)
        top.addWidget(self._scan_btn)
        lay.addLayout(top)

        self._scan_progress = QProgressBar()
        lay.addWidget(self._scan_progress)

        self._scan_table = QTableWidget(0, 4)
        self._scan_table.setHorizontalHeaderLabels(["Port", "Service", "Status", "Banner"])
        self._scan_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._scan_table.setFont(QFont("Consolas", 10))
        self._scan_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._scan_table.verticalHeader().setVisible(False)
        lay.addWidget(self._scan_table)

        self._tabs.addTab(tab, "🔍 PORT SCAN")

    # ── GeoIP Tab ──────────────────────────────────────────────────────────────

    def _build_geo_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)

        top = QHBoxLayout()
        self._geo_ip = QLineEdit()
        self._geo_ip.setPlaceholderText("Enter IP address or hostname to geolocate")
        self._geo_ip.setFont(QFont("Consolas", 11))
        self._geo_ip.returnPressed.connect(self._run_geo)
        self._geo_btn = QPushButton("🌍 LOCATE")
        self._geo_btn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        self._geo_btn.clicked.connect(self._run_geo)
        top.addWidget(self._geo_ip, 4)
        top.addWidget(self._geo_btn)
        lay.addLayout(top)

        # Results box
        self._geo_result = QTextEdit()
        self._geo_result.setReadOnly(True)
        self._geo_result.setFont(QFont("Consolas", 11))
        self._geo_result.setMaximumHeight(160)
        lay.addWidget(self._geo_result)

        # Detail grid
        detail = QGroupBox("Location Details")
        grid   = QGridLayout(detail)
        fields = [
            ("IP", "query"), ("Country", "country"), ("Region", "regionName"),
            ("City", "city"), ("ZIP", "zip"), ("Latitude", "lat"),
            ("Longitude", "lon"), ("Timezone", "timezone"),
            ("ISP", "isp"), ("Organization", "org"), ("AS", "as"),
            ("Proxy/VPN", "proxy"), ("Hosting", "hosting"),
        ]
        self._geo_fields = {}
        for i, (label, key) in enumerate(fields):
            r, c = divmod(i, 2)
            lbl = QLabel(label + ":")
            lbl.setFont(QFont("Consolas", 10))
            val = QLabel("—")
            val.setFont(QFont("Consolas", 10))
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            grid.addWidget(lbl, r, c * 2)
            grid.addWidget(val, r, c * 2 + 1)
            self._geo_fields[key] = val
        lay.addWidget(detail)

        self._tabs.addTab(tab, "🌍 GEOIP")

    # ── IP Storage Tab ─────────────────────────────────────────────────────────

    def _build_storage_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)

        add_row = QHBoxLayout()
        self._store_ip   = QLineEdit(); self._store_ip.setPlaceholderText("IP Address")
        self._store_name = QLineEdit(); self._store_name.setPlaceholderText("Label / Name")
        self._store_note = QLineEdit(); self._store_note.setPlaceholderText("Notes")
        for w in [self._store_ip, self._store_name, self._store_note]:
            w.setFont(QFont("Consolas", 10))
        add_btn = QPushButton("+ ADD")
        add_btn.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
        add_btn.clicked.connect(self._add_stored_ip)
        add_row.addWidget(QLabel("IP:")); add_row.addWidget(self._store_ip, 2)
        add_row.addWidget(QLabel("Name:")); add_row.addWidget(self._store_name, 2)
        add_row.addWidget(QLabel("Note:")); add_row.addWidget(self._store_note, 3)
        add_row.addWidget(add_btn)
        lay.addLayout(add_row)

        self._storage_table = QTableWidget(0, 5)
        self._storage_table.setHorizontalHeaderLabels(
            ["IP Address", "Name", "Notes", "Date Added", ""])
        self._storage_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._storage_table.setFont(QFont("Consolas", 10))
        self._storage_table.verticalHeader().setVisible(False)
        lay.addWidget(self._storage_table)

        btns = QHBoxLayout()
        for lbl, fn in [("🗑 Delete", self._delete_stored_ip),
                         ("⬇ Export", self._export_stored),
                         ("⬆ Import", self._import_stored)]:
            b = QPushButton(lbl); b.clicked.connect(fn); btns.addWidget(b)
        btns.addStretch()
        lay.addLayout(btns)

        self._tabs.addTab(tab, "💾 IP STORAGE")

    # ── SSH Tab ────────────────────────────────────────────────────────────────

    def _build_ssh_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)

        conn = QGroupBox("Connection")
        cl   = QGridLayout(conn)
        self._ssh_host = QLineEdit(); self._ssh_host.setPlaceholderText("192.168.1.1 or hostname")
        self._ssh_user = QLineEdit(); self._ssh_user.setPlaceholderText("root")
        self._ssh_pass = QLineEdit(); self._ssh_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._ssh_pass.setPlaceholderText("password (leave blank if using key)")
        self._ssh_key  = QLineEdit(); self._ssh_key.setPlaceholderText("/path/to/id_rsa  (optional)")
        self._ssh_port_spin = QSpinBox()
        self._ssh_port_spin.setRange(1, 65535); self._ssh_port_spin.setValue(22)
        for w in [self._ssh_host, self._ssh_user, self._ssh_pass, self._ssh_key]:
            w.setFont(QFont("Consolas", 10))
        browse_key = QPushButton("📂")
        browse_key.setFixedWidth(32)
        browse_key.clicked.connect(self._browse_key)
        cl.addWidget(QLabel("Host:"),     0, 0); cl.addWidget(self._ssh_host, 0, 1, 1, 3)
        cl.addWidget(QLabel("User:"),     1, 0); cl.addWidget(self._ssh_user, 1, 1)
        cl.addWidget(QLabel("Port:"),     1, 2); cl.addWidget(self._ssh_port_spin, 1, 3)
        cl.addWidget(QLabel("Password:"), 2, 0); cl.addWidget(self._ssh_pass, 2, 1, 1, 3)
        cl.addWidget(QLabel("Key file:"), 3, 0); cl.addWidget(self._ssh_key, 3, 1, 1, 2)
        cl.addWidget(browse_key,          3, 3)
        lay.addWidget(conn)

        cmd_row = QHBoxLayout()
        self._ssh_cmd = QLineEdit()
        self._ssh_cmd.setPlaceholderText("Enter command  (e.g. whoami)")
        self._ssh_cmd.setFont(QFont("Consolas", 11))
        self._ssh_cmd.returnPressed.connect(self._run_ssh)
        self._ssh_btn = QPushButton("▶ RUN")
        self._ssh_btn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        self._ssh_btn.clicked.connect(self._run_ssh)
        clr_ssh = QPushButton("✕ Clear")
        clr_ssh.clicked.connect(lambda: self._ssh_output.clear())
        cmd_row.addWidget(self._ssh_cmd, 4)
        cmd_row.addWidget(self._ssh_btn)
        cmd_row.addWidget(clr_ssh)
        lay.addLayout(cmd_row)

        self._ssh_output = QTextEdit()
        self._ssh_output.setReadOnly(True)
        self._ssh_output.setFont(QFont("Consolas", 10))
        lay.addWidget(self._ssh_output)

        quick = QGroupBox("Quick Commands")
        ql    = QHBoxLayout(quick)
        for label, cmd in [
            ("whoami",    "whoami"),
            ("hostname",  "hostname"),
            ("ip addr",   "ip a 2>/dev/null || ipconfig"),
            ("netstat",   "netstat -an 2>/dev/null | head -40"),
            ("processes", "ps aux 2>/dev/null | head -25 || tasklist"),
            ("uptime",    "uptime 2>/dev/null || net stats workstation | head -5"),
            ("disk",      "df -h 2>/dev/null || wmic logicaldisk get size,freespace,caption"),
            ("users",     "who 2>/dev/null || query user"),
            ("passwd",    "cat /etc/passwd 2>/dev/null | head -20"),
        ]:
            b = QPushButton(label)
            b.setFont(QFont("Consolas", 9))
            b.clicked.connect(lambda _, c=cmd: self._ssh_quick(c))
            ql.addWidget(b)
        lay.addWidget(quick)

        self._tabs.addTab(tab, "🔒 SSH")

    # ── Theme Tab ──────────────────────────────────────────────────────────────

    def _build_theme_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)
        lay.setSpacing(10)

        colors = QGroupBox("Colors")
        cl = QGridLayout(colors)
        self._ap1 = QLabel("■  Primary Accent")
        self._ap2 = QLabel("■  Secondary Accent")
        self._abg = QLabel("■  Background Color")
        for lbl in [self._ap1, self._ap2, self._abg]:
            lbl.setFont(QFont("Consolas", 12))
        for i, (lbl, key) in enumerate([
            (self._ap1, "accent"), (self._ap2, "accent2"), (self._abg, "bg_color")
        ]):
            btn = QPushButton("Change")
            btn.clicked.connect(lambda _, k=key: self._pick_color(k))
            cl.addWidget(lbl, i, 0)
            cl.addWidget(btn, i, 1)
        reset = QPushButton("Reset to Default (Red / Black)")
        reset.clicked.connect(self._reset_colors)
        cl.addWidget(reset, 3, 0, 1, 2)
        lay.addWidget(colors)

        img = QGroupBox("Background Image  (JPEG / PNG / GIF supported)")
        il  = QHBoxLayout(img)
        self._bg_lbl = QLabel("No image loaded")
        self._bg_lbl.setFont(QFont("Consolas", 9))
        b_load = QPushButton("📂 Load Image")
        b_load.clicked.connect(self._load_bg_image)
        b_clr  = QPushButton("✕ Clear")
        b_clr.clicked.connect(self._clear_bg_image)
        il.addWidget(self._bg_lbl, 2)
        il.addWidget(b_load); il.addWidget(b_clr)
        lay.addWidget(img)

        fs = QGroupBox("Font Size")
        fl = QHBoxLayout(fs)
        self._font_slider = QSlider(Qt.Orientation.Horizontal)
        self._font_slider.setRange(8, 16)
        self._font_slider.setValue(self.settings.get("font_size", 10))
        self._fs_lbl = QLabel(f"{self._font_slider.value()}pt")
        self._font_slider.valueChanged.connect(lambda v: (
            self._fs_lbl.setText(f"{v}pt"),
            self.settings.update({"font_size": v}),
            save_settings(self.settings)
        ))
        fl.addWidget(self._font_slider); fl.addWidget(self._fs_lbl)
        lay.addWidget(fs)

        buf = QGroupBox("Packet Buffer")
        bl  = QHBoxLayout(buf)
        self._buf_spin = QSpinBox()
        self._buf_spin.setRange(100, 10000)
        self._buf_spin.setValue(self.settings.get("max_packets", 2000))
        self._buf_spin.setSuffix(" rows")
        self._buf_spin.valueChanged.connect(lambda v: (
            self.settings.update({"max_packets": v}),
            save_settings(self.settings)
        ))
        bl.addWidget(QLabel("Max rows in packet table:"))
        bl.addWidget(self._buf_spin); bl.addStretch()
        lay.addWidget(buf)

        lay.addStretch()
        self._tabs.addTab(tab, "🎨 THEME")
        self._update_color_previews()

    # ── Adapter logic ──────────────────────────────────────────────────────────

    def _refresh_adapters(self):
        self._adapters = get_adapters()
        self._adapter_combo.blockSignals(True)
        self._adapter_combo.clear()
        self._adapter_combo.addItem("All Interfaces  (0.0.0.0)", "0.0.0.0")
        for a in self._adapters:
            self._adapter_combo.addItem(a["friendly_name"], a["ip"])
        self._adapter_combo.blockSignals(False)

    def _selected_adapter_ip(self):
        return self._adapter_combo.currentData() or "0.0.0.0"

    # ── Engine callbacks ───────────────────────────────────────────────────────

    def _on_packet(self, pkt):
        self._total_pkts  += 1
        self._total_bytes += pkt["size"]

        max_pkts = self.settings.get("max_packets", 2000)
        if self._pkt_table.rowCount() >= max_pkts:
            self._pkt_table.removeRow(0)

        row = self._pkt_table.rowCount()
        self._pkt_table.insertRow(row)
        cells = [
            pkt["ts"], pkt["direction"], pkt["proto"],
            pkt["src"], str(pkt["sport"]),
            pkt["dst"], str(pkt["dport"]), str(pkt["size"]),
        ]
        a2 = self.settings["accent2"]
        for c, val in enumerate(cells):
            item = QTableWidgetItem(val)
            item.setFont(QFont("Consolas", 9))
            if pkt["direction"] == "IN":
                item.setForeground(QColor(a2))
            else:
                item.setForeground(QColor("#999999"))
            if pkt.get("new"):
                item.setBackground(QColor(25, 0, 0))
            self._pkt_table.setItem(row, c, item)
        self._pkt_table.scrollToBottom()

        # IP summary
        for ip in [pkt["src"], pkt["dst"]]:
            if ip not in self.captured_ips:
                self.captured_ips[ip] = {"count": 0, "last": ""}
            self.captured_ips[ip]["count"] += 1
            self.captured_ips[ip]["last"]   = pkt["ts"]

        # Peers tab
        if pkt.get("is_peer") and pkt.get("peer_ip"):
            pip = pkt["peer_ip"]
            if pip not in self._peers_data:
                self._peers_data[pip] = {
                    "count": 0, "first": pkt["ts"], "last": pkt["ts"],
                    "country": "—", "isp": "—"
                }
            self._peers_data[pip]["count"] += 1
            self._peers_data[pip]["last"]   = pkt["ts"]
            self._refresh_peers_table()

        self._refresh_ip_table()
        self._log_packet(pkt)

        self._pkt_count_lbl.setText(f"Packets: {self._total_pkts:,}")
        self._ip_count_lbl.setText(f"IPs: {len(self.captured_ips)}")
        self._bytes_lbl.setText(f"Bytes: {self._total_bytes:,}")

    def _on_status(self, msg):
        self._status_lbl.setText(msg)

    # ── Sniffer controls ───────────────────────────────────────────────────────

    def _toggle_sniff(self):
        if self.engine.is_running():
            self.engine.stop()
            self._start_btn.setText("▶  START")
            self._mode_lbl.setText("STOPPED")
            self._on_status("● STOPPED")
        else:
            f   = self._filter_edit.text().strip() or "true"
            ip  = self._selected_adapter_ip()
            self.engine.start(f, adapter_ip=ip if ip != "0.0.0.0" else None)
            self._start_btn.setText("⏹  STOP")
            mode = "SIM" if self.engine.simulation else "LIVE"
            self._mode_lbl.setText(mode)
            self._on_status(f"● RUNNING [{mode}]")

    def _on_profile_change(self, name):
        p = SNIFFER_PROFILES.get(name, {})
        self._filter_edit.setText(p.get("filter", "true"))
        self._profile_desc.setText(f"  {p.get('description', '')}")

    def _clear_packets(self):
        self._pkt_table.setRowCount(0)
        self._ip_table.setRowCount(0)
        self.captured_ips.clear()
        self._total_pkts = 0; self._total_bytes = 0
        self._pkt_count_lbl.setText("Packets: 0")
        self._ip_count_lbl.setText("IPs: 0")
        self._bytes_lbl.setText("Bytes: 0")

    def _export_packets(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Packets", "packets.json", "JSON (*.json);;CSV (*.csv)")
        if not path: return
        rows = [[self._pkt_table.item(r, c).text() if self._pkt_table.item(r, c) else ""
                 for c in range(self._pkt_table.columnCount())]
                for r in range(self._pkt_table.rowCount())]
        if path.endswith(".csv"):
            with open(path, "w") as f:
                f.write("Time,Dir,Proto,SrcIP,SPort,DstIP,DPort,Bytes\n")
                f.writelines(",".join(r) + "\n" for r in rows)
        else:
            json.dump(rows, open(path, "w"), indent=2)

    def _refresh_ip_table(self):
        self._ip_table.setRowCount(0)
        for ip, d in sorted(self.captured_ips.items(),
                             key=lambda x: x[1]["count"], reverse=True)[:200]:
            r = self._ip_table.rowCount()
            self._ip_table.insertRow(r)
            for c, v in enumerate([ip, str(d["count"]), d["last"]]):
                item = QTableWidgetItem(v)
                item.setFont(QFont("Consolas", 9))
                self._ip_table.setItem(r, c, item)

    def _refresh_peers_table(self):
        self._peers_table.setRowCount(0)
        for ip, d in sorted(self._peers_data.items(),
                             key=lambda x: x[1]["count"], reverse=True):
            r = self._peers_table.rowCount()
            self._peers_table.insertRow(r)
            for c, v in enumerate([ip, str(d["count"]), d["first"],
                                    d["last"], d["country"], d["isp"]]):
                item = QTableWidgetItem(v)
                item.setFont(QFont("Consolas", 10))
                if c == 0:
                    item.setForeground(QColor(self.settings["accent2"]))
                self._peers_table.setItem(r, c, item)

    def _pkt_double_click(self, row, col):
        ip_col = 3 if col < 5 else 5
        item   = self._pkt_table.item(row, ip_col)
        if item:
            self._geo_ip.setText(item.text())
            self._tabs.setCurrentIndex(5)
            self._run_geo()

    def _peer_double_click(self, row, col):
        item = self._peers_table.item(row, 0)
        if item:
            self._geo_ip.setText(item.text())
            self._tabs.setCurrentIndex(5)
            self._run_geo()

    def _selected_ip_from_table(self):
        items = self._ip_table.selectedItems()
        return items[0].text() if items else None

    def _quick_geo(self):
        ip = self._selected_ip_from_table()
        if ip:
            self._geo_ip.setText(ip)
            self._tabs.setCurrentIndex(5)
            self._run_geo()

    def _quick_ping(self):
        ip = self._selected_ip_from_table()
        if ip:
            self._ping_host.setText(ip)
            self._tabs.setCurrentIndex(3)
            self._run_ping()

    def _quick_scan(self):
        ip = self._selected_ip_from_table()
        if ip:
            self._scan_host.setText(ip)
            self._tabs.setCurrentIndex(4)
            self._run_scan()

    def _save_selected_ip(self):
        ip = self._selected_ip_from_table()
        if ip:
            self._store_ip.setText(ip)
            self._tabs.setCurrentIndex(6)

    def _geo_all_peers(self):
        ips = list(self._peers_data.keys())
        if not ips:
            return
        # Geo first peer immediately, rest sequentially via QTimer
        def geo_next(idx=0):
            if idx >= len(ips): return
            ip = ips[idx]
            w  = GeoWorker(ip)
            def done(data, i=idx, peer=ip):
                if data.get("status") == "success":
                    if peer in self._peers_data:
                        self._peers_data[peer]["country"] = data.get("country", "—")
                        self._peers_data[peer]["isp"]     = data.get("isp", "—")
                    self._refresh_peers_table()
                QTimer.singleShot(200, lambda: geo_next(i + 1))
            w.result.connect(done)
            w.start()
        geo_next()

    def _save_all_peers(self):
        for ip in self._peers_data:
            if not any(e["ip"] == ip for e in self.saved_ips):
                self.saved_ips.append({
                    "ip": ip, "name": "Peer",
                    "note": f"Captured {self._peers_data[ip]['count']} pkts",
                    "date": datetime.now().strftime("%Y-%m-%d %H:%M")
                })
        self._refresh_storage_table()
        self._persist_stored_ips()

    # ── Log ────────────────────────────────────────────────────────────────────

    def _log_packet(self, pkt):
        in_col  = self.settings["accent2"]
        out_col = "#888888"
        proto_c = {"TCP": "#5599ff", "UDP": "#ffbb00"}.get(pkt["proto"], "#aaaaaa")
        color   = in_col if pkt["direction"] == "IN" else out_col
        peer_tag = " ★" if pkt.get("is_peer") else ""
        line = (f'<span style="color:{color}">[{pkt["ts"]}] {pkt["direction"]} '
                f'<span style="color:{proto_c}">{pkt["proto"]}</span> '
                f'{pkt["src"]}:{pkt["sport"]} → {pkt["dst"]}:{pkt["dport"]} '
                f'({pkt["size"]}B){peer_tag}</span><br>')
        self._log_text.insertHtml(line)
        self._log_text.ensureCursorVisible()

    def _save_log(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Log", "dvrksniff_log.txt", "Text (*.txt);;HTML (*.html)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._log_text.toPlainText() if path.endswith(".txt")
                        else self._log_text.toHtml())

    # ── Pinger ─────────────────────────────────────────────────────────────────

    def _run_ping(self):
        host = self._ping_host.text().strip()
        if not host: return
        self._ping_btn.setEnabled(False)
        self._ping_result.setPlainText(f"Pinging {host} …\n")
        self._ping_worker = PingWorker(host, self._ping_count.value())
        self._ping_worker.result.connect(self._show_ping_result)
        self._ping_worker.start()

    def _show_ping_result(self, results):
        self._ping_btn.setEnabled(True)
        lines = []
        rtts  = []
        for r in results:
            mark = "✓" if r["success"] else "✗"
            lines.append(f"{mark}  {r['line']}")
            if r.get("rtt_ms") is not None:
                rtts.append(r["rtt_ms"])
        self._ping_result.setPlainText("\n".join(lines))
        if rtts:
            self._ps_min.setText(f"{min(rtts):.1f} ms")
            self._ps_max.setText(f"{max(rtts):.1f} ms")
            self._ps_avg.setText(f"{sum(rtts)/len(rtts):.1f} ms")
        total   = len(results)
        success = sum(1 for r in results if r["success"])
        loss    = max(0, total - success) / total * 100 if total else 100
        self._ps_loss.setText(f"{loss:.0f}%")

    # ── Port Scanner ───────────────────────────────────────────────────────────

    def _run_scan(self):
        host = self._scan_host.text().strip()
        if not host: return
        ports_txt = self._scan_ports_edit.text().strip()
        ports = None
        if ports_txt:
            try:
                if "-" in ports_txt and "," not in ports_txt:
                    a, b = ports_txt.split("-")
                    ports = list(range(int(a.strip()), int(b.strip()) + 1))
                else:
                    ports = [int(x.strip()) for x in ports_txt.split(",") if x.strip()]
            except Exception:
                pass
        self._scan_btn.setEnabled(False)
        self._scan_table.setRowCount(0)
        self._scan_progress.setValue(0)
        timeout = self._scan_timeout_spin.value() / 1000.0
        self._scan_worker = ScanWorker(host, ports, timeout)
        self._scan_worker.progress.connect(
            lambda i, t, p: self._scan_progress.setValue(int(i/t*100)))
        self._scan_worker.result.connect(self._show_scan_result)
        self._scan_worker.start()

    def _show_scan_result(self, results):
        self._scan_btn.setEnabled(True)
        self._scan_progress.setValue(100)
        a2 = self.settings["accent2"]
        for r in results:
            row = self._scan_table.rowCount()
            self._scan_table.insertRow(row)
            status = "OPEN" if r["open"] else "closed"
            color  = QColor(a2) if r["open"] else QColor("#555555")
            for c, v in enumerate([str(r["port"]), r["service"], status, r["banner"]]):
                item = QTableWidgetItem(v)
                item.setFont(QFont("Consolas", 10))
                item.setForeground(color)
                self._scan_table.setItem(row, c, item)

    # ── GeoIP ──────────────────────────────────────────────────────────────────

    def _run_geo(self):
        ip = self._geo_ip.text().strip()
        if not ip: return
        self._geo_btn.setEnabled(False)
        self._geo_result.setPlainText(f"Looking up {ip} …")
        self._geo_worker = GeoWorker(ip)
        self._geo_worker.result.connect(self._show_geo_result)
        self._geo_worker.start()

    def _show_geo_result(self, data):
        self._geo_btn.setEnabled(True)
        if "error" in data:
            self._geo_result.setPlainText(f"[!] {data['error']}")
            return

        for key, lbl in self._geo_fields.items():
            val = data.get(key, "—")
            if isinstance(val, bool):
                val = "Yes" if val else "No"
            lbl.setText(str(val) if val else "—")

        a  = self.settings["accent"]
        box = (
            f"╔══════════════════════════════════════════╗\n"
            f"  IP:          {data.get('query','')}\n"
            f"  Country:     {data.get('country','')} ({data.get('countryCode','')})\n"
            f"  City/Region: {data.get('city','')}, {data.get('regionName','')}\n"
            f"  ISP:         {str(data.get('isp',''))[:44]}\n"
            f"  Coordinates: {data.get('lat','')}, {data.get('lon','')}\n"
            f"  Timezone:    {data.get('timezone','')}\n"
            f"  Proxy/VPN:   {'Yes ⚠' if data.get('proxy') else 'No'}\n"
            f"  Hosting:     {'Yes' if data.get('hosting') else 'No'}\n"
            f"╚══════════════════════════════════════════╝"
        )
        self._geo_result.setPlainText(box)

    # ── IP Storage ─────────────────────────────────────────────────────────────

    def _add_stored_ip(self):
        ip = self._store_ip.text().strip()
        if not ip: return
        self.saved_ips.append({
            "ip":   ip,
            "name": self._store_name.text().strip(),
            "note": self._store_note.text().strip(),
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        })
        self._refresh_storage_table()
        self._persist_stored_ips()
        self._store_ip.clear(); self._store_name.clear(); self._store_note.clear()

    def _refresh_storage_table(self):
        self._storage_table.setRowCount(0)
        for e in self.saved_ips:
            r = self._storage_table.rowCount()
            self._storage_table.insertRow(r)
            for c, v in enumerate([e["ip"], e["name"], e["note"], e["date"], ""]):
                item = QTableWidgetItem(v)
                item.setFont(QFont("Consolas", 10))
                self._storage_table.setItem(r, c, item)
            btn = QPushButton("🌍")
            btn.setFixedWidth(36)
            btn.clicked.connect(lambda _, i=e["ip"]: self._geo_from_storage(i))
            self._storage_table.setCellWidget(r, 4, btn)

    def _geo_from_storage(self, ip):
        self._geo_ip.setText(ip)
        self._tabs.setCurrentIndex(5)
        self._run_geo()

    def _delete_stored_ip(self):
        rows = sorted({i.row() for i in self._storage_table.selectedIndexes()}, reverse=True)
        for r in rows:
            if 0 <= r < len(self.saved_ips):
                self.saved_ips.pop(r)
        self._refresh_storage_table()
        self._persist_stored_ips()

    def _persist_stored_ips(self):
        json.dump(self.saved_ips, open(Path.home() / ".dvrksniff_ips.json", "w"), indent=2)

    def _load_stored_ips(self):
        p = Path.home() / ".dvrksniff_ips.json"
        if p.exists():
            try:
                self.saved_ips = json.load(open(p))
                self._refresh_storage_table()
            except Exception:
                pass

    def _export_stored(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export IPs", "saved_ips.json", "JSON (*.json)")
        if path:
            json.dump(self.saved_ips, open(path, "w"), indent=2)

    def _import_stored(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import IPs", "", "JSON (*.json)")
        if path:
            self.saved_ips.extend(json.load(open(path)))
            self._refresh_storage_table()
            self._persist_stored_ips()

    # ── SSH ────────────────────────────────────────────────────────────────────

    def _browse_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select SSH Key", "", "All Files (*)")
        if path:
            self._ssh_key.setText(path)

    def _run_ssh(self):
        host = self._ssh_host.text().strip()
        user = self._ssh_user.text().strip()
        cmd  = self._ssh_cmd.text().strip()
        if not host or not cmd:
            self._ssh_output.append("[!] Host and command are required.")
            return
        self._ssh_btn.setEnabled(False)
        self._ssh_output.append(f"\n<span style='color:{self.settings[\"accent2\"]}'>$ {cmd}</span>")
        self._ssh_worker = SSHWorker(
            host, user, self._ssh_pass.text(),
            self._ssh_port_spin.value(), cmd,
            self._ssh_key.text().strip()
        )
        self._ssh_worker.output.connect(self._show_ssh_output)
        self._ssh_worker.error.connect(self._show_ssh_error)
        self._ssh_worker.start()

    def _show_ssh_output(self, out, err):
        self._ssh_btn.setEnabled(True)
        if out.strip():
            self._ssh_output.append(out)
        if err.strip():
            self._ssh_output.append(
                f"<span style='color:#ff6666'>[STDERR] {err}</span>")
        self._ssh_output.ensureCursorVisible()

    def _show_ssh_error(self, error):
        self._ssh_btn.setEnabled(True)
        self._ssh_output.append(
            f"<span style='color:#ff4444'>[ERROR] {error}</span>")

    def _ssh_quick(self, cmd):
        self._ssh_cmd.setText(cmd)
        self._run_ssh()

    # ── Theme ──────────────────────────────────────────────────────────────────

    def _pick_color(self, key):
        c = QColorDialog.getColor(QColor(self.settings.get(key, "#cc0000")), self)
        if c.isValid():
            self.settings[key] = c.name()
            save_settings(self.settings)
            self._apply_theme()
            self._update_color_previews()

    def _reset_colors(self):
        self.settings.update({"accent": "#cc0000", "accent2": "#ff3333", "bg_color": "#0a0000"})
        save_settings(self.settings)
        self._apply_theme()
        self._update_color_previews()

    def _update_color_previews(self):
        self._ap1.setStyleSheet(f"color:{self.settings['accent']}")
        self._ap2.setStyleSheet(f"color:{self.settings['accent2']}")
        self._abg.setStyleSheet(f"color:{self.settings['bg_color']}; background:#222;")

    def _load_bg_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Background", "",
            "Images (*.jpg *.jpeg *.png *.gif *.bmp *.webp)")
        if path:
            self.settings["bg_image"] = path
            save_settings(self.settings)
            self._bg.set_image(path)
            self._bg_lbl.setText(os.path.basename(path))

    def _clear_bg_image(self):
        self.settings["bg_image"] = ""
        save_settings(self.settings)
        self._bg.set_image("")
        self._bg_lbl.setText("No image loaded")

    def _apply_theme(self):
        a  = self.settings["accent"]
        a2 = self.settings["accent2"]
        bg = self.settings["bg_color"]
        fs = self.settings.get("font_size", 10)

        self._title_lbl.setStyleSheet(f"color:{a}; background:transparent;")
        self._credit_lbl.setStyleSheet(f"color:{a2}; background:transparent;")
        self._status_lbl.setStyleSheet(f"color:{a2}; background:transparent;")

        QApplication.instance().setStyleSheet(f"""
        QWidget {{
            background: transparent;
            color: #dddddd;
            font-family: Consolas, monospace;
            font-size: {fs}pt;
        }}
        QTabWidget::pane {{
            border: 1px solid {a};
            background: rgba(10,0,0,0.88);
        }}
        QTabBar::tab {{
            background: rgba(20,0,0,0.92);
            color: #aaaaaa;
            border: 1px solid #330000;
            padding: 6px 14px;
        }}
        QTabBar::tab:selected {{
            background: rgba(45,0,0,0.96);
            color: {a};
            border-bottom: 2px solid {a};
        }}
        QTabBar::tab:hover {{ color: {a2}; }}
        QPushButton {{
            background: rgba(70,0,0,0.85);
            color: {a2};
            border: 1px solid {a};
            border-radius: 3px;
            padding: 4px 10px;
        }}
        QPushButton:hover {{
            background: {a};
            color: #000000;
        }}
        QPushButton:disabled {{
            background: #1a0000;
            color: #555;
            border-color: #330000;
        }}
        QLineEdit, QSpinBox, QComboBox, QTextEdit {{
            background: rgba(12,0,0,0.92);
            color: #dddddd;
            border: 1px solid {a};
            border-radius: 3px;
            padding: 3px 6px;
            selection-background-color: {a};
        }}
        QComboBox::drop-down {{ border: none; }}
        QComboBox QAbstractItemView {{
            background: #1a0000;
            color: #dddddd;
            selection-background-color: {a};
        }}
        QTableWidget {{
            background: rgba(8,0,0,0.90);
            color: #cccccc;
            gridline-color: #2a0000;
            border: 1px solid {a};
            alternate-background-color: rgba(18,0,0,0.75);
        }}
        QTableWidget::item:selected {{
            background: rgba(160,0,0,0.55);
            color: #ffffff;
        }}
        QHeaderView::section {{
            background: rgba(35,0,0,0.96);
            color: {a};
            border: 1px solid #2a0000;
            padding: 4px;
            font-weight: bold;
        }}
        QGroupBox {{
            border: 1px solid {a};
            border-radius: 4px;
            margin-top: 8px;
            padding-top: 8px;
            background: rgba(8,0,0,0.55);
            color: {a2};
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            color: {a};
        }}
        QProgressBar {{
            background: rgba(18,0,0,0.85);
            border: 1px solid {a};
            color: #fff;
            text-align: center;
        }}
        QProgressBar::chunk {{ background: {a}; }}
        QScrollBar:vertical {{
            background: rgba(8,0,0,0.8);
            width: 9px;
        }}
        QScrollBar::handle:vertical {{
            background: {a};
            min-height: 18px;
        }}
        QLabel {{ color: #cccccc; background: transparent; }}
        QSplitter::handle {{ background: {a}; width: 2px; }}
        QSlider::groove:horizontal {{
            height: 4px;
            background: #330000;
            border-radius: 2px;
        }}
        QSlider::handle:horizontal {{
            background: {a};
            border: none;
            width: 14px; height: 14px;
            margin: -5px 0;
            border-radius: 7px;
        }}
        QSlider::sub-page:horizontal {{ background: {a2}; border-radius: 2px; }}
        """)
        self._bg.set_bg_color(bg)
        self._bg.set_accent(a)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("DVRKSNIFF")
    app.setOrganizationName("botnet1337")

    icon_path = os.path.join(
        getattr(sys, "_MEIPASS", os.path.dirname(__file__)), "icon.ico"
    )
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    win = DVRKSniff()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
