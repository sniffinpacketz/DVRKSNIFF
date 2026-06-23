"""
DVRKSNIFF — Advanced Network Intelligence Tool
Credited to @botnet1337 on IG
"""

import sys
import os
import json
import threading
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path

# ── Qt imports ────────────────────────────────────────────────────────────────
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTableWidget, QTableWidgetItem, QPushButton, QLabel,
    QLineEdit, QComboBox, QTextEdit, QSplitter, QFileDialog,
    QColorDialog, QSpinBox, QCheckBox, QGroupBox, QFormLayout,
    QProgressBar, QHeaderView, QMenuBar, QMenu, QStatusBar,
    QMessageBox, QDialog, QDialogButtonBox, QFrame, QSlider,
    QScrollArea, QGridLayout, QSizePolicy
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize, QPropertyAnimation,
    QEasingCurve, QRect, QPoint
)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QPixmap, QMovie, QPainter, QBrush,
    QLinearGradient, QIcon, QAction, QPen, QTextCharFormat,
    QTextCursor, QGuiApplication
)

from profiles import SNIFFER_PROFILES
from engine import SnifferEngine, icmp_ping, scan_ports, geoip_lookup

# ── Settings path ─────────────────────────────────────────────────────────────
SETTINGS_FILE = Path.home() / ".dvrksniff_settings.json"

DEFAULT_SETTINGS = {
    "accent": "#cc0000",
    "accent2": "#ff3333",
    "bg_color": "#0a0000",
    "bg_image": "",
    "font_size": 11,
    "max_packets": 1000,
    "auto_geo": False,
}


def load_settings():
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE) as f:
                s = DEFAULT_SETTINGS.copy()
                s.update(json.load(f))
                return s
        except Exception:
            pass
    return DEFAULT_SETTINGS.copy()


def save_settings(s):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(s, f, indent=2)


# ── Worker threads ─────────────────────────────────────────────────────────────

class PingWorker(QThread):
    result = pyqtSignal(list)
    def __init__(self, host, count):
        super().__init__()
        self.host = host
        self.count = count
    def run(self):
        r = icmp_ping(self.host, self.count)
        self.result.emit(r)


class ScanWorker(QThread):
    progress = pyqtSignal(int, int, int)
    result = pyqtSignal(list)
    def __init__(self, host, ports, timeout):
        super().__init__()
        self.host = host
        self.ports = ports
        self.timeout = timeout
    def run(self):
        r = scan_ports(self.host, self.ports, self.timeout,
                       on_progress=lambda i, t, p: self.progress.emit(i, t, p))
        self.result.emit(r)


class GeoWorker(QThread):
    result = pyqtSignal(dict)
    def __init__(self, ip):
        super().__init__()
        self.ip = ip
    def run(self):
        self.result.emit(geoip_lookup(self.ip))


class SSHWorker(QThread):
    output = pyqtSignal(str)
    def __init__(self, host, user, password, port, command):
        super().__init__()
        self.host = host; self.user = user
        self.password = password; self.port = port
        self.command = command
    def run(self):
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, port=self.port, username=self.user,
                           password=self.password, timeout=10)
            stdin, stdout, stderr = client.exec_command(self.command)
            out = stdout.read().decode(errors="replace")
            err = stderr.read().decode(errors="replace")
            client.close()
            self.output.emit(out + (("\n[STDERR]\n" + err) if err.strip() else ""))
        except ImportError:
            self.output.emit("[!] paramiko not installed. Run: pip install paramiko")
        except Exception as e:
            self.output.emit(f"[SSH Error] {e}")


# ── Background Widget ──────────────────────────────────────────────────────────

class BackgroundWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._pixmap = None
        self._movie = None
        self._bg_color = QColor("#0a0000")
        self._accent = QColor("#cc0000")
        self._accent2 = QColor("#ff3333")

    def set_bg_color(self, color_hex):
        self._bg_color = QColor(color_hex)
        self.update()

    def set_accent(self, a1, a2):
        self._accent = QColor(a1)
        self._accent2 = QColor(a2)
        self.update()

    def set_image(self, path):
        if not path:
            self._pixmap = None
            self._movie = None
            self.update()
            return
        if path.lower().endswith(".gif"):
            self._pixmap = None
            self._movie = QMovie(path)
            self._movie.frameChanged.connect(lambda: self.update())
            self._movie.start()
        else:
            self._movie = None
            self._pixmap = QPixmap(path)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Background
        if self._movie and self._movie.isValid():
            frame = self._movie.currentPixmap()
            if not frame.isNull():
                p.drawPixmap(self.rect(), frame.scaled(
                    self.size(), Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                    Qt.TransformationMode.SmoothTransformation))
            else:
                p.fillRect(self.rect(), self._bg_color)
        elif self._pixmap and not self._pixmap.isNull():
            p.drawPixmap(self.rect(), self._pixmap.scaled(
                self.size(), Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation))
        else:
            grad = QLinearGradient(0, 0, 0, self.height())
            grad.setColorAt(0, self._bg_color)
            grad.setColorAt(0.5, QColor("#1a0000"))
            grad.setColorAt(1, QColor("#000000"))
            p.fillRect(self.rect(), grad)

        # Vignette overlay for readability
        vign = QLinearGradient(0, 0, 0, self.height())
        vign.setColorAt(0, QColor(0, 0, 0, 160))
        vign.setColorAt(0.5, QColor(0, 0, 0, 60))
        vign.setColorAt(1, QColor(0, 0, 0, 180))
        p.fillRect(self.rect(), vign)
        p.end()


# ── Main Window ────────────────────────────────────────────────────────────────

class DVRKSniff(QMainWindow):
    packet_signal = pyqtSignal(dict)
    status_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.settings = load_settings()
        self.engine = SnifferEngine(
            on_packet=lambda p: self.packet_signal.emit(p),
            on_status=lambda s: self.status_signal.emit(s),
        )
        self.packet_signal.connect(self._on_packet)
        self.status_signal.connect(self._on_status)

        self.captured_ips = {}   # ip -> {count, last_seen, packets}
        self.packet_log = []
        self.saved_ips = []      # storage tab

        self._init_ui()
        self._apply_theme()

        if self.settings.get("bg_image"):
            self._bg.set_image(self.settings["bg_image"])

    # ── UI Construction ────────────────────────────────────────────────────────

    def _init_ui(self):
        self.setWindowTitle("DVRKSNIFF  ·  @botnet1337")
        self.setMinimumSize(1280, 800)
        self.resize(1400, 900)

        # Background
        self._bg = BackgroundWidget(self)
        self.setCentralWidget(self._bg)

        root = QVBoxLayout(self._bg)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # ── Header bar ──
        hdr = QHBoxLayout()
        self._title_lbl = QLabel("◈ DVRKSNIFF")
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

        # ── Tab widget ──
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        self._tabs.setFont(QFont("Consolas", 10))
        root.addWidget(self._tabs)

        self._build_sniffer_tab()
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
        lay.setSpacing(6)

        # Controls row
        ctrl = QHBoxLayout()

        self._profile_combo = QComboBox()
        self._profile_combo.addItems(list(SNIFFER_PROFILES.keys()))
        self._profile_combo.setFont(QFont("Consolas", 10))
        self._profile_combo.currentTextChanged.connect(self._on_profile_change)
        ctrl.addWidget(QLabel("Profile:"))
        ctrl.addWidget(self._profile_combo, 2)

        self._filter_edit = QLineEdit()
        self._filter_edit.setPlaceholderText("WinDivert filter (e.g. udp and ip.SrcPort == 6672)")
        self._filter_edit.setFont(QFont("Consolas", 10))
        ctrl.addWidget(QLabel("Filter:"), 0)
        ctrl.addWidget(self._filter_edit, 3)

        self._start_btn = QPushButton("▶  START")
        self._start_btn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        self._start_btn.clicked.connect(self._toggle_sniff)
        self._start_btn.setFixedWidth(120)

        self._clear_btn = QPushButton("✕  CLEAR")
        self._clear_btn.setFont(QFont("Consolas", 10))
        self._clear_btn.clicked.connect(self._clear_packets)

        self._export_btn = QPushButton("⬇  EXPORT")
        self._export_btn.setFont(QFont("Consolas", 10))
        self._export_btn.clicked.connect(self._export_packets)

        ctrl.addWidget(self._start_btn)
        ctrl.addWidget(self._clear_btn)
        ctrl.addWidget(self._export_btn)
        lay.addLayout(ctrl)

        # Profile description
        self._profile_desc = QLabel("")
        self._profile_desc.setFont(QFont("Consolas", 9))
        lay.addWidget(self._profile_desc)

        # Splitter: packet table | IP list
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Packet table
        self._pkt_table = QTableWidget(0, 8)
        self._pkt_table.setHorizontalHeaderLabels(
            ["Time", "Dir", "Proto", "Source IP", "SPort", "Dest IP", "DPort", "Bytes"]
        )
        self._pkt_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._pkt_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._pkt_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._pkt_table.setFont(QFont("Consolas", 9))
        self._pkt_table.verticalHeader().setVisible(False)
        self._pkt_table.setAlternatingRowColors(True)
        self._pkt_table.cellDoubleClicked.connect(self._pkt_double_click)
        splitter.addWidget(self._pkt_table)

        # IP summary panel
        ip_panel = QWidget()
        ip_lay = QVBoxLayout(ip_panel)
        ip_lay.addWidget(QLabel("Unique IPs"))
        self._ip_table = QTableWidget(0, 3)
        self._ip_table.setHorizontalHeaderLabels(["IP Address", "Packets", "Last Seen"])
        self._ip_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._ip_table.setFont(QFont("Consolas", 9))
        self._ip_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._ip_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._ip_table.verticalHeader().setVisible(False)

        ip_btn_row = QHBoxLayout()
        geo_quick = QPushButton("🌍 GeoIP")
        geo_quick.setFont(QFont("Consolas", 9))
        geo_quick.clicked.connect(self._quick_geo)
        save_ip_btn = QPushButton("💾 Save IP")
        save_ip_btn.setFont(QFont("Consolas", 9))
        save_ip_btn.clicked.connect(self._save_selected_ip)
        ip_btn_row.addWidget(geo_quick)
        ip_btn_row.addWidget(save_ip_btn)

        ip_lay.addWidget(self._ip_table)
        ip_lay.addLayout(ip_btn_row)
        splitter.addWidget(ip_panel)
        splitter.setSizes([900, 350])

        lay.addWidget(splitter)

        # Stats bar
        stats = QHBoxLayout()
        self._pkt_count_lbl = QLabel("Packets: 0")
        self._ip_count_lbl = QLabel("Unique IPs: 0")
        self._bytes_lbl = QLabel("Total Bytes: 0")
        self._mode_lbl = QLabel("Mode: IDLE")
        for w in [self._pkt_count_lbl, self._ip_count_lbl, self._bytes_lbl, self._mode_lbl]:
            w.setFont(QFont("Consolas", 9))
            stats.addWidget(w)
        stats.addStretch()
        lay.addLayout(stats)

        self._tabs.addTab(tab, "⚡ SNIFFER")
        self._on_profile_change(self._profile_combo.currentText())

        # Stats counters
        self._total_bytes = 0
        self._total_pkts = 0

    # ── IP Log Tab ─────────────────────────────────────────────────────────────

    def _build_ip_log_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)

        lbl = QLabel("Live IP Activity Log — color-coded by direction and protocol")
        lbl.setFont(QFont("Consolas", 10))
        lay.addWidget(lbl)

        self._log_text = QTextEdit()
        self._log_text.setReadOnly(True)
        self._log_text.setFont(QFont("Consolas", 9))
        lay.addWidget(self._log_text)

        btn_row = QHBoxLayout()
        clr_log = QPushButton("✕ Clear Log")
        clr_log.clicked.connect(self._log_text.clear)
        save_log = QPushButton("⬇ Save Log")
        save_log.clicked.connect(self._save_log)
        btn_row.addWidget(clr_log)
        btn_row.addWidget(save_log)
        btn_row.addStretch()
        lay.addLayout(btn_row)

        self._tabs.addTab(tab, "📋 IP LOG")

    # ── Pinger Tab ─────────────────────────────────────────────────────────────

    def _build_pinger_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)

        top = QHBoxLayout()
        self._ping_host = QLineEdit()
        self._ping_host.setPlaceholderText("IP or hostname  (e.g. 8.8.8.8)")
        self._ping_host.setFont(QFont("Consolas", 11))
        self._ping_count = QSpinBox()
        self._ping_count.setRange(1, 100)
        self._ping_count.setValue(4)
        self._ping_count.setFont(QFont("Consolas", 10))
        self._ping_btn = QPushButton("▶ PING")
        self._ping_btn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        self._ping_btn.clicked.connect(self._run_ping)
        top.addWidget(QLabel("Host:"))
        top.addWidget(self._ping_host, 3)
        top.addWidget(QLabel("Count:"))
        top.addWidget(self._ping_count)
        top.addWidget(self._ping_btn)
        lay.addLayout(top)

        self._ping_result = QTextEdit()
        self._ping_result.setReadOnly(True)
        self._ping_result.setFont(QFont("Consolas", 10))
        lay.addWidget(self._ping_result)

        # Ping stats
        stats_box = QGroupBox("Last Ping Stats")
        stats_lay = QFormLayout(stats_box)
        self._ping_min = QLabel("—")
        self._ping_max = QLabel("—")
        self._ping_avg = QLabel("—")
        self._ping_loss = QLabel("—")
        for lbl, w in [("Min RTT:", self._ping_min), ("Max RTT:", self._ping_max),
                        ("Avg RTT:", self._ping_avg), ("Packet Loss:", self._ping_loss)]:
            stats_lay.addRow(lbl, w)
            w.setFont(QFont("Consolas", 10))
        lay.addWidget(stats_box)

        self._tabs.addTab(tab, "📡 PINGER")

    # ── Port Scanner Tab ───────────────────────────────────────────────────────

    def _build_portscanner_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)

        top = QHBoxLayout()
        self._scan_host = QLineEdit()
        self._scan_host.setPlaceholderText("Target IP or host")
        self._scan_host.setFont(QFont("Consolas", 11))
        self._scan_ports_edit = QLineEdit()
        self._scan_ports_edit.setPlaceholderText("Ports: 22,80,443 or 1-1024 (blank = common)")
        self._scan_ports_edit.setFont(QFont("Consolas", 10))
        self._scan_timeout = QSpinBox()
        self._scan_timeout.setRange(100, 5000)
        self._scan_timeout.setValue(500)
        self._scan_timeout.setSuffix(" ms")
        self._scan_btn = QPushButton("▶ SCAN")
        self._scan_btn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        self._scan_btn.clicked.connect(self._run_scan)
        top.addWidget(QLabel("Host:"))
        top.addWidget(self._scan_host, 2)
        top.addWidget(QLabel("Ports:"))
        top.addWidget(self._scan_ports_edit, 2)
        top.addWidget(QLabel("Timeout:"))
        top.addWidget(self._scan_timeout)
        top.addWidget(self._scan_btn)
        lay.addLayout(top)

        self._scan_progress = QProgressBar()
        self._scan_progress.setValue(0)
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
        self._geo_ip.setPlaceholderText("Enter IP address to geolocate")
        self._geo_ip.setFont(QFont("Consolas", 11))
        self._geo_btn = QPushButton("🌍 LOCATE")
        self._geo_btn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        self._geo_btn.clicked.connect(self._run_geo)
        top.addWidget(self._geo_ip, 3)
        top.addWidget(self._geo_btn)
        lay.addLayout(top)

        self._geo_result = QTextEdit()
        self._geo_result.setReadOnly(True)
        self._geo_result.setFont(QFont("Consolas", 11))
        lay.addWidget(self._geo_result)

        # Map-style display (text-based)
        geo_info = QGroupBox("Location Details")
        geo_grid = QGridLayout(geo_info)
        fields = ["IP", "Country", "Region", "City", "ZIP",
                  "Latitude", "Longitude", "Timezone", "ISP", "Organization", "AS"]
        self._geo_fields = {}
        for i, f in enumerate(fields):
            lbl = QLabel(f + ":")
            lbl.setFont(QFont("Consolas", 10))
            val = QLabel("—")
            val.setFont(QFont("Consolas", 10))
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            geo_grid.addWidget(lbl, i // 2, (i % 2) * 2)
            geo_grid.addWidget(val, i // 2, (i % 2) * 2 + 1)
            self._geo_fields[f] = val
        lay.addWidget(geo_info)

        self._tabs.addTab(tab, "🌍 GEOIP")

    # ── IP Storage Tab ─────────────────────────────────────────────────────────

    def _build_storage_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)

        add_row = QHBoxLayout()
        self._store_ip = QLineEdit()
        self._store_ip.setPlaceholderText("IP Address")
        self._store_ip.setFont(QFont("Consolas", 10))
        self._store_name = QLineEdit()
        self._store_name.setPlaceholderText("Label / Name")
        self._store_name.setFont(QFont("Consolas", 10))
        self._store_note = QLineEdit()
        self._store_note.setPlaceholderText("Notes")
        self._store_note.setFont(QFont("Consolas", 10))
        add_btn = QPushButton("+ ADD")
        add_btn.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
        add_btn.clicked.connect(self._add_stored_ip)
        add_row.addWidget(QLabel("IP:"))
        add_row.addWidget(self._store_ip, 2)
        add_row.addWidget(QLabel("Name:"))
        add_row.addWidget(self._store_name, 2)
        add_row.addWidget(QLabel("Note:"))
        add_row.addWidget(self._store_note, 3)
        add_row.addWidget(add_btn)
        lay.addLayout(add_row)

        self._storage_table = QTableWidget(0, 5)
        self._storage_table.setHorizontalHeaderLabels(
            ["IP Address", "Name", "Notes", "Date Added", "Actions"]
        )
        self._storage_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._storage_table.setFont(QFont("Consolas", 10))
        self._storage_table.verticalHeader().setVisible(False)
        lay.addWidget(self._storage_table)

        btn_row = QHBoxLayout()
        del_btn = QPushButton("🗑 Delete Selected")
        del_btn.clicked.connect(self._delete_stored_ip)
        export_btn = QPushButton("⬇ Export JSON")
        export_btn.clicked.connect(self._export_stored)
        import_btn = QPushButton("⬆ Import JSON")
        import_btn.clicked.connect(self._import_stored)
        btn_row.addWidget(del_btn)
        btn_row.addWidget(export_btn)
        btn_row.addWidget(import_btn)
        btn_row.addStretch()
        lay.addLayout(btn_row)

        self._tabs.addTab(tab, "💾 IP STORAGE")
        self._load_stored_ips()

    # ── SSH Tab ────────────────────────────────────────────────────────────────

    def _build_ssh_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)

        conn_box = QGroupBox("SSH Connection")
        conn_lay = QFormLayout(conn_box)
        self._ssh_host = QLineEdit()
        self._ssh_host.setPlaceholderText("192.168.1.1")
        self._ssh_host.setFont(QFont("Consolas", 10))
        self._ssh_user = QLineEdit()
        self._ssh_user.setPlaceholderText("root")
        self._ssh_user.setFont(QFont("Consolas", 10))
        self._ssh_pass = QLineEdit()
        self._ssh_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._ssh_pass.setFont(QFont("Consolas", 10))
        self._ssh_port = QSpinBox()
        self._ssh_port.setRange(1, 65535)
        self._ssh_port.setValue(22)
        conn_lay.addRow("Host:", self._ssh_host)
        conn_lay.addRow("User:", self._ssh_user)
        conn_lay.addRow("Password:", self._ssh_pass)
        conn_lay.addRow("Port:", self._ssh_port)
        lay.addWidget(conn_box)

        cmd_row = QHBoxLayout()
        self._ssh_cmd = QLineEdit()
        self._ssh_cmd.setPlaceholderText("Command (e.g. whoami, ls -la, cat /etc/passwd)")
        self._ssh_cmd.setFont(QFont("Consolas", 10))
        self._ssh_cmd.returnPressed.connect(self._run_ssh)
        self._ssh_btn = QPushButton("▶ RUN")
        self._ssh_btn.setFont(QFont("Consolas", 11, QFont.Weight.Bold))
        self._ssh_btn.clicked.connect(self._run_ssh)
        cmd_row.addWidget(self._ssh_cmd, 4)
        cmd_row.addWidget(self._ssh_btn)
        lay.addLayout(cmd_row)

        self._ssh_output = QTextEdit()
        self._ssh_output.setReadOnly(True)
        self._ssh_output.setFont(QFont("Consolas", 10))
        lay.addWidget(self._ssh_output)

        # Quick commands
        quick_box = QGroupBox("Quick Commands")
        quick_lay = QHBoxLayout(quick_box)
        quick_cmds = [
            ("whoami", "whoami"), ("hostname", "hostname"), ("ifconfig", "ip a || ifconfig"),
            ("netstat", "netstat -an | head -30"), ("processes", "ps aux | head -20"),
            ("uptime", "uptime"), ("df", "df -h"), ("users", "who"),
        ]
        for label, cmd in quick_cmds:
            btn = QPushButton(label)
            btn.setFont(QFont("Consolas", 9))
            btn.clicked.connect(lambda _, c=cmd: self._ssh_quick(c))
            quick_lay.addWidget(btn)
        lay.addWidget(quick_box)

        self._tabs.addTab(tab, "🔒 SSH")

    # ── Theme Tab ──────────────────────────────────────────────────────────────

    def _build_theme_tab(self):
        tab = QWidget()
        lay = QVBoxLayout(tab)
        lay.setSpacing(12)

        # Colors
        color_box = QGroupBox("Colors")
        color_lay = QGridLayout(color_box)

        self._accent_preview = QLabel("■ Primary Accent")
        self._accent_preview.setFont(QFont("Consolas", 12))
        self._accent_preview2 = QLabel("■ Secondary Accent")
        self._accent_preview2.setFont(QFont("Consolas", 12))
        self._bg_preview = QLabel("■ Background Color")
        self._bg_preview.setFont(QFont("Consolas", 12))

        btn_a1 = QPushButton("Change Primary")
        btn_a1.clicked.connect(lambda: self._pick_color("accent"))
        btn_a2 = QPushButton("Change Secondary")
        btn_a2.clicked.connect(lambda: self._pick_color("accent2"))
        btn_bg = QPushButton("Change Background")
        btn_bg.clicked.connect(lambda: self._pick_color("bg_color"))
        btn_reset = QPushButton("Reset to Default (Red/Black)")
        btn_reset.clicked.connect(self._reset_colors)

        color_lay.addWidget(self._accent_preview, 0, 0)
        color_lay.addWidget(btn_a1, 0, 1)
        color_lay.addWidget(self._accent_preview2, 1, 0)
        color_lay.addWidget(btn_a2, 1, 1)
        color_lay.addWidget(self._bg_preview, 2, 0)
        color_lay.addWidget(btn_bg, 2, 1)
        color_lay.addWidget(btn_reset, 3, 0, 1, 2)
        lay.addWidget(color_box)

        # Background image
        img_box = QGroupBox("Background Image")
        img_lay = QHBoxLayout(img_box)
        self._bg_path_lbl = QLabel("No image loaded")
        self._bg_path_lbl.setFont(QFont("Consolas", 9))
        btn_load_img = QPushButton("📂 Load JPEG / PNG / GIF")
        btn_load_img.clicked.connect(self._load_bg_image)
        btn_clear_img = QPushButton("✕ Clear Image")
        btn_clear_img.clicked.connect(self._clear_bg_image)
        img_lay.addWidget(self._bg_path_lbl, 2)
        img_lay.addWidget(btn_load_img)
        img_lay.addWidget(btn_clear_img)
        lay.addWidget(img_box)

        # Font size
        font_box = QGroupBox("Font Size")
        font_lay = QHBoxLayout(font_box)
        self._font_slider = QSlider(Qt.Orientation.Horizontal)
        self._font_slider.setRange(8, 16)
        self._font_slider.setValue(self.settings.get("font_size", 11))
        self._font_size_lbl = QLabel(str(self._font_slider.value()) + "pt")
        self._font_slider.valueChanged.connect(
            lambda v: (self._font_size_lbl.setText(f"{v}pt"),
                       self.settings.update({"font_size": v}),
                       save_settings(self.settings))
        )
        font_lay.addWidget(self._font_slider)
        font_lay.addWidget(self._font_size_lbl)
        lay.addWidget(font_box)

        # Max packet buffer
        buf_box = QGroupBox("Packet Buffer Size")
        buf_lay = QHBoxLayout(buf_box)
        self._buf_spin = QSpinBox()
        self._buf_spin.setRange(100, 10000)
        self._buf_spin.setValue(self.settings.get("max_packets", 1000))
        self._buf_spin.setSuffix(" packets")
        self._buf_spin.valueChanged.connect(
            lambda v: (self.settings.update({"max_packets": v}), save_settings(self.settings))
        )
        buf_lay.addWidget(QLabel("Max rows in packet table:"))
        buf_lay.addWidget(self._buf_spin)
        buf_lay.addStretch()
        lay.addWidget(buf_box)

        lay.addStretch()
        self._tabs.addTab(tab, "🎨 THEME")
        self._update_color_previews()

    # ── Engine callbacks ───────────────────────────────────────────────────────

    def _on_packet(self, pkt):
        self._total_pkts += 1
        self._total_bytes += pkt["size"]

        # Trim table
        max_pkts = self.settings.get("max_packets", 1000)
        if self._pkt_table.rowCount() >= max_pkts:
            self._pkt_table.removeRow(0)

        row = self._pkt_table.rowCount()
        self._pkt_table.insertRow(row)
        cells = [
            pkt["ts"], pkt["direction"], pkt["proto"],
            pkt["src"], str(pkt["sport"]),
            pkt["dst"], str(pkt["dport"]),
            str(pkt["size"]),
        ]
        for col, val in enumerate(cells):
            item = QTableWidgetItem(val)
            item.setFont(QFont("Consolas", 9))
            # Color by direction
            if pkt["direction"] == "IN":
                item.setForeground(QColor(self.settings["accent2"]))
            else:
                item.setForeground(QColor("#aaaaaa"))
            if pkt.get("new"):
                item.setBackground(QColor(30, 0, 0))
            self._pkt_table.setItem(row, col, item)

        self._pkt_table.scrollToBottom()

        # Update IP list
        for ip in [pkt["src"], pkt["dst"]]:
            if ip not in self.captured_ips:
                self.captured_ips[ip] = {"count": 0, "last_seen": ""}
            self.captured_ips[ip]["count"] += 1
            self.captured_ips[ip]["last_seen"] = pkt["ts"]

        self._refresh_ip_table()

        # Log tab
        self._log_packet(pkt)

        # Stats
        self._pkt_count_lbl.setText(f"Packets: {self._total_pkts}")
        self._ip_count_lbl.setText(f"Unique IPs: {len(self.captured_ips)}")
        self._bytes_lbl.setText(f"Total Bytes: {self._total_bytes:,}")

    def _on_status(self, msg):
        self._status_lbl.setText(msg)

    # ── Sniffer controls ───────────────────────────────────────────────────────

    def _toggle_sniff(self):
        if self.engine.is_running():
            self.engine.stop()
            self._start_btn.setText("▶  START")
            self._mode_lbl.setText("Mode: STOPPED")
            self._on_status("● STOPPED")
        else:
            f = self._filter_edit.text().strip() or "true"
            self.engine.start(f)
            self._start_btn.setText("⏹  STOP")
            mode = "SIMULATION" if self.engine.simulation else "LIVE"
            self._mode_lbl.setText(f"Mode: {mode}")
            self._on_status(f"● RUNNING [{mode}]")

    def _on_profile_change(self, name):
        p = SNIFFER_PROFILES.get(name, {})
        self._filter_edit.setText(p.get("filter", "true"))
        self._profile_desc.setText(f"  {p.get('description','')}")

    def _clear_packets(self):
        self._pkt_table.setRowCount(0)
        self.captured_ips.clear()
        self._ip_table.setRowCount(0)
        self._total_pkts = 0
        self._total_bytes = 0
        self._pkt_count_lbl.setText("Packets: 0")
        self._ip_count_lbl.setText("Unique IPs: 0")
        self._bytes_lbl.setText("Total Bytes: 0")

    def _export_packets(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Packets", "packets.json",
                                               "JSON (*.json);;CSV (*.csv)")
        if not path:
            return
        rows = []
        for r in range(self._pkt_table.rowCount()):
            row = [self._pkt_table.item(r, c).text() if self._pkt_table.item(r, c) else ""
                   for c in range(self._pkt_table.columnCount())]
            rows.append(row)
        if path.endswith(".csv"):
            with open(path, "w") as f:
                f.write("Time,Dir,Proto,SrcIP,SPort,DstIP,DPort,Bytes\n")
                for r in rows:
                    f.write(",".join(r) + "\n")
        else:
            with open(path, "w") as f:
                json.dump(rows, f, indent=2)

    def _refresh_ip_table(self):
        self._ip_table.setRowCount(0)
        sorted_ips = sorted(self.captured_ips.items(), key=lambda x: x[1]["count"], reverse=True)
        for ip, data in sorted_ips[:200]:
            r = self._ip_table.rowCount()
            self._ip_table.insertRow(r)
            for c, val in enumerate([ip, str(data["count"]), data["last_seen"]]):
                item = QTableWidgetItem(val)
                item.setFont(QFont("Consolas", 9))
                self._ip_table.setItem(r, c, item)

    def _pkt_double_click(self, row, col):
        ip_col = 3 if col < 5 else 5
        item = self._pkt_table.item(row, ip_col)
        if item:
            self._geo_ip.setText(item.text())
            self._tabs.setCurrentIndex(4)
            self._run_geo()

    def _quick_geo(self):
        rows = self._ip_table.selectedItems()
        if rows:
            ip = rows[0].text()
            self._geo_ip.setText(ip)
            self._tabs.setCurrentIndex(4)
            self._run_geo()

    def _save_selected_ip(self):
        rows = self._ip_table.selectedItems()
        if rows:
            ip = rows[0].text()
            self._store_ip.setText(ip)
            self._tabs.setCurrentIndex(5)

    # ── Log tab ────────────────────────────────────────────────────────────────

    def _log_packet(self, pkt):
        color_map = {"IN": self.settings["accent2"], "OUT": "#888888"}
        proto_color = {"TCP": "#5599ff", "UDP": "#ffaa00"}.get(pkt["proto"], "#ffffff")
        color = color_map.get(pkt["direction"], "#aaaaaa")

        line = (f'<span style="color:{color}">'
                f'[{pkt["ts"]}] {pkt["direction"]} {pkt["proto"]} '
                f'{pkt["src"]}:{pkt["sport"]} → {pkt["dst"]}:{pkt["dport"]} '
                f'({pkt["size"]}B)</span><br>')
        self._log_text.insertHtml(line)
        self._log_text.ensureCursorVisible()

    def _save_log(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Log", "dvrksniff_log.txt",
                                               "Text (*.txt);;HTML (*.html)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._log_text.toPlainText() if path.endswith(".txt") else
                        self._log_text.toHtml())

    # ── Pinger ─────────────────────────────────────────────────────────────────

    def _run_ping(self):
        host = self._ping_host.text().strip()
        if not host:
            return
        self._ping_btn.setEnabled(False)
        self._ping_result.setPlainText(f"Pinging {host}...\n")
        self._ping_worker = PingWorker(host, self._ping_count.value())
        self._ping_worker.result.connect(self._show_ping_result)
        self._ping_worker.start()

    def _show_ping_result(self, results):
        self._ping_btn.setEnabled(True)
        lines = []
        times = []
        for r in results:
            prefix = "✓" if r["success"] else "✗"
            lines.append(f"{prefix}  {r['line']}")
            # Parse ms
            try:
                part = [x for x in r["line"].split() if "time" in x.lower()]
                if part:
                    ms_str = part[0].split("=")[-1].replace("ms", "").strip()
                    times.append(float(ms_str))
            except Exception:
                pass
        self._ping_result.setPlainText("\n".join(lines))
        if times:
            self._ping_min.setText(f"{min(times):.1f} ms")
            self._ping_max.setText(f"{max(times):.1f} ms")
            self._ping_avg.setText(f"{sum(times)/len(times):.1f} ms")
            total = len(results)
            success = sum(1 for r in results if r["success"])
            loss = ((total - success) / total * 100) if total else 100
            self._ping_loss.setText(f"{loss:.0f}%")

    # ── Port Scanner ───────────────────────────────────────────────────────────

    def _run_scan(self):
        host = self._scan_host.text().strip()
        if not host:
            return
        ports_txt = self._scan_ports_edit.text().strip()
        ports = None
        if ports_txt:
            try:
                if "-" in ports_txt:
                    a, b = ports_txt.split("-")
                    ports = list(range(int(a), int(b) + 1))
                else:
                    ports = [int(x.strip()) for x in ports_txt.split(",") if x.strip()]
            except Exception:
                pass

        self._scan_btn.setEnabled(False)
        self._scan_table.setRowCount(0)
        self._scan_progress.setValue(0)
        timeout = self._scan_timeout.value() / 1000.0

        self._scan_worker = ScanWorker(host, ports, timeout)
        self._scan_worker.progress.connect(self._scan_progress_update)
        self._scan_worker.result.connect(self._show_scan_result)
        self._scan_worker.start()

    def _scan_progress_update(self, current, total, port):
        pct = int(current / total * 100)
        self._scan_progress.setValue(pct)

    def _show_scan_result(self, results):
        self._scan_btn.setEnabled(True)
        self._scan_progress.setValue(100)
        for r in results:
            row = self._scan_table.rowCount()
            self._scan_table.insertRow(row)
            status = "OPEN" if r["open"] else "closed"
            color = QColor(self.settings["accent2"]) if r["open"] else QColor("#555555")
            for c, val in enumerate([str(r["port"]), r["service"], status, r["banner"]]):
                item = QTableWidgetItem(val)
                item.setFont(QFont("Consolas", 10))
                item.setForeground(color)
                self._scan_table.setItem(row, c, item)

    # ── GeoIP ──────────────────────────────────────────────────────────────────

    def _run_geo(self):
        ip = self._geo_ip.text().strip()
        if not ip:
            return
        self._geo_btn.setEnabled(False)
        self._geo_result.setPlainText(f"Looking up {ip}...")
        self._geo_worker = GeoWorker(ip)
        self._geo_worker.result.connect(self._show_geo_result)
        self._geo_worker.start()

    def _show_geo_result(self, data):
        self._geo_btn.setEnabled(True)
        if "error" in data:
            self._geo_result.setPlainText(f"Error: {data['error']}")
            return

        mapping = {
            "IP": "query", "Country": "country", "Region": "regionName",
            "City": "city", "ZIP": "zip", "Latitude": "lat",
            "Longitude": "lon", "Timezone": "timezone",
            "ISP": "isp", "Organization": "org", "AS": "as",
        }
        for field, key in mapping.items():
            val = str(data.get(key, "—"))
            self._geo_fields[field].setText(val)

        summary = (
            f"╔══════════════════════════════════════╗\n"
            f"║  IP:       {data.get('query',''):<28}║\n"
            f"║  Country:  {data.get('country',''):<28}║\n"
            f"║  City:     {data.get('city',''):<28}║\n"
            f"║  ISP:      {str(data.get('isp',''))[:28]:<28}║\n"
            f"║  Coords:   {data.get('lat','')}, {data.get('lon',''):<22}║\n"
            f"║  Timezone: {data.get('timezone',''):<28}║\n"
            f"╚══════════════════════════════════════╝"
        )
        self._geo_result.setPlainText(summary)

    # ── IP Storage ─────────────────────────────────────────────────────────────

    def _add_stored_ip(self):
        ip = self._store_ip.text().strip()
        name = self._store_name.text().strip()
        note = self._store_note.text().strip()
        if not ip:
            return
        entry = {"ip": ip, "name": name, "note": note,
                 "date": datetime.now().strftime("%Y-%m-%d %H:%M")}
        self.saved_ips.append(entry)
        self._refresh_storage_table()
        self._persist_stored_ips()
        self._store_ip.clear()
        self._store_name.clear()
        self._store_note.clear()

    def _refresh_storage_table(self):
        self._storage_table.setRowCount(0)
        for entry in self.saved_ips:
            r = self._storage_table.rowCount()
            self._storage_table.insertRow(r)
            for c, val in enumerate([entry["ip"], entry["name"], entry["note"], entry["date"], ""]):
                item = QTableWidgetItem(val)
                item.setFont(QFont("Consolas", 10))
                self._storage_table.setItem(r, c, item)
            # Quick geo button per row
            geo_btn = QPushButton("🌍")
            geo_btn.setFixedWidth(40)
            ip = entry["ip"]
            geo_btn.clicked.connect(lambda _, i=ip: self._geo_from_storage(i))
            self._storage_table.setCellWidget(r, 4, geo_btn)

    def _geo_from_storage(self, ip):
        self._geo_ip.setText(ip)
        self._tabs.setCurrentIndex(4)
        self._run_geo()

    def _delete_stored_ip(self):
        rows = {idx.row() for idx in self._storage_table.selectedIndexes()}
        for r in sorted(rows, reverse=True):
            if 0 <= r < len(self.saved_ips):
                self.saved_ips.pop(r)
        self._refresh_storage_table()
        self._persist_stored_ips()

    def _persist_stored_ips(self):
        path = Path.home() / ".dvrksniff_ips.json"
        with open(path, "w") as f:
            json.dump(self.saved_ips, f, indent=2)

    def _load_stored_ips(self):
        path = Path.home() / ".dvrksniff_ips.json"
        if path.exists():
            try:
                with open(path) as f:
                    self.saved_ips = json.load(f)
                self._refresh_storage_table()
            except Exception:
                pass

    def _export_stored(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export IPs", "saved_ips.json", "JSON (*.json)")
        if path:
            with open(path, "w") as f:
                json.dump(self.saved_ips, f, indent=2)

    def _import_stored(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import IPs", "", "JSON (*.json)")
        if path:
            with open(path) as f:
                data = json.load(f)
            self.saved_ips.extend(data)
            self._refresh_storage_table()
            self._persist_stored_ips()

    # ── SSH ────────────────────────────────────────────────────────────────────

    def _run_ssh(self):
        host = self._ssh_host.text().strip()
        user = self._ssh_user.text().strip()
        password = self._ssh_pass.text()
        port = self._ssh_port.value()
        cmd = self._ssh_cmd.text().strip()
        if not host or not cmd:
            return
        self._ssh_btn.setEnabled(False)
        self._ssh_output.append(f"\n$ {cmd}\n")
        self._ssh_worker = SSHWorker(host, user, password, port, cmd)
        self._ssh_worker.output.connect(self._show_ssh_output)
        self._ssh_worker.start()

    def _show_ssh_output(self, text):
        self._ssh_btn.setEnabled(True)
        self._ssh_output.append(text)

    def _ssh_quick(self, cmd):
        self._ssh_cmd.setText(cmd)
        self._run_ssh()

    # ── Theme ──────────────────────────────────────────────────────────────────

    def _pick_color(self, key):
        current = QColor(self.settings.get(key, "#cc0000"))
        color = QColorDialog.getColor(current, self, f"Pick {key}")
        if color.isValid():
            self.settings[key] = color.name()
            save_settings(self.settings)
            self._apply_theme()
            self._update_color_previews()

    def _reset_colors(self):
        self.settings["accent"] = "#cc0000"
        self.settings["accent2"] = "#ff3333"
        self.settings["bg_color"] = "#0a0000"
        save_settings(self.settings)
        self._apply_theme()
        self._update_color_previews()

    def _update_color_previews(self):
        a = self.settings["accent"]
        a2 = self.settings["accent2"]
        bg = self.settings["bg_color"]
        self._accent_preview.setStyleSheet(f"color: {a}; font-size: 14px;")
        self._accent_preview2.setStyleSheet(f"color: {a2}; font-size: 14px;")
        self._bg_preview.setStyleSheet(f"color: {bg}; background: #333; font-size: 14px;")

    def _load_bg_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Background", "",
            "Images (*.jpg *.jpeg *.png *.gif *.bmp *.webp)"
        )
        if path:
            self.settings["bg_image"] = path
            save_settings(self.settings)
            self._bg.set_image(path)
            self._bg_path_lbl.setText(os.path.basename(path))

    def _clear_bg_image(self):
        self.settings["bg_image"] = ""
        save_settings(self.settings)
        self._bg.set_image("")
        self._bg_path_lbl.setText("No image loaded")

    def _apply_theme(self):
        a = self.settings["accent"]
        a2 = self.settings["accent2"]
        bg = self.settings["bg_color"]
        fs = self.settings.get("font_size", 11)

        # Title
        self._title_lbl.setStyleSheet(f"color: {a}; background: transparent;")
        self._credit_lbl.setStyleSheet(f"color: {a2}; background: transparent;")
        self._status_lbl.setStyleSheet(f"color: {a2}; background: transparent;")
        self._profile_desc.setStyleSheet("color: #888888; background: transparent;")

        # Global stylesheet
        qss = f"""
        QWidget {{
            background: transparent;
            color: #dddddd;
            font-family: Consolas, monospace;
            font-size: {fs}pt;
        }}
        QTabWidget::pane {{
            border: 1px solid {a};
            background: rgba(10, 0, 0, 0.85);
        }}
        QTabBar::tab {{
            background: rgba(20, 0, 0, 0.9);
            color: #aaaaaa;
            border: 1px solid #330000;
            padding: 6px 16px;
            font-size: {fs - 1}pt;
        }}
        QTabBar::tab:selected {{
            background: rgba(40, 0, 0, 0.95);
            color: {a};
            border-bottom: 2px solid {a};
        }}
        QTabBar::tab:hover {{
            color: {a2};
        }}
        QPushButton {{
            background: rgba(80, 0, 0, 0.8);
            color: {a2};
            border: 1px solid {a};
            border-radius: 3px;
            padding: 5px 12px;
        }}
        QPushButton:hover {{
            background: {a};
            color: #000000;
        }}
        QPushButton:disabled {{
            background: #222222;
            color: #555555;
            border: 1px solid #333333;
        }}
        QLineEdit, QSpinBox, QComboBox, QTextEdit {{
            background: rgba(15, 0, 0, 0.9);
            color: #dddddd;
            border: 1px solid {a};
            border-radius: 3px;
            padding: 4px;
            selection-background-color: {a};
        }}
        QTableWidget {{
            background: rgba(10, 0, 0, 0.88);
            color: #cccccc;
            gridline-color: #330000;
            border: 1px solid {a};
            alternate-background-color: rgba(20, 0, 0, 0.7);
        }}
        QTableWidget::item:selected {{
            background: rgba(180, 0, 0, 0.6);
            color: #ffffff;
        }}
        QHeaderView::section {{
            background: rgba(40, 0, 0, 0.95);
            color: {a};
            border: 1px solid #330000;
            padding: 4px;
            font-weight: bold;
        }}
        QGroupBox {{
            border: 1px solid {a};
            border-radius: 4px;
            margin-top: 8px;
            padding-top: 8px;
            background: rgba(10, 0, 0, 0.6);
            color: {a2};
        }}
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: 10px;
            color: {a};
        }}
        QProgressBar {{
            background: rgba(20, 0, 0, 0.8);
            border: 1px solid {a};
            color: #ffffff;
            text-align: center;
        }}
        QProgressBar::chunk {{
            background: {a};
        }}
        QScrollBar:vertical {{
            background: rgba(10,0,0,0.8);
            width: 10px;
        }}
        QScrollBar::handle:vertical {{
            background: {a};
            min-height: 20px;
        }}
        QLabel {{
            color: #cccccc;
            background: transparent;
        }}
        QSplitter::handle {{
            background: {a};
        }}
        """
        QApplication.instance().setStyleSheet(qss)
        self._bg.set_bg_color(bg)
        self._bg.set_accent(a, a2)


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("DVRKSNIFF")
    app.setOrganizationName("botnet1337")

    # Set app icon if bundled
    icon_path = os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(__file__)), "icon.ico")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))

    win = DVRKSniff()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
