#!/usr/bin/env python3
"""
Safffire v2 — Dark Sapphire Pro (Performance Fixed)
Key fixes:
1. Batch packet processing to reduce GUI updates
2. Deferred UI updates using QTimer
3. Limited list widget items to prevent slowdown
4. Optimized signal emissions
"""

import os
import sys
import json
import threading
import time
import re
from datetime import datetime
from collections import deque, Counter, defaultdict

# PyQt5
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QObject, QPropertyAnimation, QRect
from PyQt5.QtGui import QIcon, QPixmap, QFontDatabase
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QPushButton,
    QLabel, QTextEdit, QComboBox, QFileDialog, QMessageBox, QSplitter,
    QTabWidget, QLineEdit, QSlider, QProgressBar, QDialog, QFormLayout, QSpinBox,
    QCheckBox, QFrame, QInputDialog, QListWidgetItem
)

# Matplotlib for plots
import numpy as np
import matplotlib
matplotlib.use("Qt5Agg")
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# scapy
try:
    from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, ARP, Ether
except Exception:
    print("scapy is required. Install: pip install scapy")
    raise

# Optional libraries
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    SKLEARN = True
except Exception:
    SKLEARN = False

try:
    import pandas as pd
    PANDAS = True
except Exception:
    PANDAS = False

APP_NAME = "Safffire v2 - Dark Sapphire Pro"
LOG_DIR = os.path.join(os.path.expanduser("~"), ".safffire")
os.makedirs(LOG_DIR, exist_ok=True)

def resource_path(rel):
    base = getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__)))
    return os.path.join(base, rel)

# ---------- Signals ----------
class Comms(QObject):
    # Removed individual packet signal - use batch processing instead
    status_signal = pyqtSignal(str)
    suspicious_signal = pyqtSignal(dict)
    update_plots = pyqtSignal()
    update_ui = pyqtSignal()  # Signal for safe UI updates from main thread

# ---------- Detector (Hybrid) ----------
class HybridDetector:
    def __init__(self):
        self.use_ml = SKLEARN
        self.if_model = None
        self.ocsvm = None
        self.trained = False
        self.buffer = []
        self.min_train = 150
        if self.use_ml:
            try:
                self.if_model = IsolationForest(n_estimators=100, contamination=0.02, random_state=42)
                self.ocsvm = OneClassSVM(gamma='auto', nu=0.02)
            except Exception:
                self.use_ml = False

    def featurize(self, pkt):
        length = float(pkt.get("length", 0))
        proto = pkt.get("proto", "UNK")
        proto_id = float({'ICMP':1,'TCP':6,'UDP':17,'ARP':0}.get(proto, 100))
        src_hash = float(abs(hash(pkt.get("src",""))) % 1000)
        dst_hash = float(abs(hash(pkt.get("dst",""))) % 1000)
        sport = float(pkt.get("sport", 0))
        dport = float(pkt.get("dport", 0))
        return np.array([length, proto_id, src_hash, dst_hash, sport, dport], dtype=float)

    def partial_fit(self, pkt):
        if not self.use_ml: return
        try:
            vec = self.featurize(pkt)
            self.buffer.append(vec)
            if (not self.trained) and len(self.buffer) >= self.min_train:
                X = np.vstack(self.buffer)
                self.if_model.fit(X)
                try:
                    self.ocsvm.fit(X)
                except Exception:
                    pass
                self.trained = True
                self.buffer = []
        except Exception:
            pass

    def is_suspicious(self, pkt):
        if self.use_ml and self.trained:
            try:
                v = self.featurize(pkt).reshape(1, -1)
                pred_if = self.if_model.predict(v)[0]
                pred_oc = 1
                if self.ocsvm is not None:
                    pred_oc = self.ocsvm.predict(v)[0]
                return (pred_if == -1) or (pred_oc == -1)
            except Exception:
                return False
        else:
            length = pkt.get("length", 0)
            proto = pkt.get("proto", "")
            if length > 3000: return True
            if proto == "ICMP" and length > 1000: return True
            return False

# ---------- Plots ----------
class MatCanvas(FigureCanvas):
    def __init__(self, width=4, height=2, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)
        super().__init__(fig)
        self.ax = fig.add_subplot(111)
        fig.tight_layout()

# ---------- Main App ----------
class Safffire(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1250, 800)
        # load font & icon
        if os.path.exists(resource_path("Orbitron.ttf")):
            QFontDatabase.addApplicationFont(resource_path("Orbitron.ttf"))
        if os.path.exists(resource_path("logo.png")):
            self.setWindowIcon(QIcon(resource_path("logo.png")))

        # core
        self.comms = Comms()
        self.comms.status_signal.connect(self._append_status)
        self.comms.suspicious_signal.connect(self._on_suspicious)
        self.comms.update_plots.connect(self._refresh_plots)
        self.comms.update_ui.connect(self._update_ui_safe)  # Connect UI update signal

        self.detector = HybridDetector()
        self.packets = []  # list of pkt dicts
        self.suspicious = []
        self.running = False
        self.queue = deque(maxlen=10000)
        
        # PERFORMANCE FIX: Batch processing buffer
        self.pending_packets = []
        self.pending_lock = threading.Lock()
        
        # Temporary storage for UI updates
        self.pending_ui_packets = []
        self.pending_ui_suspicious = []

        # analytics state
        self.protocol_counter = Counter()
        self.dst_counter = Counter()
        self.src_to_macs = defaultdict(set)
        self.ip_mac_map = {}
        self.port_scan_candidates = defaultdict(list)
        self.alerts = deque(maxlen=200)
        
        # Display limits to prevent GUI slowdown
        self.MAX_DISPLAY_PACKETS = 5000
        self.last_displayed_index = 0

        # UI
        self._build_ui()
        self._start_timers()

    def _build_ui(self):
        # Theme and stylesheet (dark-sapphire)
        self.setStyleSheet("""
            QWidget { background-color: #071021; color: #d8f3ff; font-family: Orbitron, Arial; }
            QTabWidget::pane { border: none; }
            QPushButton { background:#0f2a3b; color:#7fe0ff; border:1px solid #2aa6d6; padding:6px; border-radius:6px;}
            QPushButton:hover { background:#165a73; color:white; }
            QLineEdit, QComboBox, QTextEdit, QListWidget { background:#0b2030; border:1px solid #123f55; color:#cfeefe; }
            QProgressBar { border:1px solid #123f55; text-align:center; }
        """)

        main_layout = QVBoxLayout(self)

        # top bar: interface, start/stop, filter/search, save/load
        top = QHBoxLayout()
        top.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        try:
            ifs = get_if_list()
            if not ifs: ifs = ["lo"]
        except Exception:
            ifs = ["lo"]
        self.iface_combo.addItems(ifs)
        top.addWidget(self.iface_combo)

        self.start_btn = QPushButton("Start")
        self.start_btn.clicked.connect(self._toggle_capture)
        top.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self._stop_capture)
        self.stop_btn.setEnabled(False)
        top.addWidget(self.stop_btn)

        top.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("e.g., tcp, ip:192.168.1.5, port:80")
        top.addWidget(self.filter_edit)

        top.addWidget(QLabel("Search:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Regex pattern")
        top.addWidget(self.search_edit)

        self.apply_filter_btn = QPushButton("Apply")
        self.apply_filter_btn.clicked.connect(self._apply_filter)
        top.addWidget(self.apply_filter_btn)

        top.addStretch()

        self.save_btn = QPushButton("Save Session")
        self.save_btn.clicked.connect(self._save_session)
        top.addWidget(self.save_btn)

        self.load_btn = QPushButton("Load Session")
        self.load_btn.clicked.connect(self._load_session)
        top.addWidget(self.load_btn)

        self.inspect_btn = QPushButton("Inspect Packet")
        self.inspect_btn.clicked.connect(self._inspect_packet_popup)
        top.addWidget(self.inspect_btn)

        main_layout.addLayout(top)

        # Tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs, stretch=1)

        # --- Tab 1: Live Capture ---
        self.tab_capture = QWidget()
        cap_layout = QHBoxLayout(self.tab_capture)

        # left column: packet list + suspicious list + replay slider
        left_col = QVBoxLayout()
        left_col.addWidget(QLabel("Captured Packets"))
        self.pkt_list = QListWidget()
        self.pkt_list.itemClicked.connect(self._pkt_selected)
        left_col.addWidget(self.pkt_list, stretch=6)

        left_col.addWidget(QLabel("Suspicious"))
        self.susp_list = QListWidget()
        self.susp_list.itemClicked.connect(self._susp_selected)
        left_col.addWidget(self.susp_list, stretch=2)

        left_widget = QWidget()
        left_widget.setLayout(left_col)
        cap_layout.addWidget(left_widget, stretch=4)

        # right column: details + mini plots
        right_col = QVBoxLayout()
        right_col.addWidget(QLabel("Packet Details"))
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        right_col.addWidget(self.details, stretch=3)

        # mini plots
        plot_row = QHBoxLayout()
        self.canvas_rate = MatCanvas(width=4, height=2)
        self.rate_ax = self.canvas_rate.ax
        self.rate_ax.set_title("Packets/sec")
        plot_row.addWidget(self.canvas_rate)
        self.canvas_proto = MatCanvas(width=3, height=2)
        self.proto_ax = self.canvas_proto.ax
        self.proto_ax.set_title("Protocol Breakdown")
        plot_row.addWidget(self.canvas_proto)
        right_col.addLayout(plot_row, stretch=2)

        meter_row = QHBoxLayout()
        meter_row.addWidget(QLabel("Threat Level:"))
        self.threat_bar = QProgressBar()
        self.threat_bar.setMinimum(0); self.threat_bar.setMaximum(100)
        meter_row.addWidget(self.threat_bar)
        self.alert_label = QLabel("Status: Idle")
        meter_row.addWidget(self.alert_label)
        right_col.addLayout(meter_row)

        right_widget = QWidget()
        right_widget.setLayout(right_col)
        cap_layout.addWidget(right_widget, stretch=6)

        self.tabs.addTab(self.tab_capture, "Capture")

        # --- Tab 2: Dashboard ---
        self.tab_dashboard = QWidget()
        dash_layout = QVBoxLayout(self.tab_dashboard)
        self.canvas_proto_big = MatCanvas(width=5, height=3)
        self.proto_big_ax = self.canvas_proto_big.ax
        self.proto_big_ax.set_title("Protocol Distribution")
        dash_layout.addWidget(self.canvas_proto_big)
        self.canvas_dst = MatCanvas(width=8, height=2.5)
        self.dst_ax = self.canvas_dst.ax
        self.dst_ax.set_title("Top Destinations")
        dash_layout.addWidget(self.canvas_dst)
        self.tabs.addTab(self.tab_dashboard, "Analytics")

        # --- Tab 3: ML Insights ---
        self.tab_ml = QWidget()
        ml_layout = QVBoxLayout(self.tab_ml)
        self.canvas_ml = MatCanvas(width=8, height=2.5)
        self.ml_ax = self.canvas_ml.ax
        self.ml_ax.set_title("Anomaly Score History")
        ml_layout.addWidget(self.canvas_ml)
        ml_ctrl = QHBoxLayout()
        self.ml_enable_cb = QCheckBox("Enable ML Detector")
        self.ml_enable_cb.setChecked(SKLEARN)
        ml_ctrl.addWidget(self.ml_enable_cb)
        ml_ctrl.addWidget(QLabel("Train threshold:"))
        self.ml_train_spin = QSpinBox()
        self.ml_train_spin.setRange(50, 2000)
        self.ml_train_spin.setValue(150)
        ml_ctrl.addWidget(self.ml_train_spin)
        ml_ctrl.addStretch()
        ml_layout.addLayout(ml_ctrl)
        self.tabs.addTab(self.tab_ml, "ML Insights")

        # bottom status
        bottom = QHBoxLayout()
        self.status = QLabel("Idle")
        bottom.addWidget(self.status)
        bottom.addStretch()
        bottom.addWidget(QLabel("Total Packets:"))
        self.packet_count_label = QLabel("0")
        bottom.addWidget(self.packet_count_label)
        bottom.addWidget(QLabel("Matches:"))
        self.match_label = QLabel("0")
        bottom.addWidget(self.match_label)

        main_layout.addLayout(bottom)

        # alert banner
        self.alert_banner = QLabel("")
        self.alert_banner.setStyleSheet("background:#5a0000;color:#fff;padding:6px;border-radius:6px;")
        self.alert_banner.setVisible(False)
        main_layout.addWidget(self.alert_banner)

        # plotting buffers
        self.rate_history = deque(maxlen=120)
        self.rate_times = deque(maxlen=120)
        self.ml_scores = deque(maxlen=300)

    # ---------- Capture control ----------
    def _toggle_capture(self):
        if self.running:
            self._stop_capture()
        else:
            self._start_capture()

    def _start_capture(self):
        iface = self.iface_combo.currentText()
        if not iface:
            QMessageBox.warning(self, "Interface", "No interface selected")
            return
        
        # Clear all data
        self.packets.clear()
        self.suspicious.clear()
        self.pkt_list.clear()
        self.susp_list.clear()
        self.protocol_counter.clear()
        self.dst_counter.clear()
        self.alerts.clear()
        self.last_displayed_index = 0
        self.pending_ui_packets.clear()
        self.pending_ui_suspicious.clear()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.running = True
        self.detector.min_train = self.ml_train_spin.value()
        
        self.capture_thread = threading.Thread(target=self._sniff_thread, args=(iface,), daemon=True)
        self.capture_thread.start()
        self.comms.status_signal.emit(f"Capturing on {iface}...")

    def _stop_capture(self):
        self.running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.iface_combo.setEnabled(True)
        self.comms.status_signal.emit("Stopped capturing")

    def _sniff_thread(self, iface):
        def handle(pkt):
            if not self.running:
                return
            pkt_info = self._pkt_to_dict(pkt)
            # PERFORMANCE FIX: Add to pending buffer instead of emitting signal
            with self.pending_lock:
                self.pending_packets.append(pkt_info)
        try:
            sniff(iface=iface, prn=handle, store=False, stop_filter=lambda _: not self.running)
        except Exception as e:
            self.comms.status_signal.emit(f"Sniffer error: {e}")

    def _pkt_to_dict(self, pkt):
        ts = getattr(pkt, 'time', time.time())
        time_s = datetime.fromtimestamp(ts).isoformat(sep=' ')
        src = getattr(pkt, 'src', None)
        dst = getattr(pkt, 'dst', None)
        sport = 0
        dport = 0
        proto = "UNKNOWN"
        try:
            if pkt.haslayer(IP):
                ip = pkt.getlayer(IP)
                src = ip.src
                dst = ip.dst
                proto = {6:"TCP",17:"UDP",1:"ICMP"}.get(ip.proto, str(ip.proto))
            if pkt.haslayer(TCP):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            if pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            if pkt.haslayer(ARP):
                proto = "ARP"
                arp = pkt.getlayer(ARP)
                src = arp.psrc
                dst = arp.pdst
        except Exception:
            pass
        
        # PERFORMANCE FIX: Limit raw hex storage
        raw_hex = bytes(pkt).hex()[:2048] if hasattr(pkt, '__bytes__') else ""
        summary = pkt.summary() if hasattr(pkt, 'summary') else pkt.__class__.__name__
        length = len(bytes(pkt)) if hasattr(pkt, '__bytes__') else 0
        
        return {
            "time": time_s, "src": src or "N/A", "dst": dst or "N/A",
            "proto": proto, "summary": summary, "length": length,
            "raw_hex": raw_hex, "sport": int(sport), "dport": int(dport)
        }

    # ---------- PERFORMANCE FIX: Batch packet processing ----------
    def _process_pending_packets(self):
        """Process pending packets in batches to avoid GUI blocking"""
        if not self.running:
            return
            
        with self.pending_lock:
            batch = self.pending_packets[:100]  # Process up to 100 at a time
            self.pending_packets = self.pending_packets[100:]
        
        if not batch:
            return
        
        # Process packets (non-GUI operations only)
        for pkt in batch:
            self.packets.append(pkt)
            self.protocol_counter[pkt.get('proto','UNK')] += 1
            self.dst_counter[pkt.get('dst','N/A')] += 1
            
            # ML detection (lightweight)
            if self.ml_enable_cb.isChecked():
                self.detector.partial_fit(pkt)
            
            # Suspicion check
            if self.detector.is_suspicious(pkt):
                self.suspicious.append(pkt)
                # Store for UI update instead of directly modifying widget
                self.pending_ui_suspicious.append(pkt)
                self.comms.suspicious_signal.emit(pkt)
            
            # Security checks (lightweight)
            self._check_portscan(pkt)
            
            # Store for UI update
            self.pending_ui_packets.append(pkt)
        
        # Update rate stats (non-GUI)
        self._update_rate_stats()
        
        # Trigger UI update via signal (runs in main thread)
        self.comms.update_ui.emit()

    def _update_ui_safe(self):
        """Update UI elements safely from main thread"""
        # Update packet list
        for pkt in self.pending_ui_packets:
            if self.pkt_list.count() >= self.MAX_DISPLAY_PACKETS:
                # Remove old items from top
                self.pkt_list.takeItem(0)
            
            idx = len(self.packets) - len(self.pending_ui_packets) + self.pending_ui_packets.index(pkt)
            label = (f"{idx:06d} | {pkt.get('time')} | {pkt.get('src')} -> "
                    f"{pkt.get('dst')} | {pkt.get('proto')} | {pkt.get('length')}")
            self.pkt_list.addItem(label)
        
        # Update suspicious list
        for pkt in self.pending_ui_suspicious:
            if self.susp_list.count() < 1000:
                self.susp_list.addItem(
                    f"{len(self.suspicious):04d} | {pkt.get('time')} | "
                    f"{pkt.get('src')} -> {pkt.get('dst')} | {pkt.get('proto')}"
                )
        
        # Update packet count
        self.packet_count_label.setText(str(len(self.packets)))
        
        # Clear pending UI updates
        self.pending_ui_packets.clear()
        self.pending_ui_suspicious.clear()

    def _update_packet_list(self):
        """DEPRECATED - replaced by _update_ui_safe"""
        pass

    def _update_rate_stats(self):
        """Update rate statistics"""
        now = time.time()
        if not self.rate_times or (now - self.rate_times[-1] >= 1.0):
            self.rate_times.append(now)
            self.rate_history.append(1)
        else:
            self.rate_history[-1] += 1

    # ---------- Packet UI handlers ----------
    def _on_suspicious(self, pkt):
        self.alerts.appendleft(
            f"Suspicious: {pkt.get('proto')} {pkt.get('src')} -> "
            f"{pkt.get('dst')} len={pkt.get('length')}"
        )
        self._flash_alert("Suspicious packet detected!")
        self._update_threat_meter()

    def _pkt_selected(self, item):
        try:
            text = item.text()
            idx = int(text.split("|",1)[0].strip())
            if idx < len(self.packets):
                pkt = self.packets[idx]
                self._show_details(pkt)
        except Exception as e:
            self._append_status(f"Selection error: {e}")

    def _susp_selected(self, item):
        try:
            text = item.text()
            idx = int(text.split("|",1)[0].strip())
            if idx <= len(self.suspicious):
                pkt = self.suspicious[idx-1]
                self._show_details(pkt)
        except Exception as e:
            self._append_status(f"Selection error: {e}")

    def _show_details(self, pkt):
        ascii_preview = ""
        try:
            raw = pkt.get("raw_hex","")
            bytes_seq = bytes.fromhex(raw) if raw else b""
            ascii_preview = ''.join([chr(b) if 32 <= b < 127 else '.' for b in bytes_seq[:512]])
        except Exception:
            ascii_preview = "<binary>"

        layer_info = [
            f"Time: {pkt.get('time')}",
            f"Summary: {pkt.get('summary')}",
            f"Src: {pkt.get('src')}",
            f"Dst: {pkt.get('dst')}",
            f"Proto: {pkt.get('proto')}",
            f"Sport: {pkt.get('sport')} Dport: {pkt.get('dport')}",
            f"Length: {pkt.get('length')}",
            "",
            "Raw (hex, truncated):",
            pkt.get('raw_hex','')[:2048],
            "",
            "ASCII preview:",
            ascii_preview
        ]
        self.details.setPlainText("\n".join([str(x) for x in layer_info]))

    # ---------- Inspect Packet popup ----------
    def _inspect_packet_popup(self):
        if not self.packets:
            QMessageBox.information(self, "Inspect Packet", "No packets captured yet.")
            return
        num, ok = QInputDialog.getInt(
            self, "Inspect Packet", 
            f"Enter packet number (1..{len(self.packets)}):", 
            1, 1, len(self.packets)
        )
        if ok:
            idx = num - 1
            pkt = self.packets[idx]
            self._show_packet_popup(pkt, num)

    def _show_packet_popup(self, pkt, serial_number):
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Packet #{serial_number} Details")
        dialog.resize(800, 600)
        v = QVBoxLayout(dialog)
        txt = QTextEdit()
        txt.setReadOnly(True)
        
        try:
            raw = pkt.get("raw_hex","")
            bytes_seq = bytes.fromhex(raw) if raw else b""
            ascii_preview = ''.join([chr(b) if 32 <= b < 127 else '.' for b in bytes_seq[:2048]])
        except Exception:
            ascii_preview = "<binary>"

        info_lines = [
            f"Packet Serial #: {serial_number}",
            f"Captured Time: {pkt.get('time')}",
            f"Summary: {pkt.get('summary')}",
            f"Source IP: {pkt.get('src')}",
            f"Destination IP: {pkt.get('dst')}",
            f"Protocol: {pkt.get('proto')}",
            f"Source Port: {pkt.get('sport')}",
            f"Destination Port: {pkt.get('dport')}",
            f"Length: {pkt.get('length')}",
            "",
            "---- Raw (hex, truncated) ----",
            pkt.get('raw_hex','')[:4096],
            "",
            "---- ASCII preview ----",
            ascii_preview,
        ]
        txt.setPlainText("\n".join(info_lines))
        v.addWidget(txt)
        
        btn_row = QHBoxLayout()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        v.addLayout(btn_row)
        dialog.exec_()

    # ---------- Filters & Search ----------
    def _apply_filter(self):
        f = self.filter_edit.text().strip()
        regex = self.search_edit.text().strip()
        self.pkt_list.clear()
        matches = 0
        
        for i, pkt in enumerate(self.packets):
            if f and not self._matches_filter(pkt, f):
                continue
            if regex:
                try:
                    if not re.search(regex, pkt.get('summary','') + pkt.get('raw_hex',''), re.IGNORECASE):
                        continue
                except re.error:
                    self._append_status("Invalid regex")
                    return
            
            label = (f"{i:06d} | {pkt.get('time')} | {pkt.get('src')} -> "
                    f"{pkt.get('dst')} | {pkt.get('proto')} | {pkt.get('length')}")
            self.pkt_list.addItem(label)
            matches += 1
            
            if matches >= self.MAX_DISPLAY_PACKETS:
                break
        
        self.match_label.setText(str(matches))

    def _matches_filter(self, pkt, filt):
        f = filt.lower()
        terms = [t.strip() for t in f.split(",")]
        for t in terms:
            if t in ("tcp","udp","icmp","arp"):
                if pkt.get("proto","").lower() != t:
                    return False
            elif t.startswith("ip:"):
                ip = t.split(":",1)[1]
                if not (pkt.get("src")==ip or pkt.get("dst")==ip):
                    return False
            elif t.startswith("src:"):
                ip = t.split(":",1)[1]
                if pkt.get("src") != ip:
                    return False
            elif t.startswith("dst:"):
                ip = t.split(":",1)[1]
                if pkt.get("dst") != ip:
                    return False
            elif t.startswith("port:"):
                try:
                    p = int(t.split(":",1)[1])
                    if not (pkt.get("sport")==p or pkt.get("dport")==p):
                        return False
                except ValueError:
                    return False
            elif t.startswith("minlen:"):
                try:
                    l = int(t.split(":",1)[1])
                    if pkt.get("length",0) < l:
                        return False
                except ValueError:
                    return False
        return True

    # ---------- Plots & Analytics ----------
    def _start_timers(self):
        # PERFORMANCE FIX: Process packets in batches
        self.packet_timer = QTimer()
        self.packet_timer.timeout.connect(self._process_pending_packets)
        self.packet_timer.start(50)  # Process every 50ms
        
        # Plot updates less frequently
        self.plot_timer = QTimer()
        self.plot_timer.timeout.connect(self._refresh_plots)
        self.plot_timer.start(2000)  # Every 2 seconds

        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self._update_threat_meter)
        self.status_timer.start(3000)  # Every 3 seconds

    def _refresh_plots(self):
        """Refresh all plots - called less frequently"""
        # Rate plot
        self.rate_ax.clear()
        xs = list(range(-len(self.rate_history)+1, 1))
        ys = list(self.rate_history)
        if ys:
            self.rate_ax.plot(xs, ys, linewidth=1.5, color='#00d4ff')
            self.rate_ax.set_ylim(0, max(5, max(ys)+1))
        self.rate_ax.set_facecolor('#0b1a2a')
        self.canvas_rate.draw()

        # Protocol pie (small)
        self.proto_ax.clear()
        labels = []
        vals = []
        for k, v in self.protocol_counter.most_common(6):
            labels.append(k)
            vals.append(v)
        if vals:
            self.proto_ax.pie(vals, labels=labels, autopct="%1.0f%%")
        self.canvas_proto.draw()

        # Protocol pie (large)
        self.proto_big_ax.clear()
        if vals:
            self.proto_big_ax.pie(vals, labels=labels, autopct="%1.1f%%", 
                                 colors=['#00d4ff', '#0099cc', '#006699', '#003d5c', '#002233', '#001a29'])
        self.canvas_proto_big.draw()

        # Destination bar chart
        self.dst_ax.clear()
        topdst = self.dst_counter.most_common(8)
        if topdst:
            labels = [x[0] for x in topdst]
            vals = [x[1] for x in topdst]
            ind = np.arange(len(vals))
            self.dst_ax.bar(ind, vals, color='#00d4ff')
            self.dst_ax.set_xticks(ind)
            self.dst_ax.set_xticklabels(labels, rotation=45, ha='right')
            self.dst_ax.set_facecolor('#0b1a2a')
        self.canvas_dst.draw()

        # ML plot
        self.ml_ax.clear()
        if SKLEARN and self.ml_scores:
            scores = list(self.ml_scores)
            self.ml_ax.plot(scores, color='#ff6b00', linewidth=1.5)
            self.ml_ax.set_facecolor('#0b1a2a')
        self.canvas_ml.draw()

    # ---------- Threat meter ----------
    def _update_threat_meter(self):
        """Calculate and display threat level"""
        threat = 0
        threat += min(50, len(self.suspicious) * 5)
        recent_rate = self.rate_history[-1] if self.rate_history else 0
        threat += min(30, recent_rate * 2)
        threat += min(20, len([a for a in list(self.alerts) if "ARP" in a or "scan" in a]) * 5)
        threat = min(100, threat)
        
        self.threat_bar.setValue(threat)
        if threat > 70:
            self.alert_label.setText("Status: HIGH")
            self.threat_bar.setStyleSheet("QProgressBar::chunk { background-color: #ff0000; }")
        elif threat > 30:
            self.alert_label.setText("Status: MEDIUM")
            self.threat_bar.setStyleSheet("QProgressBar::chunk { background-color: #ff9900; }")
        else:
            self.alert_label.setText("Status: LOW")
            self.threat_bar.setStyleSheet("QProgressBar::chunk { background-color: #00ff00; }")

    def _flash_alert(self, text, duration=2500):
        """Show animated alert banner"""
        self.alert_banner.setText(text)
        self.alert_banner.setVisible(True)
        QTimer.singleShot(duration, lambda: self.alert_banner.setVisible(False))

    # ---------- Session save/load + replay ----------
    def _save_session(self):
        if not self.packets:
            QMessageBox.information(self, "Save", "No packets captured.")
            return
        default = os.path.join(LOG_DIR, f"safffire_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        fn, _ = QFileDialog.getSaveFileName(self, "Save session", default, "JSON Files (*.json)")
        if not fn:
            return
        try:
            with open(fn, "w") as f:
                json.dump(self.packets, f, indent=2)
            QMessageBox.information(self, "Saved", f"Saved {len(self.packets)} packets to {fn}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Save failed: {e}")

    def _load_session(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Load session", LOG_DIR, "JSON Files (*.json)")
        if not fn:
            return
        try:
            with open(fn, "r") as f:
                data = json.load(f)
            
            self.packets = data
            self.pkt_list.clear()
            self.protocol_counter.clear()
            self.dst_counter.clear()
            
            # Load with limits
            for i, pkt in enumerate(self.packets):
                if i < self.MAX_DISPLAY_PACKETS:
                    label = (f"{i:06d} | {pkt.get('time')} | {pkt.get('src')} -> "
                            f"{pkt.get('dst')} | {pkt.get('proto')} | {pkt.get('length')}")
                    self.pkt_list.addItem(label)
                
                self.protocol_counter[pkt.get('proto','UNK')] += 1
                self.dst_counter[pkt.get('dst','N/A')] += 1
            
            self.packet_count_label.setText(str(len(self.packets)))
            
            QMessageBox.information(self, "Loaded", 
                                  f"Loaded {len(self.packets)} packets from {fn}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Load failed: {e}")

    # ---------- Security heuristics ----------
    def _check_portscan(self, pkt):
        """Detect potential port scanning activity"""
        src = pkt.get('src')
        dport = pkt.get('dport')
        ts = time.time()
        
        if not src or not dport:
            return
        
        lst = self.port_scan_candidates[src]
        lst.append((dport, ts))
        # Keep only recent connections (last 10 seconds)
        self.port_scan_candidates[src] = [(p, t) for (p, t) in lst if ts - t < 10]
        
        # Check for multiple unique ports
        ports = {p for (p, t) in self.port_scan_candidates[src]}
        if len(ports) >= 12:
            alert = f"Possible port-scan from {src} ({len(ports)} ports)"
            if alert not in list(self.alerts)[:5]:  # Avoid duplicates
                self.alerts.appendleft(alert)
                self._flash_alert(alert)

    def _check_arp_spoof(self, pkt):
        """Basic ARP activity monitoring"""
        try:
            if pkt.get('proto') == 'ARP':
                src = pkt.get('src')
                # Track ARP activity
                if src != 'N/A':
                    alert = f"ARP activity from {src}"
                    # Only alert if not recently alerted
                    recent_arp = [a for a in list(self.alerts)[:10] if 'ARP' in a]
                    if len(recent_arp) < 3:
                        self.alerts.appendleft(alert)
        except Exception:
            pass

    # ---------- Utility ----------
    def _append_status(self, text):
        """Update status label"""
        self.status.setText(text)

# ---------- App entry ----------
def main():
    app = QApplication(sys.argv)
    win = Safffire()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()