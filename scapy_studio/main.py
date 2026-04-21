"""
Primary Qt desktop application for Scapy Studio.

Code updates and public-repo packaging by Ayman Elbanhawy (c) SoftwareMile.com.
"""

# Copyright (c) Ayman Elbanhawy - SoftwareMile.com

from __future__ import annotations

import argparse
import json
import shutil
import sys
import webbrowser
from pathlib import Path

import pyqtgraph as pg
from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from scapy.all import Ether, IP, TCP, UDP, raw

from . import APP_NAME, REPO_URL, SUPPORT_EMAIL, WEBSITE_URL
from .analysis import (
    PacketRecord,
    build_metrics,
    compare_metrics,
    export_packet_pdf,
    export_packet_ps,
    export_selected_pcap,
    filter_records,
    load_packets,
    packet_details,
    packet_hex,
    packet_json,
    session_rows,
    simple_findings,
)
from .database import StudioDatabase
from .reports import archive_project, export_findings_csv, export_html_report, export_sessions_json
from .workers import LiveCaptureWorker, PcapLoadWorker, WorkerThread, probe_capture


APP_DIR = Path(__file__).resolve().parents[1]
PROJECTS_DIR = APP_DIR / "ScapyStudioProjects"
DB_PATH = APP_DIR / "ScapyStudioData" / "studio.db"
HELP_PATH = APP_DIR / "docs" / "help" / "index.html"


class MetricCard(QFrame):
    """Small reusable dashboard card for fast-glance metrics."""

    def __init__(self, title: str, accent: str) -> None:
        super().__init__()
        self.setObjectName("metricCard")
        self.setProperty("accent", accent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(6)

        self.title_label = QLabel(title)
        self.title_label.setObjectName("metricTitle")
        self.value_label = QLabel("0")
        self.value_label.setObjectName("metricValue")
        self.detail_label = QLabel("")
        self.detail_label.setObjectName("metricDetail")
        self.detail_label.setWordWrap(True)

        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.detail_label)

    def set_metric(self, value: str, detail: str) -> None:
        """Refresh the primary value and the supporting description text."""

        self.value_label.setText(value)
        self.detail_label.setText(detail)


class PacketTable(QTableWidget):
    """Styled packet table reused by explorer and live capture views."""

    def __init__(self) -> None:
        super().__init__(0, 7)
        self.setHorizontalHeaderLabels(["#", "Time", "Source", "Destination", "Protocol", "Bytes", "Summary"])
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)

    def set_packets(self, records: list[PacketRecord]) -> None:
        """Replace the table contents with the supplied packet list."""

        self.setRowCount(0)
        for rec in records:
            self.add_packet(rec)
        self.resizeColumnsToContents()

    def add_packet(self, rec: PacketRecord) -> None:
        """Append a single packet record to the bottom of the table."""

        row = self.rowCount()
        self.insertRow(row)
        values = [rec.index, f"{rec.time:.6f}", rec.source, rec.destination, rec.protocol, rec.length, rec.summary]
        for col, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            if col in (0, 5):
                item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.setItem(row, col, item)


class ScapyStudio(QMainWindow):
    """Main application window coordinating analysis, capture, reporting, and notes."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1560, 960)

        self.db = StudioDatabase(DB_PATH)
        self.project_id: int | None = None
        self.project_root: Path | None = None
        self.records: list[PacketRecord] = []
        self.visible_records: list[PacketRecord] = []
        self.current_path: Path | None = None
        self.live_packets: list[object] = []
        self.current_findings: list[str] = []
        self.worker_thread: WorkerThread | None = None
        self.worker_threads: list[WorkerThread] = []
        self.live = LiveCaptureWorker()

        self.tabs = QTabWidget()
        self.project_badge = QLabel("No project opened")
        self.status_hint = QLabel("Load a PCAP, open a project, or start a live capture.")

        self._apply_theme()
        self._build_window()
        self.refresh_home()
        self.statusBar().showMessage("Ready")

    def _apply_theme(self) -> None:
        """Define the visual language for the public desktop build."""

        self.setStyleSheet(
            """
            QMainWindow, QWidget {
                background: #08151d;
                color: #edf4f7;
                font-family: "Segoe UI";
                font-size: 10.5pt;
            }
            QFrame#heroCard, QFrame#panelCard, QFrame#metricCard {
                border: 1px solid #23404f;
                border-radius: 18px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(18, 36, 47, 245),
                    stop:1 rgba(10, 26, 36, 245));
            }
            QFrame#sidebarCard {
                border: 1px solid #28495b;
                border-radius: 20px;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(13, 29, 40, 255),
                    stop:1 rgba(8, 21, 29, 255));
            }
            QLabel#heroTitle {
                font-size: 25pt;
                font-weight: 700;
                color: #f3fbfd;
            }
            QLabel#heroSubtitle, QLabel#metricDetail, QLabel#mutedText {
                color: #9eb7c5;
            }
            QLabel#metricTitle {
                font-size: 9pt;
                font-weight: 600;
                letter-spacing: 0.08em;
                text-transform: uppercase;
                color: #9ec5cf;
            }
            QLabel#metricValue {
                font-size: 20pt;
                font-weight: 700;
                color: #ffffff;
            }
            QLabel#sectionTitle {
                font-size: 14pt;
                font-weight: 700;
                color: #e8f5f8;
            }
            QLabel#projectBadge {
                border: 1px solid #355c70;
                border-radius: 999px;
                padding: 7px 14px;
                color: #dff2f8;
                background: rgba(42, 157, 143, 28);
            }
            QPushButton {
                border: 1px solid #326074;
                border-radius: 12px;
                padding: 10px 14px;
                background: #123345;
                color: #eef8fb;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #184860;
                border-color: #4f8198;
            }
            QPushButton:pressed {
                background: #0f2937;
            }
            QPushButton[variant="primary"] {
                background: #2a9d8f;
                border-color: #3abdad;
                color: #041115;
            }
            QPushButton[variant="warm"] {
                background: #f4a261;
                border-color: #f9b27e;
                color: #2f1903;
            }
            QLineEdit, QTextEdit, QComboBox, QListWidget, QTreeWidget, QTableWidget, QTabWidget::pane {
                background: #0d2230;
                border: 1px solid #27495c;
                border-radius: 12px;
                color: #edf4f7;
            }
            QLineEdit, QComboBox {
                padding: 8px 10px;
            }
            QTextEdit, QListWidget, QTreeWidget, QTableWidget {
                selection-background-color: rgba(42, 157, 143, 95);
                alternate-background-color: rgba(255,255,255,0.03);
            }
            QHeaderView::section {
                background: #16384a;
                color: #dfeff5;
                border: none;
                border-right: 1px solid #23495d;
                padding: 8px;
                font-weight: 700;
            }
            QTabBar::tab {
                background: #102634;
                color: #b8cfdb;
                border: 1px solid #234657;
                border-bottom: none;
                border-top-left-radius: 12px;
                border-top-right-radius: 12px;
                padding: 10px 16px;
                margin-right: 6px;
            }
            QTabBar::tab:selected {
                background: #173647;
                color: #ffffff;
            }
            QSplitter::handle {
                background: #1b3d4d;
            }
            QStatusBar {
                background: #07131b;
                color: #c7dde8;
            }
            """
        )

    def _build_window(self) -> None:
        """Create the full desktop shell and all workspace tabs."""

        central = QWidget()
        shell = QHBoxLayout(central)
        shell.setContentsMargins(18, 18, 18, 18)
        shell.setSpacing(18)

        shell.addWidget(self._build_sidebar(), 0)
        shell.addWidget(self._build_main_column(), 1)

        self.setCentralWidget(central)
        self.live.packet.connect(self.on_live_packet)
        self.live.status.connect(self.statusBar().showMessage)
        self.live.failed.connect(self.show_error)

    def _build_sidebar(self) -> QWidget:
        """Create the left-hand command rail used for high-level navigation."""

        card = QFrame()
        card.setObjectName("sidebarCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        brand = QLabel("Scapy\nStudio")
        brand.setStyleSheet("font-size: 22pt; font-weight: 800; line-height: 1.1;")
        layout.addWidget(brand)

        layout.addWidget(self._nav_button("Dashboard", lambda: self.tabs.setCurrentWidget(self.dashboard_page), "primary"))
        layout.addWidget(self._nav_button("Capture", lambda: self.tabs.setCurrentWidget(self.capture_page)))
        layout.addWidget(self._nav_button("PCAP Explorer", lambda: self.tabs.setCurrentWidget(self.explorer_page)))
        layout.addWidget(self._nav_button("Flows", lambda: self.tabs.setCurrentWidget(self.flows_page)))
        layout.addWidget(self._nav_button("Charts", lambda: self.tabs.setCurrentWidget(self.charts_page)))
        layout.addWidget(self._nav_button("Builder", lambda: self.tabs.setCurrentWidget(self.builder_page)))
        layout.addWidget(self._nav_button("Protocols", lambda: self.tabs.setCurrentWidget(self.protocols_page)))
        layout.addWidget(self._nav_button("Reports", lambda: self.tabs.setCurrentWidget(self.reports_page)))
        layout.addWidget(self._nav_button("Notes", lambda: self.tabs.setCurrentWidget(self.notes_page)))

        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet("color: #234657;")
        layout.addWidget(divider)

        layout.addWidget(self._nav_button("Create Project", self.create_project, "primary"))
        layout.addWidget(self._nav_button("Open Project", self.open_project))
        layout.addWidget(self._nav_button("Open Help", self.open_help))
        layout.addWidget(self._nav_button("Open GitHub Repo", self.open_github, "warm"))

        layout.addStretch(1)

        footer = QLabel(
            f"Repository\n{REPO_URL}\n\nSupport\n{SUPPORT_EMAIL}\n\nWebsite\n{WEBSITE_URL}"
        )
        footer.setObjectName("mutedText")
        footer.setWordWrap(True)
        layout.addWidget(footer)
        return card

    def _build_main_column(self) -> QWidget:
        """Create the right-hand content column with header, cards, and tabs."""

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        layout.addWidget(self._build_header())
        layout.addWidget(self._build_metrics_row())

        self.tabs.setDocumentMode(True)
        layout.addWidget(self.tabs, 1)

        self._build_home()
        self._build_capture()
        self._build_explorer()
        self._build_flows()
        self._build_charts()
        self._build_builder()
        self._build_protocols()
        self._build_reports()
        self._build_notes()

        return container

    def _build_header(self) -> QWidget:
        """Create the top hero strip that summarizes the current workspace."""

        card = QFrame()
        card.setObjectName("heroCard")
        layout = QHBoxLayout(card)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(18)

        left = QVBoxLayout()
        title = QLabel(APP_NAME)
        title.setObjectName("heroTitle")
        subtitle = QLabel(
            "Desktop packet analysis for offline PCAP review, live capture, flow triage, packet building, and HTML exports."
        )
        subtitle.setObjectName("heroSubtitle")
        subtitle.setWordWrap(True)
        left.addWidget(title)
        left.addWidget(subtitle)
        left.addWidget(self.project_badge)

        right = QVBoxLayout()
        right.setSpacing(8)
        quick = QLabel("Quick Actions")
        quick.setObjectName("sectionTitle")
        right.addWidget(quick)
        right.addWidget(self._nav_button("Import PCAP Files", self.import_pcaps, "primary"))
        right.addWidget(self._nav_button("Import Folder", self.import_folder))
        right.addWidget(self._nav_button("Start Live Capture", lambda: self.tabs.setCurrentWidget(self.capture_page)))
        right.addWidget(self._nav_button("Export HTML Report", self.export_html, "warm"))

        layout.addLayout(left, 1)
        layout.addLayout(right, 0)
        return card

    def _build_metrics_row(self) -> QWidget:
        """Create the KPI card row shown above the workspace tabs."""

        container = QWidget()
        layout = QGridLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setHorizontalSpacing(14)
        layout.setVerticalSpacing(14)

        self.metric_packets = MetricCard("Packets", "mint")
        self.metric_bytes = MetricCard("Bytes", "blue")
        self.metric_protocols = MetricCard("Protocols", "amber")
        self.metric_flows = MetricCard("Flows", "coral")

        layout.addWidget(self.metric_packets, 0, 0)
        layout.addWidget(self.metric_bytes, 0, 1)
        layout.addWidget(self.metric_protocols, 0, 2)
        layout.addWidget(self.metric_flows, 0, 3)
        return container

    def _nav_button(self, text: str, slot, variant: str = "") -> QPushButton:
        """Create a button with a shared style and click binding."""

        button = QPushButton(text)
        if variant:
            button.setProperty("variant", variant)
            button.style().unpolish(button)
            button.style().polish(button)
        button.clicked.connect(slot)
        return button

    def _section_label(self, text: str) -> QLabel:
        """Create a section heading used inside tab pages."""

        label = QLabel(text)
        label.setObjectName("sectionTitle")
        return label

    def _build_home(self) -> None:
        """Create the landing dashboard tab."""

        self.dashboard_page = QWidget()
        layout = QVBoxLayout(self.dashboard_page)
        layout.setSpacing(14)

        layout.addWidget(self._section_label("Project Dashboard"))

        summary_card = QFrame()
        summary_card.setObjectName("panelCard")
        summary_layout = QVBoxLayout(summary_card)
        summary_layout.setContentsMargins(18, 18, 18, 18)
        summary_layout.setSpacing(12)

        self.project_summary = QLabel("No project opened.")
        self.project_summary.setWordWrap(True)
        self.project_summary.setObjectName("mutedText")
        self.status_hint.setObjectName("mutedText")
        summary_layout.addWidget(self.project_summary)
        summary_layout.addWidget(self.status_hint)

        action_row = QHBoxLayout()
        action_row.addWidget(self._nav_button("Create Project", self.create_project, "primary"))
        action_row.addWidget(self._nav_button("Open Project", self.open_project))
        action_row.addWidget(self._nav_button("Open Reports", lambda: self.tabs.setCurrentWidget(self.reports_page)))
        action_row.addWidget(self._nav_button("Open Help", self.open_help))
        summary_layout.addLayout(action_row)

        layout.addWidget(summary_card)

        split = QSplitter(Qt.Horizontal)

        recent_card = QFrame()
        recent_card.setObjectName("panelCard")
        recent_layout = QVBoxLayout(recent_card)
        recent_layout.setContentsMargins(18, 18, 18, 18)
        recent_layout.addWidget(self._section_label("Recent Projects"))
        self.recent_projects = QListWidget()
        self.recent_projects.itemDoubleClicked.connect(self.open_recent_project)
        recent_layout.addWidget(self.recent_projects)

        findings_card = QFrame()
        findings_card.setObjectName("panelCard")
        findings_layout = QVBoxLayout(findings_card)
        findings_layout.setContentsMargins(18, 18, 18, 18)
        findings_layout.addWidget(self._section_label("Current Findings"))
        self.dashboard_findings = QListWidget()
        findings_layout.addWidget(self.dashboard_findings)

        split.addWidget(recent_card)
        split.addWidget(findings_card)
        split.setSizes([460, 740])
        layout.addWidget(split, 1)

        self.tabs.addTab(self.dashboard_page, "Dashboard")

    def _build_capture(self) -> None:
        """Create the live capture workspace."""

        self.capture_page = QWidget()
        layout = QVBoxLayout(self.capture_page)
        layout.setSpacing(14)

        layout.addWidget(self._section_label("Live Capture"))

        controls_card = QFrame()
        controls_card.setObjectName("panelCard")
        controls_layout = QVBoxLayout(controls_card)
        controls_layout.setContentsMargins(18, 18, 18, 18)
        controls_layout.setSpacing(12)

        top = QHBoxLayout()
        self.iface_combo = QComboBox()
        self.refresh_interfaces()
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("BPF filter, for example: tcp port 80")
        top.addWidget(QLabel("Interface"))
        top.addWidget(self.iface_combo, 1)
        top.addWidget(QLabel("Filter"))
        top.addWidget(self.filter_edit, 1)
        controls_layout.addLayout(top)

        buttons = QHBoxLayout()
        buttons.addWidget(self._nav_button("Start", self.start_live_capture, "primary"))
        buttons.addWidget(self._nav_button("Stop", self.live.stop))
        buttons.addWidget(self._nav_button("Save Live PCAP", self.save_live_capture))
        buttons.addWidget(self._nav_button("Clear", self.clear_live_capture))
        buttons.addWidget(self._nav_button("Refresh Interfaces", self.refresh_interfaces))
        buttons.addWidget(self._nav_button("Interface Info", self.show_interface_info))
        buttons.addWidget(self._nav_button("Probe 5s", self.probe_selected_interface, "warm"))
        controls_layout.addLayout(buttons)

        layout.addWidget(controls_card)

        splitter = QSplitter(Qt.Vertical)
        self.live_table = PacketTable()
        self.live_pps = pg.PlotWidget(title="Packets Per Second")
        self._style_plot(self.live_pps)
        splitter.addWidget(self.live_table)
        splitter.addWidget(self.live_pps)
        splitter.setSizes([560, 220])
        layout.addWidget(splitter, 1)

        self.tabs.addTab(self.capture_page, "Capture")

    def _build_explorer(self) -> None:
        """Create the offline PCAP explorer workspace."""

        self.explorer_page = QWidget()
        layout = QVBoxLayout(self.explorer_page)
        layout.setSpacing(14)

        layout.addWidget(self._section_label("PCAP Explorer"))

        toolbar = QFrame()
        toolbar.setObjectName("panelCard")
        toolbar_layout = QVBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(18, 18, 18, 18)
        toolbar_layout.setSpacing(12)

        buttons = QHBoxLayout()
        for text, slot, variant in [
            ("Open PCAP", self.open_pcap, "primary"),
            ("Import Folder", self.import_folder, ""),
            ("Save Selected PCAP", self.save_selected_pcap, ""),
            ("Packet JSON", self.show_packet_json, ""),
            ("PDF Dump", self.pdf_dump_packet, ""),
            ("PS Dump", self.ps_dump_packet, ""),
        ]:
            buttons.addWidget(self._nav_button(text, slot, variant))
        toolbar_layout.addLayout(buttons)

        filters = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search packets by host, protocol, length, or summary")
        self.protocol_filter = QComboBox()
        self.protocol_filter.addItem("All")
        filters.addWidget(QLabel("Search"))
        filters.addWidget(self.search_edit, 1)
        filters.addWidget(QLabel("Protocol"))
        filters.addWidget(self.protocol_filter)
        filters.addWidget(self._nav_button("Apply Filter", self.apply_packet_filter, "primary"))
        filters.addWidget(self._nav_button("Clear Filter", self.clear_packet_filter))
        toolbar_layout.addLayout(filters)

        layout.addWidget(toolbar)

        splitter = QSplitter(Qt.Horizontal)
        left = QSplitter(Qt.Vertical)
        self.packet_table = PacketTable()
        self.packet_table.itemSelectionChanged.connect(self.update_packet_detail)
        self.findings_list = QListWidget()
        left.addWidget(self.packet_table)
        left.addWidget(self.findings_list)

        right = QSplitter(Qt.Vertical)
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.hex_text = QTextEdit()
        self.hex_text.setReadOnly(True)
        right.addWidget(self.detail_text)
        right.addWidget(self.hex_text)

        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([900, 520])
        layout.addWidget(splitter, 1)

        self.tabs.addTab(self.explorer_page, "PCAP Explorer")

    def _build_flows(self) -> None:
        """Create the conversation summary workspace."""

        self.flows_page = QWidget()
        layout = QVBoxLayout(self.flows_page)
        layout.setSpacing(14)
        layout.addWidget(self._section_label("Flows"))

        controls = QFrame()
        controls.setObjectName("panelCard")
        controls_layout = QHBoxLayout(controls)
        controls_layout.setContentsMargins(18, 18, 18, 18)
        controls_layout.addWidget(self._nav_button("Export Sessions JSON", self.export_sessions, "primary"))
        controls_layout.addWidget(self._nav_button("Compare With PCAP", self.compare_with_pcap))
        controls_layout.addStretch(1)
        layout.addWidget(controls)

        self.flow_table = QTableWidget(0, 7)
        self.flow_table.setHorizontalHeaderLabels(["Source", "Destination", "Protocol", "Packets", "Bytes", "First", "Last"])
        self.flow_table.verticalHeader().setVisible(False)
        self.flow_table.horizontalHeader().setStretchLastSection(True)
        self.flow_table.setAlternatingRowColors(True)
        self.flow_table.setShowGrid(False)
        layout.addWidget(self.flow_table, 1)

        self.tabs.addTab(self.flows_page, "Flows")

    def _build_charts(self) -> None:
        """Create the metrics chart workspace."""

        self.charts_page = QWidget()
        layout = QGridLayout(self.charts_page)
        layout.setSpacing(14)

        self.protocol_plot = pg.PlotWidget(title="Protocol Mix")
        self.source_plot = pg.PlotWidget(title="Top Source IPs")
        self.dest_plot = pg.PlotWidget(title="Top Destination IPs")
        self.bytes_plot = pg.PlotWidget(title="Bytes Per Second")
        for widget in [self.protocol_plot, self.source_plot, self.dest_plot, self.bytes_plot]:
            self._style_plot(widget)

        layout.addWidget(self.protocol_plot, 0, 0)
        layout.addWidget(self.source_plot, 0, 1)
        layout.addWidget(self.dest_plot, 1, 0)
        layout.addWidget(self.bytes_plot, 1, 1)
        self.tabs.addTab(self.charts_page, "Charts")

    def _build_builder(self) -> None:
        """Create the packet crafting workspace."""

        self.builder_page = QWidget()
        layout = QHBoxLayout(self.builder_page)
        layout.setSpacing(14)

        form_card = QFrame()
        form_card.setObjectName("panelCard")
        form_layout = QVBoxLayout(form_card)
        form_layout.setContentsMargins(18, 18, 18, 18)
        form_layout.addWidget(self._section_label("Packet Builder"))

        form = QFormLayout()
        form.setSpacing(10)
        self.src_ip = QLineEdit("10.0.0.1")
        self.dst_ip = QLineEdit("10.0.0.2")
        self.src_port = QLineEdit("12345")
        self.dst_port = QLineEdit("80")
        self.payload = QLineEdit("Scapy Studio")
        self.transport = QComboBox()
        self.transport.addItems(["TCP", "UDP"])
        for label, widget in [
            ("Source IP", self.src_ip),
            ("Destination IP", self.dst_ip),
            ("Transport", self.transport),
            ("Source Port", self.src_port),
            ("Destination Port", self.dst_port),
            ("Payload", self.payload),
        ]:
            form.addRow(label, widget)
        form_layout.addLayout(form)

        form_buttons = QHBoxLayout()
        form_buttons.addWidget(self._nav_button("Build Packet", self.build_packet, "primary"))
        form_buttons.addWidget(self._nav_button("Save Template JSON", self.save_packet_template))
        form_layout.addLayout(form_buttons)

        output_card = QFrame()
        output_card.setObjectName("panelCard")
        output_layout = QVBoxLayout(output_card)
        output_layout.setContentsMargins(18, 18, 18, 18)
        output_layout.addWidget(self._section_label("Decoded Output"))
        self.builder_output = QTextEdit()
        self.builder_output.setReadOnly(True)
        output_layout.addWidget(self.builder_output)

        layout.addWidget(form_card, 0)
        layout.addWidget(output_card, 1)
        self.tabs.addTab(self.builder_page, "Builder")

    def _build_protocols(self) -> None:
        """Create the quick layer-inspection workspace."""

        self.protocols_page = QWidget()
        layout = QVBoxLayout(self.protocols_page)
        layout.setSpacing(14)
        layout.addWidget(self._section_label("Protocol Browser"))

        controls = QFrame()
        controls.setObjectName("panelCard")
        controls_layout = QHBoxLayout(controls)
        controls_layout.setContentsMargins(18, 18, 18, 18)
        self.protocol_query = QLineEdit("IP")
        controls_layout.addWidget(QLabel("Layer"))
        controls_layout.addWidget(self.protocol_query, 1)
        controls_layout.addWidget(self._nav_button("Inspect Layer", self.inspect_protocol, "primary"))
        layout.addWidget(controls)

        self.protocol_tree = QTreeWidget()
        self.protocol_tree.setHeaderLabels(["Protocol / Field", "Details"])
        layout.addWidget(self.protocol_tree, 1)
        self.tabs.addTab(self.protocols_page, "Protocols")

    def _build_reports(self) -> None:
        """Create the export and archive workspace."""

        self.reports_page = QWidget()
        layout = QVBoxLayout(self.reports_page)
        layout.setSpacing(14)
        layout.addWidget(self._section_label("Reports & Exports"))

        buttons_card = QFrame()
        buttons_card.setObjectName("panelCard")
        buttons_layout = QHBoxLayout(buttons_card)
        buttons_layout.setContentsMargins(18, 18, 18, 18)
        buttons_layout.addWidget(self._nav_button("Export HTML Report", self.export_html, "primary"))
        buttons_layout.addWidget(self._nav_button("Export Packet JSON", self.export_json))
        buttons_layout.addWidget(self._nav_button("Export Findings CSV", self.export_findings))
        buttons_layout.addWidget(self._nav_button("Archive Project", self.export_project_archive, "warm"))
        layout.addWidget(buttons_card)

        self.report_log = QTextEdit()
        self.report_log.setReadOnly(True)
        self.report_log.setPlaceholderText("Export activity will appear here.")
        layout.addWidget(self.report_log, 1)
        self.tabs.addTab(self.reports_page, "Reports")

    def _build_notes(self) -> None:
        """Create the analyst notes workspace."""

        self.notes_page = QWidget()
        layout = QVBoxLayout(self.notes_page)
        layout.setSpacing(14)
        layout.addWidget(self._section_label("Notes"))

        editor = QFrame()
        editor.setObjectName("panelCard")
        editor_layout = QVBoxLayout(editor)
        editor_layout.setContentsMargins(18, 18, 18, 18)
        self.note_title = QLineEdit()
        self.note_title.setPlaceholderText("Note title")
        self.note_body = QTextEdit()
        self.note_body.setPlaceholderText("Write case notes, capture observations, or follow-up actions.")
        editor_layout.addWidget(self.note_title)
        editor_layout.addWidget(self.note_body)
        editor_layout.addWidget(self._nav_button("Save Note", self.save_note, "primary"))
        layout.addWidget(editor)

        self.notes_list = QListWidget()
        layout.addWidget(self.notes_list, 1)
        self.tabs.addTab(self.notes_page, "Notes")

    def _style_plot(self, widget: pg.PlotWidget) -> None:
        """Apply consistent styling to all pyqtgraph plots."""

        widget.setBackground("#0d2230")
        plot_item = widget.getPlotItem()
        plot_item.showGrid(x=True, y=True, alpha=0.18)
        plot_item.getAxis("left").setTextPen("#c3d8e3")
        plot_item.getAxis("bottom").setTextPen("#c3d8e3")
        plot_item.getAxis("left").setPen(pg.mkPen("#355b6f"))
        plot_item.getAxis("bottom").setPen(pg.mkPen("#355b6f"))
        plot_item.getAxis("left").setTickFont(self.font())
        plot_item.getAxis("bottom").setTickFont(self.font())
        plot_item.setTitle(plot_item.titleLabel.text, color="#edf4f7", size="12pt")

    def refresh_home(self) -> None:
        """Refresh project lists, dashboard summaries, and KPI cards."""

        self.recent_projects.clear()
        for row in self.db.recent_projects():
            item = QListWidgetItem(f"{row['name']} | {row['root_path']}")
            self.recent_projects.addItem(item)

        if self.project_root:
            project_text = str(self.project_root)
            self.project_summary.setText(f"Current project root: {project_text}")
            self.project_badge.setText(project_text)
        else:
            self.project_summary.setText("No project opened. Create one to organize captures, exports, notes, and reports.")
            self.project_badge.setText("No project opened")

        self._refresh_notes_list()
        self._refresh_dashboard_findings()
        self._refresh_metrics()

    def _refresh_dashboard_findings(self) -> None:
        """Mirror the active findings into the dashboard summary list."""

        self.dashboard_findings.clear()
        if not self.current_findings:
            self.dashboard_findings.addItem("No findings yet. Load a PCAP or start a live capture.")
            return
        for finding in self.current_findings[:50]:
            self.dashboard_findings.addItem(finding)

    def _refresh_notes_list(self) -> None:
        """Populate the notes list from the database for the current project."""

        self.notes_list.clear()
        for row in self.db.notes(self.project_id):
            self.notes_list.addItem(row["title"])

    def _refresh_metrics(self) -> None:
        """Update the top KPI cards using the current record set."""

        metrics = build_metrics(self.records)
        sessions = session_rows(self.records)
        self.metric_packets.set_metric(str(metrics["total_packets"]), "Packets currently loaded or captured.")
        self.metric_bytes.set_metric(str(metrics["total_bytes"]), "Total bytes represented in the active dataset.")
        self.metric_protocols.set_metric(str(len(metrics["protocols"])), "Distinct protocol labels visible in the workspace.")
        self.metric_flows.set_metric(str(len(sessions)), "Grouped source/destination/protocol conversations.")

    def create_project(self) -> None:
        """Prompt for a project name, create the folder structure, and open it."""

        name, ok = QInputDialog.getText(self, "Create Project", "Project name")
        if not ok or not name.strip():
            return
        root = PROJECTS_DIR / f"{name.strip().replace(' ', '_')}.scapyproj"
        for sub in ["captures", "exports", "reports", "notes"]:
            (root / sub).mkdir(parents=True, exist_ok=True)
        (root / "project.json").write_text(json.dumps({"name": name.strip()}, indent=2), encoding="utf-8")
        self.project_id = self.db.upsert_project(name.strip(), root)
        self.project_root = root
        self.refresh_home()
        self.statusBar().showMessage(f"Project opened: {root}")

    def open_project(self) -> None:
        """Open an existing Scapy Studio project folder."""

        path = QFileDialog.getExistingDirectory(self, "Open .scapyproj Folder", str(PROJECTS_DIR))
        if path:
            root = Path(path)
            self.project_root = root
            self.project_id = self.db.upsert_project(root.name, root)
            self.refresh_home()

    def open_recent_project(self) -> None:
        """Open a project selected from the dashboard list."""

        item = self.recent_projects.currentItem()
        if item:
            root = Path(item.text().split(" | ", 1)[1])
            self.project_root = root
            self.project_id = self.db.upsert_project(root.name, root)
            self.refresh_home()

    def import_pcaps(self) -> None:
        """Import one or more capture files, optionally copying them into the project."""

        files, _ = QFileDialog.getOpenFileNames(self, "Import PCAP Files", "", "Capture Files (*.pcap *.pcapng);;All Files (*)")
        for file in files:
            src = Path(file)
            target = src
            if self.project_root:
                target = self.project_root / "captures" / src.name
                if src.resolve() != target.resolve():
                    shutil.copy2(src, target)
            self.load_pcap(target)

    def import_folder(self) -> None:
        """Import all PCAP and PCAPNG files found below a chosen folder."""

        folder = QFileDialog.getExistingDirectory(self, "Import PCAP Folder", "")
        if not folder:
            return
        paths = sorted(Path(folder).rglob("*.pcap")) + sorted(Path(folder).rglob("*.pcapng"))
        if not paths:
            self.show_error("No .pcap or .pcapng files were found in that folder.")
            return
        for path in paths:
            target = path
            if self.project_root:
                target = self.project_root / "captures" / path.name
                if path.resolve() != target.resolve():
                    shutil.copy2(path, target)
            self.load_pcap(target)

    def open_pcap(self) -> None:
        """Prompt for one PCAP file and load it into the explorer."""

        file, _ = QFileDialog.getOpenFileName(self, "Open PCAP", "", "Capture Files (*.pcap *.pcapng);;All Files (*)")
        if file:
            self.load_pcap(Path(file))

    def load_pcap(self, path: Path) -> None:
        """Load a capture file on a worker thread so the UI remains responsive."""

        worker = PcapLoadWorker(path)
        thread = WorkerThread(worker)
        worker.finished.connect(self.on_pcap_loaded)
        worker.failed.connect(self.show_error)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.finished.connect(lambda: self._forget_worker_thread(thread))
        self.worker_thread = thread
        self.worker_threads.append(thread)
        thread.start()
        self.statusBar().showMessage(f"Loading {path}")

    def _forget_worker_thread(self, thread: WorkerThread) -> None:
        """Remove completed worker threads from the tracking list."""

        if thread in self.worker_threads:
            self.worker_threads.remove(thread)

    def on_pcap_loaded(self, records: list[PacketRecord], path: Path) -> None:
        """Apply capture results to all dependent views once background loading finishes."""

        self.records = records
        self.visible_records = list(records)
        self.current_path = path
        self.packet_table.set_packets(self.visible_records)
        self.db.add_capture(self.project_id, path, len(records), "imported")
        self.refresh_protocol_filter()
        self.populate_findings()
        self.update_flow_table()
        self.update_charts()
        self.refresh_home()
        self.tabs.setCurrentWidget(self.explorer_page)
        self.status_hint.setText(f"Loaded {len(records)} packets from {path.name}.")
        self.statusBar().showMessage(f"Loaded {len(records)} packets from {path.name}")

    def selected_record(self) -> PacketRecord | None:
        """Return the currently selected packet row, if any."""

        rows = self.packet_table.selectionModel().selectedRows()
        if not rows:
            return None
        index = rows[0].row()
        return self.visible_records[index] if 0 <= index < len(self.visible_records) else None

    def refresh_protocol_filter(self) -> None:
        """Rebuild the explorer protocol drop-down from the active packet set."""

        current = self.protocol_filter.currentText() if hasattr(self, "protocol_filter") else "All"
        self.protocol_filter.blockSignals(True)
        self.protocol_filter.clear()
        self.protocol_filter.addItem("All")
        for proto in sorted({rec.protocol for rec in self.records}):
            self.protocol_filter.addItem(proto)
        index = self.protocol_filter.findText(current)
        self.protocol_filter.setCurrentIndex(index if index >= 0 else 0)
        self.protocol_filter.blockSignals(False)

    def apply_packet_filter(self) -> None:
        """Apply the explorer search box and protocol filter."""

        self.visible_records = filter_records(
            self.records,
            self.search_edit.text(),
            self.protocol_filter.currentText(),
        )
        self.packet_table.set_packets(self.visible_records)
        self.statusBar().showMessage(f"Showing {len(self.visible_records)} of {len(self.records)} packets")

    def clear_packet_filter(self) -> None:
        """Reset the explorer filters back to the full packet set."""

        self.search_edit.clear()
        self.protocol_filter.setCurrentText("All")
        self.visible_records = list(self.records)
        self.packet_table.set_packets(self.visible_records)

    def update_packet_detail(self) -> None:
        """Refresh the packet detail and hex panes for the selected row."""

        rec = self.selected_record()
        if rec:
            self.detail_text.setPlainText(packet_details(rec.packet))
            self.hex_text.setPlainText(packet_hex(rec.packet))

    def populate_findings(self) -> None:
        """Generate lightweight findings and mirror them into the explorer and dashboard."""

        self.findings_list.clear()
        self.current_findings = []
        for title, severity, detail in simple_findings(self.records):
            finding = f"[{severity}] {title}: {detail}"
            self.current_findings.append(finding)
            self.findings_list.addItem(finding)
            self.db.add_finding(self.project_id, title, severity, detail)
        self._refresh_dashboard_findings()

    def update_flow_table(self) -> None:
        """Populate the flows table from grouped session data."""

        self.flow_table.setRowCount(0)
        for session in session_rows(self.records)[:500]:
            row = self.flow_table.rowCount()
            self.flow_table.insertRow(row)
            values = [
                session["source"],
                session["destination"],
                session["protocol"],
                session["packets"],
                session["bytes"],
                f"{session['first']:.6f}",
                f"{session['last']:.6f}",
            ]
            for col, value in enumerate(values):
                self.flow_table.setItem(row, col, QTableWidgetItem(str(value)))
        self.flow_table.resizeColumnsToContents()

    def update_charts(self) -> None:
        """Refresh all chart widgets from the current record set."""

        metrics = build_metrics(self.records)
        self._bar(self.protocol_plot, metrics["protocols"].most_common(10), "#2a9d8f")
        self._bar(self.source_plot, metrics["sources"].most_common(10), "#58a6ff")
        self._bar(self.dest_plot, metrics["destinations"].most_common(10), "#f4a261")
        self.bytes_plot.clear()
        xs = list(metrics["bytes_by_second"].keys())
        ys = list(metrics["bytes_by_second"].values())
        if xs:
            self.bytes_plot.plot(xs, ys, pen=pg.mkPen("#ffb703", width=2), symbol="o", symbolBrush="#ffb703")
        self._refresh_metrics()

    def _bar(self, widget: pg.PlotWidget, values: list[tuple[object, int]], color: str) -> None:
        """Render a small bar chart into a pyqtgraph widget."""

        widget.clear()
        if not values:
            return
        xs = list(range(len(values)))
        widget.addItem(pg.BarGraphItem(x=xs, height=[v for _, v in values], width=0.62, brush=color))
        axis = widget.getAxis("bottom")
        axis.setTicks([[(i, str(label)[:14]) for i, (label, _) in enumerate(values)]])

    def refresh_interfaces(self) -> None:
        """Populate the live capture interface list from Scapy's adapter catalog."""

        self.iface_combo.clear()
        try:
            for choice in self.live.interfaces():
                self.iface_combo.addItem(choice["label"], choice["device"])
        except Exception as exc:
            self.show_error(str(exc))

    def start_live_capture(self) -> None:
        """Clear the current dataset and start streaming packets from the selected interface."""

        self.records.clear()
        self.visible_records.clear()
        self.live_packets.clear()
        self.live_table.setRowCount(0)
        self.packet_table.setRowCount(0)
        self.findings_list.clear()
        self.dashboard_findings.clear()
        device = self.iface_combo.currentData() or self.iface_combo.currentText()
        self.live.start(str(device), self.filter_edit.text())
        self.status_hint.setText("Live capture running.")

    def show_interface_info(self) -> None:
        """Show friendly and low-level capture interface details to the user."""

        label = self.iface_combo.currentText()
        device = self.iface_combo.currentData()
        QMessageBox.information(
            self,
            "Capture Interface",
            "Scapy Studio shows the friendly Windows adapter name, but Scapy/Npcap captures using the device path.\n\n"
            f"Friendly name:\n{label}\n\n"
            f"Scapy/Npcap device:\n{device}\n\n"
            "For live capture on Windows, install Npcap and run Scapy Studio as Administrator if packets do not appear.",
        )

    def probe_selected_interface(self) -> None:
        """Capture briefly on the selected interface to validate permissions and adapter health."""

        device = str(self.iface_combo.currentData() or self.iface_combo.currentText())
        self.statusBar().showMessage("Probing selected interface for 5 seconds...")
        QApplication.processEvents()
        count, error = probe_capture(device, self.filter_edit.text(), 5)
        if error:
            self.show_error(
                "Capture probe failed.\n\n"
                f"Interface: {self.iface_combo.currentText()}\n"
                f"Device: {device}\n\n"
                f"{error}\n\n"
                "Try running Scapy Studio as Administrator and confirm Npcap is installed with WinPcap API-compatible mode."
            )
            return
        QMessageBox.information(
            self,
            "Capture Probe",
            f"Captured {count} packets in 5 seconds on:\n\n{self.iface_combo.currentText()}\n\n"
            "If this is 0, generate traffic on that adapter or try a different interface.",
        )
        self.statusBar().showMessage(f"Probe captured {count} packets.")

    def on_live_packet(self, rec: PacketRecord) -> None:
        """Append one live packet to the streaming capture tables and graphs."""

        self.records.append(rec)
        self.visible_records.append(rec)
        self.live_packets.append(rec.packet)
        self.live_table.add_packet(rec)
        self.packet_table.add_packet(rec)
        metrics = build_metrics(self.records[-500:])
        self.live_pps.clear()
        xs = list(metrics["packets_by_second"].keys())
        ys = list(metrics["packets_by_second"].values())
        if xs:
            self.live_pps.plot(xs, ys, pen=pg.mkPen("#2a9d8f", width=2), symbolBrush="#2a9d8f")
        self.populate_findings()
        self.update_flow_table()
        self.update_charts()

    def save_live_capture(self) -> None:
        """Persist the currently captured live packet buffer as a PCAP."""

        if not self.live_packets:
            self.show_error("No live packets are available to save.")
            return
        default = self.project_root / "captures" / "live-capture.pcap" if self.project_root else Path("live-capture.pcap")
        file, _ = QFileDialog.getSaveFileName(self, "Save Live Capture", str(default), "PCAP (*.pcap)")
        if file:
            export_selected_pcap(Path(file), self.live_packets)
            self.db.add_capture(self.project_id, Path(file), len(self.live_packets), "live")
            self.statusBar().showMessage(f"Saved {len(self.live_packets)} live packets to {file}")

    def clear_live_capture(self) -> None:
        """Reset the current live capture state."""

        self.records.clear()
        self.visible_records.clear()
        self.live_packets.clear()
        self.current_findings.clear()
        self.live_table.setRowCount(0)
        self.packet_table.setRowCount(0)
        self.live_pps.clear()
        self.findings_list.clear()
        self.dashboard_findings.clear()
        self.update_flow_table()
        self.update_charts()
        self.refresh_home()

    def build_packet(self) -> None:
        """Construct a packet from the builder form and show its decoded output."""

        try:
            pkt = Ether() / IP(src=self.src_ip.text(), dst=self.dst_ip.text())
            if self.transport.currentText() == "TCP":
                pkt = pkt / TCP(sport=int(self.src_port.text()), dport=int(self.dst_port.text()))
            else:
                pkt = pkt / UDP(sport=int(self.src_port.text()), dport=int(self.dst_port.text()))
            pkt = pkt / self.payload.text().encode("utf-8")
            self.builder_output.setPlainText(packet_details(pkt) + "\n\nRaw bytes:\n" + raw(pkt).hex(" "))
        except Exception as exc:
            self.show_error(str(exc))

    def save_packet_template(self) -> None:
        """Save the builder form contents as a JSON template."""

        file, _ = QFileDialog.getSaveFileName(self, "Save Packet Template", "", "JSON (*.json)")
        if file:
            config = {
                "src_ip": self.src_ip.text(),
                "dst_ip": self.dst_ip.text(),
                "transport": self.transport.currentText(),
                "src_port": self.src_port.text(),
                "dst_port": self.dst_port.text(),
                "payload": self.payload.text(),
            }
            Path(file).write_text(json.dumps(config, indent=2), encoding="utf-8")

    def inspect_protocol(self) -> None:
        """Show key fields for a small curated set of common Scapy layers."""

        name = self.protocol_query.text().strip()
        self.protocol_tree.clear()
        namespace = {"IP": IP, "TCP": TCP, "UDP": UDP, "Ether": Ether}
        layer = namespace.get(name)
        if layer is None:
            self.protocol_tree.addTopLevelItem(QTreeWidgetItem([name, "Use IP, TCP, UDP, or Ether for structured field browsing."]))
            self.protocol_tree.addTopLevelItem(QTreeWidgetItem(["Scapy explore()", "Use the Scapy console for the full contributed protocol catalog."]))
            return
        root = QTreeWidgetItem([name, layer.__doc__ or "Scapy layer"])
        self.protocol_tree.addTopLevelItem(root)
        for field in layer.fields_desc:
            root.addChild(QTreeWidgetItem([field.name, repr(field.default)]))
        root.setExpanded(True)

    def save_selected_pcap(self) -> None:
        """Write the selected packet row to a single-packet PCAP."""

        rec = self.selected_record()
        if not rec:
            return
        file, _ = QFileDialog.getSaveFileName(self, "Save Selected Packet", "", "PCAP (*.pcap)")
        if file:
            export_selected_pcap(Path(file), [rec.packet])

    def show_packet_json(self) -> None:
        """Display the selected packet in JSON form."""

        rec = self.selected_record()
        if rec:
            self.detail_text.setPlainText(packet_json(rec.packet))

    def pdf_dump_packet(self) -> None:
        """Export the selected packet as a PDF dump."""

        rec = self.selected_record()
        if not rec:
            return
        file, _ = QFileDialog.getSaveFileName(self, "PDF Dump", "", "PDF (*.pdf)")
        if file:
            export_packet_pdf(Path(file), rec.packet)

    def ps_dump_packet(self) -> None:
        """Export the selected packet as a PostScript dump."""

        rec = self.selected_record()
        if not rec:
            return
        file, _ = QFileDialog.getSaveFileName(self, "PS Dump", "", "PostScript (*.ps)")
        if file:
            export_packet_ps(Path(file), rec.packet)

    def export_html(self) -> None:
        """Export the current dataset as a standalone HTML report."""

        if not self.records:
            self.show_error("Load or capture packets before exporting a report.")
            return
        default = self.project_root / "reports" / "report.html" if self.project_root else Path("scapy-studio-report.html")
        file, _ = QFileDialog.getSaveFileName(self, "Export HTML Report", str(default), "HTML (*.html)")
        if file:
            export_html_report(Path(file), self.records)
            self.report_log.append(f"Exported HTML report: {file}")

    def export_json(self) -> None:
        """Export up to the first 1000 packets as JSON rows."""

        if not self.records:
            self.show_error("Load or capture packets before exporting JSON.")
            return
        file, _ = QFileDialog.getSaveFileName(self, "Export Packet JSON", "", "JSON (*.json)")
        if file:
            rows = [json.loads(packet_json(r.packet)) for r in self.records[:1000]]
            Path(file).write_text(json.dumps(rows, indent=2), encoding="utf-8")
            self.report_log.append(f"Exported packet JSON: {file}")

    def export_findings(self) -> None:
        """Export the current findings list as CSV."""

        if not self.current_findings:
            self.show_error("No findings are available to export.")
            return
        default = self.project_root / "exports" / "findings.csv" if self.project_root else Path("findings.csv")
        file, _ = QFileDialog.getSaveFileName(self, "Export Findings CSV", str(default), "CSV (*.csv)")
        if file:
            export_findings_csv(Path(file), self.current_findings)
            self.report_log.append(f"Exported findings CSV: {file}")

    def export_sessions(self) -> None:
        """Export grouped flow rows as JSON."""

        if not self.records:
            self.show_error("Load or capture packets before exporting sessions.")
            return
        default = self.project_root / "exports" / "sessions.json" if self.project_root else Path("sessions.json")
        file, _ = QFileDialog.getSaveFileName(self, "Export Sessions JSON", str(default), "JSON (*.json)")
        if file:
            export_sessions_json(Path(file), session_rows(self.records))
            self.report_log.append(f"Exported sessions JSON: {file}")

    def export_project_archive(self) -> None:
        """Archive the current project folder into a zip file."""

        if not self.project_root:
            self.show_error("Open or create a project before exporting an archive.")
            return
        default = self.project_root.parent / f"{self.project_root.name}.zip"
        file, _ = QFileDialog.getSaveFileName(self, "Archive Project", str(default), "ZIP (*.zip)")
        if file:
            archive = archive_project(self.project_root, Path(file))
            self.report_log.append(f"Created project archive: {archive}")

    def compare_with_pcap(self) -> None:
        """Compare the current dataset against another capture at a summary level."""

        if not self.records:
            self.show_error("Load a baseline PCAP first.")
            return
        file, _ = QFileDialog.getOpenFileName(self, "Compare With PCAP", "", "Capture Files (*.pcap *.pcapng);;All Files (*)")
        if not file:
            return
        try:
            other = load_packets(Path(file))
            metrics = compare_metrics(self.records, other)
            lines = [
                f"Baseline packets: {metrics['left_packets']}",
                f"Comparison packets: {metrics['right_packets']}",
                f"Packet delta: {metrics['packet_delta']}",
                f"Baseline bytes: {metrics['left_bytes']}",
                f"Comparison bytes: {metrics['right_bytes']}",
                f"Byte delta: {metrics['byte_delta']}",
                "Protocol deltas:",
            ]
            lines.extend(f"  {proto}: {delta:+d}" for proto, delta in metrics["protocol_delta"].items())
            QMessageBox.information(self, "Capture Compare", "\n".join(lines))
        except Exception as exc:
            self.show_error(str(exc))

    def save_note(self) -> None:
        """Persist the current note to the database and, if applicable, the project folder."""

        title = self.note_title.text().strip() or "Untitled Note"
        body = self.note_body.toPlainText()
        self.db.add_note(self.project_id, title, body)
        if self.project_root:
            path = self.project_root / "notes" / f"{title.replace(' ', '_')}.md"
            path.write_text(body, encoding="utf-8")
        self.note_title.clear()
        self.note_body.clear()
        self.refresh_home()

    def open_help(self) -> None:
        """Open the local HTML help document in the default browser."""

        if HELP_PATH.exists():
            webbrowser.open(HELP_PATH.as_uri())
        else:
            self.show_error(f"Help file not found: {HELP_PATH}")

    def open_github(self) -> None:
        """Open the public GitHub repository in the default browser."""

        webbrowser.open(REPO_URL)

    def show_error(self, message: str) -> None:
        """Display an error dialog and mirror the message in the status bar."""

        QMessageBox.warning(self, APP_NAME, message)
        self.statusBar().showMessage(message)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse optional startup arguments used for testing and screenshots."""

    parser = argparse.ArgumentParser(prog="scapy_studio", add_help=True)
    parser.add_argument("--pcap", type=Path, help="Optional capture file to load at startup.")
    parser.add_argument(
        "--tab",
        choices=["dashboard", "capture", "explorer", "flows", "charts", "builder", "protocols", "reports", "notes"],
        help="Optional tab to select after startup.",
    )
    parser.add_argument("--screenshot", type=Path, help="Optional output path for an automatic window screenshot.")
    parser.add_argument("--shot-delay", type=int, default=1400, help="Delay before saving a screenshot in milliseconds.")
    parser.add_argument("--close-after", type=int, default=0, help="Close automatically after N milliseconds.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Application entry point used by the launcher and `python -m scapy_studio`."""

    args = _parse_args(list(sys.argv[1:] if argv is None else argv))
    app = QApplication(sys.argv[:1] + (argv or sys.argv[1:]))
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")
    pg.setConfigOptions(antialias=True, foreground=QColor("#edf4f7"))

    win = ScapyStudio()
    win.show()

    if args.pcap:
        QTimer.singleShot(250, lambda: win.load_pcap(args.pcap))

    if args.tab:
        tab_names = {
            "dashboard": win.dashboard_page,
            "capture": win.capture_page,
            "explorer": win.explorer_page,
            "flows": win.flows_page,
            "charts": win.charts_page,
            "builder": win.builder_page,
            "protocols": win.protocols_page,
            "reports": win.reports_page,
            "notes": win.notes_page,
        }
        QTimer.singleShot(450, lambda: win.tabs.setCurrentWidget(tab_names[args.tab]))

    if args.screenshot:
        def save_screenshot() -> None:
            args.screenshot.parent.mkdir(parents=True, exist_ok=True)
            screen = app.primaryScreen()
            if screen is not None:
                screen.grabWindow(win.winId()).save(str(args.screenshot))
            if args.close_after <= 0:
                win.close()

        QTimer.singleShot(max(args.shot_delay, 800), save_screenshot)

    if args.close_after > 0:
        QTimer.singleShot(args.close_after, win.close)

    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
