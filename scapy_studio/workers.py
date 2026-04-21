"""
Background workers for Scapy Studio file loads and live capture.

Code updates and public-repo packaging by Ayman Elbanhawy (c) SoftwareMile.com.
"""

# Copyright (c) Ayman Elbanhawy - SoftwareMile.com

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal, Slot
from scapy.all import AsyncSniffer, conf, sniff

from .analysis import PacketRecord, load_packets, packet_endpoints, packet_protocol


class PcapLoadWorker(QObject):
    """Worker that loads capture files off the UI thread."""

    finished = Signal(list, Path)
    failed = Signal(str)

    def __init__(self, path: Path, limit: int | None = None) -> None:
        super().__init__()
        self.path = path
        self.limit = limit

    @Slot()
    def run(self) -> None:
        """Perform the capture read and return normalized packet records."""

        try:
            self.finished.emit(load_packets(self.path, self.limit), self.path)
        except Exception as exc:
            self.failed.emit(str(exc))


class WorkerThread(QThread):
    """Small utility thread that owns one QObject worker."""

    def __init__(self, worker: QObject) -> None:
        super().__init__()
        self.worker = worker
        self.worker.moveToThread(self)
        self.started.connect(worker.run)  # type: ignore[attr-defined]


class LiveCaptureWorker(QObject):
    """Owns the Scapy sniffer used by the live capture workspace."""

    packet = Signal(object)
    status = Signal(str)
    failed = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.sniffer: AsyncSniffer | None = None
        self.index = 0

    def interfaces(self) -> list[dict[str, str]]:
        """Return user-friendly interface choices with useful adapter context."""

        choices: list[dict[str, str]] = []
        for iface in conf.ifaces.values():
            name = str(getattr(iface, "name", "") or "")
            description = str(getattr(iface, "description", "") or "")
            device = str(getattr(iface, "network_name", "") or name)
            mac = str(getattr(iface, "mac", "") or "")
            ips_obj = getattr(iface, "ips", {}) or {}
            ips: list[str] = []
            try:
                for values in ips_obj.values():
                    ips.extend(str(value) for value in values)
            except Exception:
                pass
            label_parts = [part for part in [name, description] if part]
            label = " - ".join(label_parts) if label_parts else device
            detail = ", ".join([value for value in [mac, " ".join(ips)] if value])
            if detail:
                label = f"{label} [{detail}]"
            choices.append(
                {
                    "label": label,
                    "device": device,
                    "name": name,
                    "description": description,
                    "mac": mac,
                    "ips": " ".join(ips),
                }
            )
        choices.sort(key=_interface_sort_key)
        return choices

    def start(self, iface: str | None, capture_filter: str = "") -> None:
        """Start a non-blocking live capture session."""

        if self.sniffer and self.sniffer.running:
            self.status.emit("Capture is already running.")
            return
        try:
            self.index = 0
            kwargs: dict[str, Any] = {"prn": self._on_packet, "store": False}
            if iface:
                kwargs["iface"] = iface
            if capture_filter.strip():
                kwargs["filter"] = capture_filter.strip()
            self.sniffer = AsyncSniffer(**kwargs)
            self.sniffer.start()
            self.status.emit("Live capture started.")
        except Exception as exc:
            self.failed.emit(str(exc))

    def stop(self) -> None:
        """Stop an active live capture session."""

        try:
            if self.sniffer and self.sniffer.running:
                self.sniffer.stop()
            self.status.emit("Live capture stopped.")
        except Exception as exc:
            self.failed.emit(str(exc))

    def _on_packet(self, pkt: Any) -> None:
        """Normalize each live packet before handing it to the GUI."""

        self.index += 1
        src, dst = packet_endpoints(pkt)
        rec = PacketRecord(
            index=self.index,
            time=float(getattr(pkt, "time", 0.0)),
            source=src,
            destination=dst,
            protocol=packet_protocol(pkt),
            length=len(pkt),
            summary=pkt.summary(),
            packet=pkt,
        )
        self.packet.emit(rec)


def probe_capture(iface: str, capture_filter: str = "", timeout: int = 5) -> tuple[int, str]:
    """Perform a short blocking probe so the user can validate an interface quickly."""

    try:
        kwargs: dict[str, Any] = {"iface": iface, "timeout": timeout, "store": True}
        if capture_filter.strip():
            kwargs["filter"] = capture_filter.strip()
        packets = sniff(**kwargs)
        return len(packets), ""
    except Exception as exc:
        return 0, str(exc)


def _interface_sort_key(choice: dict[str, str]) -> tuple[int, str]:
    """
    Push likely analyst-facing adapters to the top of the list.

    Windows often exposes many virtual adapters, so this heuristic improves the
    first-run experience without hiding any interfaces.
    """

    text = f"{choice.get('name', '')} {choice.get('description', '')}".lower()
    name = choice.get("name", "").lower()
    has_mac = bool(choice.get("mac"))
    has_ip = bool(choice.get("ips"))
    if name in {"wi-fi", "wifi"}:
        priority = 0
    elif "ethernet" in text:
        priority = 1
    elif ("wi-fi" in text or "wireless" in text) and "direct" not in text and "virtual" not in text:
        priority = 2
    elif "wi-fi direct" in text or "virtual adapter" in text:
        priority = 4
    elif has_mac and has_ip and "bluetooth" not in text:
        priority = 3
    elif "bluetooth" in text:
        priority = 5
    elif "loopback" in text:
        priority = 8
    elif "wan miniport" in text:
        priority = 9
    else:
        priority = 5
    return priority, choice.get("name", "")
