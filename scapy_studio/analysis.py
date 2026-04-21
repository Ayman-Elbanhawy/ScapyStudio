"""
Packet parsing and reporting helpers for Scapy Studio.

Code updates and public-repo packaging by Ayman Elbanhawy (c) SoftwareMile.com.
"""

# Copyright (c) Ayman Elbanhawy - SoftwareMile.com

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scapy.all import Ether, IP, IPv6, TCP, UDP, hexdump, raw, rdpcap, wrpcap


@dataclass(slots=True)
class PacketRecord:
    """Normalized packet metadata used by the GUI tables and charts."""

    index: int
    time: float
    source: str
    destination: str
    protocol: str
    length: int
    summary: str
    packet: Any


def packet_protocol(pkt: Any) -> str:
    """Return a simple protocol label that is stable enough for charts and filters."""

    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(IP):
        return str(pkt[IP].proto)
    if pkt.haslayer(IPv6):
        return str(pkt[IPv6].nh)
    return pkt.name if hasattr(pkt, "name") else pkt.__class__.__name__


def packet_endpoints(pkt: Any) -> tuple[str, str]:
    """Extract the most useful source and destination fields available for the packet."""

    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    if pkt.haslayer(Ether):
        return pkt[Ether].src, pkt[Ether].dst
    return "", ""


def load_packets(path: Path, limit: int | None = None) -> list[PacketRecord]:
    """
    Read a capture file and project every packet into a UI-friendly record.

    Keeping this transformation in one function makes the desktop code easier to
    reason about and reduces repeated per-packet logic in multiple widgets.
    """

    packets = rdpcap(str(path), count=limit or -1)
    records: list[PacketRecord] = []
    for idx, pkt in enumerate(packets, 1):
        src, dst = packet_endpoints(pkt)
        records.append(
            PacketRecord(
                index=idx,
                time=float(getattr(pkt, "time", 0.0)),
                source=src,
                destination=dst,
                protocol=packet_protocol(pkt),
                length=len(pkt),
                summary=pkt.summary(),
                packet=pkt,
            )
        )
    return records


def packet_details(pkt: Any) -> str:
    """Return Scapy's verbose field dump for the selected packet."""

    return pkt.show(dump=True)


def packet_hex(pkt: Any) -> str:
    """Return a printable hex dump for the selected packet."""

    return hexdump(pkt, dump=True)


def packet_json(pkt: Any) -> str:
    """Return Scapy's JSON representation, or a safe fallback when unavailable."""

    try:
        return pkt.json()
    except Exception:
        return "{}"


def export_selected_pcap(path: Path, packets: list[Any]) -> None:
    """Write a packet list back to disk as a PCAP file."""

    wrpcap(str(path), packets)


def export_packet_pdf(path: Path, pkt: Any) -> None:
    """
    Export a packet dump to PDF.

    Scapy can sometimes render directly. When it cannot, the fallback produces a
    deterministic analyst-friendly text PDF so export still succeeds.
    """

    try:
        pkt.pdfdump(str(path))
        return
    except Exception:
        from matplotlib.backends.backend_pdf import PdfPages
        import matplotlib.pyplot as plt

        lines = packet_details(pkt).splitlines() or [pkt.summary()]
        with PdfPages(str(path)) as pdf:
            for offset in range(0, len(lines), 58):
                fig = plt.figure(figsize=(8.5, 11))
                fig.text(0.05, 0.96, "Scapy Studio Packet Dump", fontsize=11, weight="bold")
                fig.text(
                    0.05,
                    0.92,
                    "\n".join(lines[offset : offset + 58]),
                    family="monospace",
                    fontsize=7,
                    va="top",
                )
                fig.subplots_adjust(left=0, right=1, top=1, bottom=0)
                pdf.savefig(fig)
                plt.close(fig)


def export_packet_ps(path: Path, pkt: Any) -> None:
    """
    Export a PostScript text dump for environments where Scapy's native PS path fails.
    """

    try:
        pkt.psdump(str(path))
        return
    except Exception:
        lines = packet_details(pkt).splitlines() or [pkt.summary()]
        escaped = [_ps_escape(line[:108]) for line in lines]
        y_start = 760
        line_height = 10
        body: list[str] = [
            "%!PS-Adobe-3.0",
            "%%Pages: (atend)",
            "/Courier findfont 8 scalefont setfont",
        ]
        page = 1
        y = y_start
        body.extend([f"%%Page: {page} {page}", "72 792 moveto (Scapy Studio Packet Dump) show"])
        for line in escaped:
            if y < 40:
                body.append("showpage")
                page += 1
                y = y_start
                body.extend([f"%%Page: {page} {page}", "72 792 moveto (Scapy Studio Packet Dump) show"])
            body.append(f"72 {y} moveto ({line}) show")
            y -= line_height
        body.extend(["showpage", f"%%Pages: {page}", "%%EOF"])
        path.write_text("\n".join(body), encoding="utf-8")


def _ps_escape(text: str) -> str:
    """Escape characters that would break a PostScript string literal."""

    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def record_matches(rec: PacketRecord, query: str) -> bool:
    """Perform a small free-text search against the packet table columns."""

    query = query.strip().lower()
    if not query:
        return True
    haystack = " ".join(
        [
            str(rec.index),
            rec.source,
            rec.destination,
            rec.protocol,
            str(rec.length),
            rec.summary,
        ]
    ).lower()
    return query in haystack


def filter_records(records: list[PacketRecord], query: str = "", protocol: str = "All") -> list[PacketRecord]:
    """Apply the current text and protocol filters used by the explorer view."""

    protocol = protocol.strip()
    return [
        rec
        for rec in records
        if (protocol == "All" or rec.protocol == protocol) and record_matches(rec, query)
    ]


def build_metrics(records: list[PacketRecord]) -> dict[str, Any]:
    """Aggregate packet statistics for dashboard cards, charts, and reports."""

    protocols = Counter(r.protocol for r in records)
    sources = Counter(r.source for r in records if r.source)
    destinations = Counter(r.destination for r in records if r.destination)
    conversations: Counter[tuple[str, str]] = Counter()
    bytes_by_second: defaultdict[int, int] = defaultdict(int)
    packets_by_second: defaultdict[int, int] = defaultdict(int)

    for rec in records:
        if rec.source or rec.destination:
            conversations[(rec.source, rec.destination)] += 1
        second = int(rec.time)
        packets_by_second[second] += 1
        bytes_by_second[second] += rec.length

    return {
        "protocols": protocols,
        "sources": sources,
        "destinations": destinations,
        "conversations": conversations,
        "packets_by_second": dict(sorted(packets_by_second.items())),
        "bytes_by_second": dict(sorted(bytes_by_second.items())),
        "total_packets": len(records),
        "total_bytes": sum(r.length for r in records),
    }


def session_rows(records: list[PacketRecord]) -> list[dict[str, Any]]:
    """Group packets into source/destination/protocol conversations for the flows view."""

    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for rec in records:
        key = (rec.source, rec.destination, rec.protocol)
        row = grouped.setdefault(
            key,
            {
                "source": rec.source,
                "destination": rec.destination,
                "protocol": rec.protocol,
                "packets": 0,
                "bytes": 0,
                "first": rec.time,
                "last": rec.time,
                "samples": [],
            },
        )
        row["packets"] += 1
        row["bytes"] += rec.length
        row["first"] = min(row["first"], rec.time)
        row["last"] = max(row["last"], rec.time)
        if len(row["samples"]) < 3:
            row["samples"].append(rec.summary)
    return sorted(grouped.values(), key=lambda item: (item["bytes"], item["packets"]), reverse=True)


def compare_metrics(left: list[PacketRecord], right: list[PacketRecord]) -> dict[str, Any]:
    """Compare two captures at a summary level for quick baseline triage."""

    left_metrics = build_metrics(left)
    right_metrics = build_metrics(right)
    all_protocols = sorted(set(left_metrics["protocols"]) | set(right_metrics["protocols"]))
    protocol_delta = {
        proto: right_metrics["protocols"].get(proto, 0) - left_metrics["protocols"].get(proto, 0)
        for proto in all_protocols
    }
    return {
        "left_packets": len(left),
        "right_packets": len(right),
        "packet_delta": len(right) - len(left),
        "left_bytes": left_metrics["total_bytes"],
        "right_bytes": right_metrics["total_bytes"],
        "byte_delta": right_metrics["total_bytes"] - left_metrics["total_bytes"],
        "protocol_delta": protocol_delta,
    }


def simple_findings(records: list[PacketRecord]) -> list[tuple[str, str, str]]:
    """
    Generate lightweight findings for the dashboard.

    These are intentionally simple analyst hints rather than deep detections.
    """

    findings: list[tuple[str, str, str]] = []
    protocols = Counter(r.protocol for r in records)
    if protocols.get("TCP", 0) > 0:
        findings.append(("TCP traffic observed", "Info", f"{protocols['TCP']} TCP packets were decoded."))
    if protocols.get("UDP", 0) > 0:
        findings.append(("UDP traffic observed", "Info", f"{protocols['UDP']} UDP packets were decoded."))

    top_sources = Counter(r.source for r in records if r.source)
    if top_sources:
        host, count = top_sources.most_common(1)[0]
        findings.append(("Top source host", "Info", f"{host} produced {count} packets."))
    return findings


def raw_len(pkt: Any) -> int:
    """Return raw packet length, which is useful for future export extensions."""

    return len(raw(pkt))
