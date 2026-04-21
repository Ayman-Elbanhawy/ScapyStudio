"""
Report and export helpers for Scapy Studio.

Code updates and public-repo packaging by Ayman Elbanhawy (c) SoftwareMile.com.
"""

# Copyright (c) Ayman Elbanhawy - SoftwareMile.com

from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path

import plotly.graph_objects as go
from plotly.offline import plot

from . import REPO_URL, SUPPORT_EMAIL, WEBSITE_URL
from .analysis import PacketRecord, build_metrics


def export_html_report(path: Path, records: list[PacketRecord], title: str = "Scapy Studio Report") -> None:
    """
    Export a polished standalone HTML report with summary cards and Plotly charts.
    """

    metrics = build_metrics(records)
    protocols = metrics["protocols"]
    sources = metrics["sources"].most_common(10)
    destinations = metrics["destinations"].most_common(10)

    figures = []
    if protocols:
        figures.append(
            go.Figure(
                data=[go.Pie(labels=list(protocols.keys()), values=list(protocols.values()), hole=0.45)],
                layout=go.Layout(title="Protocol Mix"),
            )
        )
    if sources:
        figures.append(
            go.Figure(
                data=[go.Bar(x=[h for h, _ in sources], y=[c for _, c in sources], marker_color="#2a9d8f")],
                layout=go.Layout(title="Top Source IPs"),
            )
        )
    if destinations:
        figures.append(
            go.Figure(
                data=[go.Bar(x=[h for h, _ in destinations], y=[c for _, c in destinations], marker_color="#f4a261")],
                layout=go.Layout(title="Top Destination IPs"),
            )
        )
    if metrics["packets_by_second"]:
        xs = list(metrics["packets_by_second"].keys())
        figures.append(
            go.Figure(
                data=[go.Scatter(x=xs, y=list(metrics["packets_by_second"].values()), mode="lines+markers")],
                layout=go.Layout(title="Packets Per Second"),
            )
        )

    chart_html = "\n".join(plot(fig, include_plotlyjs="cdn", output_type="div") for fig in figures)
    sample_rows = "\n".join(
        f"<tr><td>{r.index}</td><td>{r.protocol}</td><td>{r.source}</td><td>{r.destination}</td><td>{r.length}</td><td>{r.summary}</td></tr>"
        for r in records[:200]
    )
    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{title}</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0a1a24;
      --panel: #122634;
      --panel-alt: #183444;
      --line: #2b4f63;
      --text: #e8f0f5;
      --muted: #9cb4c3;
      --mint: #2a9d8f;
      --amber: #f4a261;
    }}
    body {{ font-family: "Segoe UI", Arial, sans-serif; margin: 0; background: linear-gradient(180deg, #07131b 0%, var(--bg) 100%); color: var(--text); }}
    .shell {{ max-width: 1280px; margin: 0 auto; padding: 28px; }}
    .hero {{ background: linear-gradient(135deg, rgba(42,157,143,.22), rgba(18,38,52,.92)); border: 1px solid var(--line); border-radius: 22px; padding: 24px; }}
    h1, h2 {{ margin: 0 0 12px; }}
    p {{ color: var(--muted); }}
    .links {{ margin-top: 14px; }}
    .links a {{ color: #8dd8d2; text-decoration: none; margin-right: 18px; }}
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 20px 0; }}
    .metric {{ border: 1px solid var(--line); background: var(--panel); padding: 16px; border-radius: 18px; }}
    .metric strong {{ display: block; margin-bottom: 8px; font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; }}
    .charts {{ display: grid; gap: 18px; }}
    .table-shell {{ margin-top: 24px; border: 1px solid var(--line); border-radius: 18px; overflow: hidden; background: var(--panel); }}
    table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
    th, td {{ border-bottom: 1px solid rgba(255,255,255,.08); padding: 10px 12px; text-align: left; vertical-align: top; }}
    th {{ background: var(--panel-alt); color: var(--text); }}
    tr:nth-child(even) td {{ background: rgba(255,255,255,.02); }}
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <h1>{title}</h1>
      <p>Desktop report exported from Scapy Studio for packet analysis, flow review, and capture comparison.</p>
      <div class="links">
        <a href="{REPO_URL}">GitHub Repository</a>
        <a href="{WEBSITE_URL}">SoftwareMile.com</a>
        <a href="mailto:{SUPPORT_EMAIL}">{SUPPORT_EMAIL}</a>
      </div>
    </section>
    <section class="summary">
      <div class="metric"><strong>Total Packets</strong>{metrics["total_packets"]}</div>
      <div class="metric"><strong>Total Bytes</strong>{metrics["total_bytes"]}</div>
      <div class="metric"><strong>Protocols</strong>{len(protocols)}</div>
      <div class="metric"><strong>Top Talkers</strong>{len(sources)}</div>
    </section>
    <section class="charts">{chart_html}</section>
    <section class="table-shell">
      <table>
        <thead><tr><th>#</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Bytes</th><th>Summary</th></tr></thead>
        <tbody>{sample_rows}</tbody>
      </table>
    </section>
  </div>
</body>
</html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")


def export_findings_csv(path: Path, findings: list[str]) -> None:
    """Export the generated findings list as a one-column CSV for ticketing or triage."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["finding"])
        for finding in findings:
            writer.writerow([finding])


def export_sessions_json(path: Path, sessions: list[dict]) -> None:
    """Export normalized conversation rows to JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sessions, indent=2, default=str), encoding="utf-8")


def archive_project(project_root: Path, target_zip: Path) -> Path:
    """Create a zip archive of the current project workspace."""

    target_zip.parent.mkdir(parents=True, exist_ok=True)
    base = target_zip.with_suffix("")
    archive = shutil.make_archive(str(base), "zip", project_root)
    return Path(archive)
