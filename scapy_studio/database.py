"""
SQLite persistence layer for Scapy Studio projects.

Code updates and public-repo packaging by Ayman Elbanhawy (c) SoftwareMile.com.
"""

# Copyright (c) Ayman Elbanhawy - SoftwareMile.com

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    root_path TEXT NOT NULL UNIQUE,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS captures (
    id INTEGER PRIMARY KEY,
    project_id INTEGER,
    path TEXT NOT NULL,
    packet_count INTEGER DEFAULT 0,
    imported_at TEXT DEFAULT CURRENT_TIMESTAMP,
    tags TEXT DEFAULT '',
    FOREIGN KEY(project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    project_id INTEGER,
    title TEXT NOT NULL,
    severity TEXT DEFAULT 'Info',
    detail TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY,
    project_id INTEGER,
    title TEXT NOT NULL,
    body TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS chart_configs (
    id INTEGER PRIMARY KEY,
    project_id INTEGER,
    name TEXT NOT NULL,
    config_json TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(project_id) REFERENCES projects(id)
);
CREATE TABLE IF NOT EXISTS saved_filters (
    id INTEGER PRIMARY KEY,
    project_id INTEGER,
    name TEXT NOT NULL,
    expression TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(project_id) REFERENCES projects(id)
);
"""


class StudioDatabase:
    """Thin wrapper around SQLite so the GUI stays focused on presentation logic."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        """Close the open SQLite connection."""

        self.conn.close()

    def upsert_project(self, name: str, root_path: Path) -> int:
        """Create or refresh the metadata row for a project directory."""

        self.conn.execute(
            """
            INSERT INTO projects(name, root_path) VALUES(?, ?)
            ON CONFLICT(root_path) DO UPDATE SET name=excluded.name, updated_at=CURRENT_TIMESTAMP
            """,
            (name, str(root_path)),
        )
        self.conn.commit()
        row = self.conn.execute("SELECT id FROM projects WHERE root_path=?", (str(root_path),)).fetchone()
        return int(row["id"])

    def add_capture(self, project_id: int | None, path: Path, packet_count: int, tags: str = "") -> None:
        """Store a capture import or live-save event."""

        self.conn.execute(
            "INSERT INTO captures(project_id, path, packet_count, tags) VALUES(?, ?, ?, ?)",
            (project_id, str(path), packet_count, tags),
        )
        self.conn.commit()

    def add_finding(self, project_id: int | None, title: str, severity: str, detail: str) -> None:
        """Persist a dashboard finding so it can be reviewed later."""

        self.conn.execute(
            "INSERT INTO findings(project_id, title, severity, detail) VALUES(?, ?, ?, ?)",
            (project_id, title, severity, detail),
        )
        self.conn.commit()

    def add_note(self, project_id: int | None, title: str, body: str) -> None:
        """Persist an analyst note."""

        self.conn.execute(
            "INSERT INTO notes(project_id, title, body) VALUES(?, ?, ?)",
            (project_id, title, body),
        )
        self.conn.commit()

    def save_chart_config(self, project_id: int | None, name: str, config: dict[str, Any]) -> None:
        """Reserved helper for future user-custom chart presets."""

        self.conn.execute(
            "INSERT INTO chart_configs(project_id, name, config_json) VALUES(?, ?, ?)",
            (project_id, name, json.dumps(config, indent=2)),
        )
        self.conn.commit()

    def recent_projects(self) -> list[sqlite3.Row]:
        """Return the most recently touched projects for the dashboard list."""

        return list(
            self.conn.execute(
                "SELECT * FROM projects ORDER BY updated_at DESC, id DESC LIMIT 12"
            )
        )

    def captures(self, project_id: int | None = None) -> list[sqlite3.Row]:
        """Fetch capture history, optionally scoped to one project."""

        if project_id is None:
            return list(self.conn.execute("SELECT * FROM captures ORDER BY imported_at DESC LIMIT 100"))
        return list(
            self.conn.execute(
                "SELECT * FROM captures WHERE project_id=? ORDER BY imported_at DESC",
                (project_id,),
            )
        )

    def notes(self, project_id: int | None = None) -> list[sqlite3.Row]:
        """Fetch stored analyst notes."""

        if project_id is None:
            return list(self.conn.execute("SELECT * FROM notes ORDER BY updated_at DESC LIMIT 100"))
        return list(
            self.conn.execute("SELECT * FROM notes WHERE project_id=? ORDER BY updated_at DESC", (project_id,))
        )

    def findings(self, project_id: int | None = None) -> list[sqlite3.Row]:
        """Fetch stored findings, newest first."""

        if project_id is None:
            return list(self.conn.execute("SELECT * FROM findings ORDER BY created_at DESC LIMIT 100"))
        return list(
            self.conn.execute("SELECT * FROM findings WHERE project_id=? ORDER BY created_at DESC", (project_id,))
        )
