"""SQLite helpers: connection, schema init, ingestion_log, source registry."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from engine.config import settings

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    settings.ensure_dirs()
    conn = sqlite3.connect(str(db_path or settings.DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_PATH.read_text())
    register_sources(conn)
    conn.commit()


def register_sources(conn: sqlite3.Connection) -> None:
    rows = [
        ("NVD", "NIST National Vulnerability Database — CVE records, CVSS, CPE, CWE, references",
         settings.NVD_BASE_URL, "US Government work; public domain. Attribution requested.", "daily", "primary"),
        ("CISA_KEV", "CISA Known Exploited Vulnerabilities Catalog",
         settings.KEV_URL, "Public. Attribution to CISA.", "daily (as published)", "exploitation"),
        ("EPSS", "FIRST Exploit Prediction Scoring System — daily probability and percentile",
         settings.EPSS_SITE, "Free; attribution to FIRST.org requested.", "daily", "likelihood"),
        ("VENDOR", "Official vendor security advisories (selected CVEs only)",
         "n/a", "Per vendor terms", "on demand", "remediation"),
    ]
    conn.executemany(
        """INSERT OR REPLACE INTO data_sources
           (source_name, description, url, license_or_terms, update_frequency, role)
           VALUES (?,?,?,?,?,?)""", rows)


def new_run_id(source: str) -> str:
    return f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}_{source.lower()}"


def log_start(conn: sqlite3.Connection, run_id: str, source: str, mode: str, params: dict | None = None) -> None:
    conn.execute(
        "INSERT INTO ingestion_log (run_id, source, mode, start_time, status, params) VALUES (?,?,?,?,?,?)",
        (run_id, source, mode, utcnow(), "running", json.dumps(params or {})))
    conn.commit()


def log_finish(conn: sqlite3.Connection, run_id: str, status: str, *, received=0, added=0, updated=0,
               failed=0, raw_files: list[str] | None = None, error_log: str | None = None) -> None:
    conn.execute(
        """UPDATE ingestion_log SET end_time=?, status=?, records_received=?, records_added=?,
           records_updated=?, records_failed=?, raw_files=?, error_log=? WHERE run_id=?""",
        (utcnow(), status, received, added, updated, failed, json.dumps(raw_files or []), error_log, run_id))
    conn.commit()


def table_counts(conn: sqlite3.Connection) -> dict[str, int]:
    names = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    return {n: conn.execute(f"SELECT COUNT(*) FROM {n}").fetchone()[0] for n in names}
