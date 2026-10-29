"""
SQLite data access for PhishGuard.

All queries use `?` placeholders (parameterised SQL), so user-supplied text can
never be interpreted as SQL. Connections are opened per operation and always
closed — this keeps the app reliable under the Flask development server and
under the automated tests.

The database path is read from `core.config.DB_PATH` at call time, which lets
the tests point the app at a temporary file without changing global state.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List, Optional

from core import config
from core.config import DB_URL_LENGTH

# Verdict values used by the filter dropdown.
VERDICTS = ("High Risk", "Suspicious", "Lower Risk", "Invalid URL")

# Risk filter -> SQL condition. The mapping is fixed in code, so the value that
# arrives from the URL is only ever used as a dictionary key.
RISK_FILTERS = {
    "all": None,
    "high": "verdict = 'High Risk'",
    "suspicious": "verdict = 'Suspicious'",
    "lower": "verdict IN ('Lower Risk', 'Invalid URL')",
}

MODES = tuple(RISK_FILTERS)


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(config.DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def _now_iso() -> str:
    """Current local time in ISO-8601, e.g. 2026-10-26T18:05:56+05:30."""
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def init_db(path: Optional[str] = None) -> None:
    """
    Create the `scans` table when missing and upgrade older schemas.

    Databases created by the original version of PhishGuard are migrated in
    place: new nullable columns are added and existing rows are left intact.
    """
    con = sqlite3.connect(path or config.DB_PATH)
    try:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                indicators TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
            """
        )
        existing = {row[1] for row in con.execute("PRAGMA table_info(scans)")}
        for column, column_type in (
            ("normalized_url", "TEXT"),
            ("findings_json", "TEXT"),
            ("hostname", "TEXT"),
        ):
            if column not in existing:
                con.execute(f"ALTER TABLE scans ADD COLUMN {column} {column_type}")

        con.execute("CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict)")
        con.commit()
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Writes
# ---------------------------------------------------------------------------

def save_scan(result) -> Optional[int]:
    """
    Persist one `AnalysisResult`.

    * Invalid submissions are not stored, so history only holds real URLs.
    * The same URL + score + timestamp within one second is treated as a
      double-submit and not inserted twice.
    Returns the row id, or None when nothing was written.
    """
    if result is None or not getattr(result, "is_valid", False):
        return None

    url = (result.normalized_url or result.input_url or "").strip()
    if not url:
        return None
    url = url[:DB_URL_LENGTH]

    timestamp = _now_iso()
    try:
        findings = json.dumps([f.as_dict() for f in result.findings], ensure_ascii=False)
        indicators = " | ".join(result.indicators)
        score = max(0, min(100, int(result.score)))
        hostname = result.hostname or None
    except (TypeError, ValueError, AttributeError):
        return None

    con = _connect()
    try:
        duplicate = con.execute(
            "SELECT id FROM scans WHERE url = ? AND score = ? AND scanned_at = ?",
            (url, score, timestamp),
        ).fetchone()
        if duplicate:
            return duplicate["id"]

        cursor = con.execute(
            """
            INSERT INTO scans
                (url, score, verdict, indicators, scanned_at,
                 normalized_url, findings_json, hostname)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (url, score, result.verdict, indicators, timestamp,
             url, findings, hostname),
        )
        con.commit()
        return cursor.lastrowid
    finally:
        con.close()


def clear_history() -> int:
    """Delete every scan row. Returns the number of rows removed."""
    con = _connect()
    try:
        deleted = con.execute("DELETE FROM scans").rowcount or 0
        # Reset AUTOINCREMENT so the next scan starts from id 1 again.
        con.execute("DELETE FROM sqlite_sequence WHERE name = 'scans'")
        con.commit()
        return int(deleted)
    finally:
        con.close()


def delete_scan(scan_id: int) -> bool:
    """Delete a single scan by id (parameterised)."""
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError):
        return False
    con = _connect()
    try:
        deleted = con.execute("DELETE FROM scans WHERE id = ?", (scan_id,)).rowcount
        con.commit()
        return bool(deleted)
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def get_recent_scans(limit: int = 5) -> List[sqlite3.Row]:
    con = _connect()
    try:
        return con.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (int(limit),)
        ).fetchall()
    finally:
        con.close()


def get_history(search: str = "", mode: str = "all", limit: int = 200) -> List[sqlite3.Row]:
    """
    Return filtered scan history.

    `search` is matched with LIKE using a bound parameter. Wildcards are
    escaped so a search for "%" does not match every row.
    """
    clauses: List[str] = []
    params: List[object] = []

    search = (search or "").strip()[:config.MAX_QUERY_LENGTH]
    if search:
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append("(url LIKE ? ESCAPE '\\' OR hostname LIKE ? ESCAPE '\\')")
        params.extend([f"%{escaped}%", f"%{escaped}%"])

    risk_clause = RISK_FILTERS.get(mode)
    if risk_clause:
        clauses.append(risk_clause)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    con = _connect()
    try:
        return con.execute(
            f"SELECT * FROM scans {where} ORDER BY id DESC LIMIT ?",
            (*params, int(limit)),
        ).fetchall()
    finally:
        con.close()


def get_stats() -> Dict[str, int]:
    """Counts used by the dashboard statistic cards."""
    con = _connect()
    try:
        row = con.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN verdict = 'High Risk' THEN 1 ELSE 0 END) AS high,
                SUM(CASE WHEN verdict = 'Suspicious' THEN 1 ELSE 0 END) AS suspicious,
                SUM(CASE WHEN verdict IN ('Lower Risk', 'Invalid URL') THEN 1 ELSE 0 END) AS lower,
                AVG(score) AS average_score,
                MAX(score) AS top_score
            FROM scans
            """
        ).fetchone()
    finally:
        con.close()

    # SUM() returns NULL on an empty table, hence the `or 0` guards.
    return {
        "total": row["total"] or 0,
        "high": row["high"] or 0,
        "suspicious": row["suspicious"] or 0,
        "lower": row["lower"] or 0,
        "average_score": int(round(row["average_score"])) if row["average_score"] else 0,
        "top_score": row["top_score"] or 0,
    }


def count_scans() -> int:
    con = _connect()
    try:
        return con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

def parse_stored_time(value: str) -> Optional[datetime]:
    """Parse an ISO timestamp, returning None when the value is malformed."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def format_time(value: str, fmt: str = "%d %b %Y, %I:%M %p") -> str:
    """Human-friendly local timestamp for templates."""
    dt = parse_stored_time(value)
    if dt is None:
        return value or "—"
    if dt.tzinfo is not None:
        dt = dt.astimezone()
    return dt.strftime(fmt)


def load_findings(row, default_indicators: str = "") -> List[dict]:
    """
    Return stored findings as dicts for the templates.

    Rows written by the original app only contain a pipe-separated
    `indicators` string, so they are converted into simple informational
    findings instead of being dropped.
    """
    raw = row["findings_json"] if "findings_json" in row.keys() else None
    if raw:
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return [d for d in data if isinstance(d, dict)]
        except (TypeError, ValueError):
            pass

    indicators = (row["indicators"] if "indicators" in row.keys() else default_indicators) or ""
    legacy = []
    for text in str(indicators).split("|"):
        text = text.strip()
        if text:
            legacy.append({
                "code": "legacy",
                "title": text,
                "detail": "Recorded by an earlier version of PhishGuard.",
                "points": 0,
                "severity": "info",
            })
    return legacy


def risk_slug(verdict: str) -> str:
    """Map a stored verdict to the CSS class used by the UI."""
    return {
        "High Risk": "high",
        "Suspicious": "suspicious",
        "Lower Risk": "low",
        "Invalid URL": "invalid",
    }.get(verdict, "low")
