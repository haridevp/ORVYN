"""Persistent Storage Engine for ORVYN.

Stores all scan metadata, scanner progress, raw and correlated findings,
and telemetry logs into SQLite so results persist across server reloads
and browser sessions.
"""

import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any, Optional

logger = logging.getLogger("orvyn.storage")

DEFAULT_DB_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_DB_PATH = DEFAULT_DB_DIR / "orvyn.db"


class ScanStorage:
    def __init__(self, db_path: Optional[str] = None):
        if db_path:
            self.db_path = Path(db_path)
        else:
            self.db_path = Path(os.environ.get("ORVYN_DB_PATH", str(DEFAULT_DB_PATH)))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        """Create necessary tables if they do not exist."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    profile TEXT NOT NULL,
                    template_id TEXT,
                    template_name TEXT,
                    overall_status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    requested_by TEXT DEFAULT 'admin',
                    in_scope TEXT,
                    out_of_scope TEXT,
                    scanner_progress TEXT,
                    severity_distribution TEXT,
                    findings_count INTEGER DEFAULT 0,
                    correlated_count INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS scan_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    target TEXT NOT NULL,
                    vulnerability TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence INTEGER DEFAULT 50,
                    description TEXT,
                    evidence TEXT,
                    reference TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS scan_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    log_text TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON scan_findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_logs_scan_id ON scan_logs(scan_id);
            """)
            conn.commit()

    def save_job(self, job: Any) -> None:
        """Upsert a ScanJob into the persistent SQLite database."""
        try:
            progress_dict = {}
            for tool, p in job.scanner_progress.items():
                tool_key = tool.value if hasattr(tool, "value") else str(tool)
                progress_dict[tool_key] = {
                    "tool": tool_key,
                    "status": p.status.value if hasattr(p.status, "value") else str(p.status),
                    "started_at": p.started_at,
                    "finished_at": p.finished_at,
                    "findings_count": p.findings_count,
                    "error": p.error,
                    "simulated": getattr(p, "simulated", False),
                }

            status_val = getattr(job, "overall_status", "completed")
            status_str = status_val.value if hasattr(status_val, "value") else str(status_val)

            if hasattr(job, "get_correlated_findings") and callable(job.get_correlated_findings):
                correlated = job.get_correlated_findings()
            else:
                correlated = getattr(job, "_correlated_cache", None) or []
            corr_count = len(correlated) if correlated else 0

            # Compute severity distribution
            sev_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in job.findings:
                s = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                if s in sev_dist:
                    sev_dist[s] += 1

            requested_by = getattr(job, "requested_by", "admin") or "admin"

            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO scans (
                        scan_id, target, profile, template_id, template_name,
                        overall_status, created_at, updated_at, requested_by,
                        in_scope, out_of_scope, scanner_progress, severity_distribution,
                        findings_count, correlated_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_id) DO UPDATE SET
                        target=excluded.target,
                        profile=excluded.profile,
                        template_id=excluded.template_id,
                        template_name=excluded.template_name,
                        overall_status=excluded.overall_status,
                        updated_at=excluded.updated_at,
                        scanner_progress=excluded.scanner_progress,
                        severity_distribution=excluded.severity_distribution,
                        findings_count=excluded.findings_count,
                        correlated_count=excluded.correlated_count;
                """, (
                    job.scan_id,
                    job.target,
                    job.profile,
                    getattr(job, "template_id", None),
                    getattr(job, "template_name", None),
                    status_str,
                    job.created_at,
                    job.updated_at,
                    requested_by,
                    json.dumps(job.in_scope),
                    json.dumps(job.out_of_scope),
                    json.dumps(progress_dict),
                    json.dumps(sev_dist),
                    len(job.findings),
                    corr_count,
                ))

                # Refresh findings
                conn.execute("DELETE FROM scan_findings WHERE scan_id = ?", (job.scan_id,))
                for f in job.findings:
                    tool_val = f.tool.value if hasattr(f.tool, "value") else str(f.tool)
                    sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                    conn.execute("""
                        INSERT INTO scan_findings (
                            scan_id, tool, target, vulnerability, severity, confidence, description, evidence, reference
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        job.scan_id,
                        tool_val,
                        f.target,
                        f.vulnerability,
                        sev_val,
                        getattr(f, "confidence", 50),
                        f.description,
                        f.evidence,
                        getattr(f, "reference", None),
                    ))

                # Refresh logs
                conn.execute("DELETE FROM scan_logs WHERE scan_id = ?", (job.scan_id,))
                for log_line in job.logs:
                    conn.execute("INSERT INTO scan_logs (scan_id, log_text) VALUES (?, ?)", (job.scan_id, log_line))

                conn.commit()
        except Exception as e:
            logger.error(f"Error persisting scan {getattr(job, 'scan_id', 'unknown')}: {e}", exc_info=True)

    def list_scans(self, limit: int = 50, requested_by: Optional[str] = None) -> list[dict]:
        """Return summary list of all stored scans sorted newest first."""
        with self._get_connection() as conn:
            if requested_by:
                cursor = conn.execute(
                    "SELECT * FROM scans WHERE requested_by = ? ORDER BY created_at DESC LIMIT ?",
                    (requested_by, limit),
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append({
                    "scan_id": row["scan_id"],
                    "target": row["target"],
                    "profile": row["profile"],
                    "template_id": row["template_id"],
                    "template_name": row["template_name"],
                    "overall_status": row["overall_status"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                    "requested_by": row["requested_by"],
                    "findings_count": row["findings_count"],
                    "correlated_count": row["correlated_count"],
                    "severity_distribution": json.loads(row["severity_distribution"] or "{}"),
                    "scanner_progress": json.loads(row["scanner_progress"] or "{}"),
                })
            return results

    def get_scan(self, scan_id: str) -> Optional[dict]:
        """Fetch a single scan with findings and logs."""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None

            findings_cur = conn.execute(
                "SELECT * FROM scan_findings WHERE scan_id = ? ORDER BY id ASC",
                (scan_id,),
            )
            findings = [dict(f) for f in findings_cur.fetchall()]

            logs_cur = conn.execute(
                "SELECT log_text FROM scan_logs WHERE scan_id = ? ORDER BY id ASC",
                (scan_id,),
            )
            logs = [l["log_text"] for l in logs_cur.fetchall()]

            return {
                "scan_id": row["scan_id"],
                "target": row["target"],
                "profile": row["profile"],
                "template_id": row["template_id"],
                "template_name": row["template_name"],
                "overall_status": row["overall_status"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "requested_by": row["requested_by"],
                "in_scope": json.loads(row["in_scope"] or "[]"),
                "out_of_scope": json.loads(row["out_of_scope"] or "[]"),
                "scanner_progress": json.loads(row["scanner_progress"] or "{}"),
                "severity_distribution": json.loads(row["severity_distribution"] or "{}"),
                "findings_count": row["findings_count"],
                "correlated_count": row["correlated_count"],
                "findings": findings,
                "logs": logs,
            }

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all associated findings/logs."""
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            conn.commit()
            return cur.rowcount > 0


scan_storage = ScanStorage()
