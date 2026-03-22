import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

DEFAULT_DB_PATH = Path(__file__).parent.parent / "depchain.db"


def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(
        db_path,
        detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Path = DEFAULT_DB_PATH) -> None:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS analyses (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_url        TEXT NOT NULL,
            repo_path       TEXT NOT NULL,
            started_at      TIMESTAMP NOT NULL,
            completed_at    TIMESTAMP,
            status          TEXT NOT NULL DEFAULT 'running',
            ecosystem       TEXT NOT NULL,
            total_commits   INTEGER
        );

        CREATE TABLE IF NOT EXISTS commit_snapshots (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id     INTEGER NOT NULL REFERENCES analyses(id),
            commit_sha      TEXT NOT NULL,
            committed_at    TIMESTAMP NOT NULL,
            dep_file        TEXT NOT NULL,
            raw_content     TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS snapshot_dependencies (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id     INTEGER NOT NULL REFERENCES commit_snapshots(id),
            package_name    TEXT NOT NULL,
            version_raw     TEXT,
            version_pinned  TEXT,
            is_pinned       INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS vulnerabilities (
            cve_id          TEXT PRIMARY KEY,
            summary         TEXT,
            severity        TEXT,
            cvss_score      REAL,
            published_at    TIMESTAMP,
            osv_url         TEXT,
            raw_osv_json    TEXT
        );

        CREATE TABLE IF NOT EXISTS snapshot_vulns (
            snapshot_id     INTEGER NOT NULL REFERENCES commit_snapshots(id),
            dependency_id   INTEGER NOT NULL REFERENCES snapshot_dependencies(id),
            cve_id          TEXT NOT NULL REFERENCES vulnerabilities(cve_id),
            PRIMARY KEY (snapshot_id, cve_id)
        );

        CREATE TABLE IF NOT EXISTS exposure_windows (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id         INTEGER NOT NULL REFERENCES analyses(id),
            cve_id              TEXT NOT NULL REFERENCES vulnerabilities(cve_id),
            package_name        TEXT NOT NULL,
            introduced_at       TIMESTAMP NOT NULL,
            introduced_commit   TEXT NOT NULL,
            resolved_at         TIMESTAMP,
            resolved_commit     TEXT,
            duration_days       INTEGER,
            severity            TEXT,
            cvss_score          REAL,
            is_active           INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_snapshots_analysis
            ON commit_snapshots(analysis_id);

        CREATE INDEX IF NOT EXISTS idx_deps_snapshot
            ON snapshot_dependencies(snapshot_id);

        CREATE INDEX IF NOT EXISTS idx_windows_analysis
            ON exposure_windows(analysis_id);

        CREATE INDEX IF NOT EXISTS idx_windows_cve
            ON exposure_windows(cve_id);
    """)
    conn.commit()
    conn.close()
    print(f"[db] Database initialized at: {db_path}")


# ── Analysis ───────────────────────────────────────────────────────────────────

def insert_analysis(repo_url: str, repo_path: str,
                    ecosystem: str, db_path: Path = DEFAULT_DB_PATH) -> int:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO analyses (repo_url, repo_path, started_at, ecosystem)
        VALUES (?, ?, ?, ?)
    """, (repo_url, str(repo_path), datetime.utcnow(), ecosystem))
    analysis_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return analysis_id


def complete_analysis(analysis_id: int, total_commits: int,
                      db_path: Path = DEFAULT_DB_PATH) -> None:
    conn = get_connection(db_path)
    conn.execute("""
        UPDATE analyses
        SET status = 'complete', completed_at = ?, total_commits = ?
        WHERE id = ?
    """, (datetime.utcnow(), total_commits, analysis_id))
    conn.commit()
    conn.close()


def fail_analysis(analysis_id: int, db_path: Path = DEFAULT_DB_PATH) -> None:
    conn = get_connection(db_path)
    conn.execute("""
        UPDATE analyses SET status = 'failed', completed_at = ? WHERE id = ?
    """, (datetime.utcnow(), analysis_id))
    conn.commit()
    conn.close()


def get_all_analyses(db_path: Path = DEFAULT_DB_PATH) -> list:
    conn = get_connection(db_path)
    rows = conn.execute(
        "SELECT * FROM analyses ORDER BY started_at DESC"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_analysis(analysis_id: int, db_path: Path = DEFAULT_DB_PATH) -> Optional[dict]:
    conn = get_connection(db_path)
    row = conn.execute(
        "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


# ── Snapshots ──────────────────────────────────────────────────────────────────

def insert_snapshot(analysis_id: int, sha: str, committed_at: datetime,
                    dep_file: str, raw_content: str,
                    db_path: Path = DEFAULT_DB_PATH) -> int:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO commit_snapshots
            (analysis_id, commit_sha, committed_at, dep_file, raw_content)
        VALUES (?, ?, ?, ?, ?)
    """, (analysis_id, sha, committed_at, dep_file, raw_content))
    snapshot_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return snapshot_id


def get_snapshots(analysis_id: int, db_path: Path = DEFAULT_DB_PATH) -> list:
    conn = get_connection(db_path)
    rows = conn.execute("""
        SELECT * FROM commit_snapshots
        WHERE analysis_id = ?
        ORDER BY committed_at ASC
    """, (analysis_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ── Dependencies ───────────────────────────────────────────────────────────────

def insert_dependencies(snapshot_id: int, deps: list,
                        db_path: Path = DEFAULT_DB_PATH) -> list:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    ids = []
    for dep in deps:
        cursor.execute("""
            INSERT INTO snapshot_dependencies
                (snapshot_id, package_name, version_raw, version_pinned, is_pinned)
            VALUES (?, ?, ?, ?, ?)
        """, (
            snapshot_id,
            dep['package_name'],
            dep.get('version_raw'),
            dep.get('version_pinned'),
            1 if dep.get('is_pinned') else 0
        ))
        ids.append(cursor.lastrowid)
    conn.commit()
    conn.close()
    return ids


# ── Vulnerabilities ────────────────────────────────────────────────────────────

def vuln_exists(cve_id: str, db_path: Path = DEFAULT_DB_PATH) -> bool:
    conn = get_connection(db_path)
    row = conn.execute(
        "SELECT 1 FROM vulnerabilities WHERE cve_id = ?", (cve_id,)
    ).fetchone()
    conn.close()
    return row is not None


def insert_vulnerability(vuln: dict, db_path: Path = DEFAULT_DB_PATH) -> None:
    conn = get_connection(db_path)
    conn.execute("""
        INSERT OR IGNORE INTO vulnerabilities
            (cve_id, summary, severity, cvss_score, published_at, osv_url, raw_osv_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        vuln['cve_id'],
        vuln.get('summary'),
        vuln.get('severity'),
        vuln.get('cvss_score'),
        vuln.get('published_at'),
        vuln.get('osv_url'),
        vuln.get('raw_osv_json')
    ))
    conn.commit()
    conn.close()


# ── Exposure Windows ───────────────────────────────────────────────────────────

def insert_exposure_windows(windows: list,
                            db_path: Path = DEFAULT_DB_PATH) -> None:
    conn = get_connection(db_path)
    conn.executemany("""
        INSERT INTO exposure_windows
            (analysis_id, cve_id, package_name, introduced_at,
             introduced_commit, resolved_at, resolved_commit,
             duration_days, severity, cvss_score, is_active)
        VALUES
            (:analysis_id, :cve_id, :package_name, :introduced_at,
             :introduced_commit, :resolved_at, :resolved_commit,
             :duration_days, :severity, :cvss_score, :is_active)
    """, windows)
    conn.commit()
    conn.close()


def get_exposure_windows(analysis_id: int,
                         db_path: Path = DEFAULT_DB_PATH) -> list:
    severity_order = """CASE ew.severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH'     THEN 2
        WHEN 'MEDIUM'   THEN 3
        WHEN 'LOW'      THEN 4
        ELSE 5 END"""
    conn = get_connection(db_path)
    rows = conn.execute(f"""
        SELECT ew.*, v.summary, v.osv_url
        FROM exposure_windows ew
        JOIN vulnerabilities v ON ew.cve_id = v.cve_id
        WHERE ew.analysis_id = ?
        ORDER BY {severity_order}, ew.duration_days DESC
    """, (analysis_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]