"""
Tests for db.py
Run with: pytest tests/test_db.py -v
"""
import pytest
from pathlib import Path
from datetime import datetime
from depchain.db import (
    init_db, insert_analysis, complete_analysis, fail_analysis,
    get_analysis, get_all_analyses, insert_snapshot, get_snapshots,
    insert_dependencies, insert_vulnerability, vuln_exists,
    insert_exposure_windows, get_exposure_windows
)

TEST_DB = Path("test_depchain.db")


@pytest.fixture(autouse=True)
def fresh_db():
    init_db(TEST_DB)
    yield
    import gc
    gc.collect()  # force-close any lingering SQLite connections on Windows
    TEST_DB.unlink(missing_ok=True)


class TestAnalysis:
    def test_insert_and_retrieve(self):
        aid = insert_analysis("https://github.com/test/repo",
                              "/tmp/repo", "PyPI", TEST_DB)
        assert aid is not None
        assert aid > 0
        analysis = get_analysis(aid, TEST_DB)
        assert analysis is not None
        assert analysis["repo_url"] == "https://github.com/test/repo"
        assert analysis["status"] == "running"
        assert analysis["ecosystem"] == "PyPI"

    def test_complete_analysis(self):
        aid = insert_analysis("https://github.com/test/repo",
                              "/tmp/repo", "PyPI", TEST_DB)
        complete_analysis(aid, total_commits=42, db_path=TEST_DB)
        analysis = get_analysis(aid, TEST_DB)
        assert analysis["status"] == "complete"
        assert analysis["total_commits"] == 42
        assert analysis["completed_at"] is not None

    def test_fail_analysis(self):
        aid = insert_analysis("https://github.com/test/repo",
                              "/tmp/repo", "PyPI", TEST_DB)
        fail_analysis(aid, TEST_DB)
        assert get_analysis(aid, TEST_DB)["status"] == "failed"

    def test_get_all_analyses(self):
        insert_analysis("https://github.com/a/a", "/tmp/a", "PyPI", TEST_DB)
        insert_analysis("https://github.com/b/b", "/tmp/b", "npm", TEST_DB)
        assert len(get_all_analyses(TEST_DB)) == 2


class TestSnapshots:
    def test_insert_and_retrieve(self):
        aid = insert_analysis("https://github.com/test/repo",
                              "/tmp/repo", "PyPI", TEST_DB)
        sid = insert_snapshot(
            analysis_id=aid,
            sha="abc123",
            committed_at=datetime(2024, 1, 15),
            dep_file="requirements.txt",
            raw_content="requests==2.28.0\nflask==2.3.0",
            db_path=TEST_DB
        )
        assert sid == 1
        snapshots = get_snapshots(aid, TEST_DB)
        assert len(snapshots) == 1
        assert snapshots[0]["commit_sha"] == "abc123"

    def test_ordered_oldest_first(self):
        aid = insert_analysis("https://github.com/test/repo",
                              "/tmp/repo", "PyPI", TEST_DB)
        insert_snapshot(aid, "new_commit", datetime(2024, 3, 1),
                        "requirements.txt", "requests==2.30.0", TEST_DB)
        insert_snapshot(aid, "old_commit", datetime(2024, 1, 1),
                        "requirements.txt", "requests==2.28.0", TEST_DB)
        snapshots = get_snapshots(aid, TEST_DB)
        assert snapshots[0]["commit_sha"] == "old_commit"
        assert snapshots[1]["commit_sha"] == "new_commit"


class TestDependencies:
    def test_insert_dependencies(self):
        aid = insert_analysis("https://github.com/test/repo",
                              "/tmp/repo", "PyPI", TEST_DB)
        sid = insert_snapshot(aid, "abc123", datetime(2024, 1, 1),
                              "requirements.txt", "requests==2.28.0", TEST_DB)
        deps = [
            {"package_name": "requests", "version_raw": "==2.28.0",
             "version_pinned": "2.28.0", "is_pinned": True},
            {"package_name": "flask", "version_raw": ">=2.0",
             "version_pinned": None, "is_pinned": False},
        ]
        ids = insert_dependencies(sid, deps, TEST_DB)
        assert len(ids) == 2


class TestVulnerabilities:
    def test_cache_miss_then_hit(self):
        assert not vuln_exists("CVE-2023-1234", TEST_DB)
        insert_vulnerability({
            "cve_id": "CVE-2023-1234",
            "summary": "Test vulnerability",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "published_at": datetime(2023, 6, 1),
            "osv_url": "https://osv.dev/vulnerability/CVE-2023-1234",
            "raw_osv_json": "{}"
        }, TEST_DB)
        assert vuln_exists("CVE-2023-1234", TEST_DB)

    def test_duplicate_insert_is_safe(self):
        vuln = {
            "cve_id": "CVE-2023-1234", "summary": "Test",
            "severity": "HIGH", "cvss_score": 7.5,
            "published_at": None, "osv_url": "", "raw_osv_json": "{}"
        }
        insert_vulnerability(vuln, TEST_DB)
        insert_vulnerability(vuln, TEST_DB)  # must not raise
        assert vuln_exists("CVE-2023-1234", TEST_DB)


class TestExposureWindows:
    def test_insert_and_retrieve(self):
        aid = insert_analysis("https://github.com/test/repo",
                              "/tmp/repo", "PyPI", TEST_DB)
        insert_vulnerability({
            "cve_id": "CVE-2023-9999", "summary": "Critical bug",
            "severity": "CRITICAL", "cvss_score": 9.8,
            "published_at": None, "osv_url": "", "raw_osv_json": "{}"
        }, TEST_DB)
        windows = [{
            "analysis_id": aid,
            "cve_id": "CVE-2023-9999",
            "package_name": "requests",
            "introduced_at": datetime(2024, 1, 1),
            "introduced_commit": "abc123",
            "resolved_at": datetime(2024, 3, 1),
            "resolved_commit": "def456",
            "duration_days": 60,
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "is_active": 0
        }]
        insert_exposure_windows(windows, TEST_DB)
        results = get_exposure_windows(aid, TEST_DB)
        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2023-9999"
        assert results[0]["duration_days"] == 60
        assert results[0]["summary"] == "Critical bug"