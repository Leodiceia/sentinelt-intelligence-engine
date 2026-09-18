"""SOURCE 01 — NVD API 2.0 acquisition.

Rules implemented (see review 2026-09-18, sections 3.1 and 3.7):
  * pubStartDate/pubEndDate windows of at most 120 days, paginated (resultsPerPage <= 2000).
  * Rate limit respected: 5 req/30s without key, 50 req/30s with key.
  * Baseline = last BASELINE_MONTHS by published date; plus KEV backfill via `hasKev` flag so that
    every KEV CVE (even old ones) exists in the master table.
  * Incremental = lastModStartDate/lastModEndDate.
  * Every page is written unmodified to RAW as gzip JSON and referenced in ingestion_log.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

from engine.config import settings
from engine.database import db
from engine.ingestion._http import get, write_json_gz

NVD_TS = "%Y-%m-%dT%H:%M:%S.000"


def _fmt(dt: datetime) -> str:
    return dt.strftime(NVD_TS)


def _headers() -> dict:
    return {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}


def _raw_dir(run_id: str) -> Path:
    return settings.RAW_DIR / "nvd" / datetime.now(timezone.utc).strftime("%Y-%m-%d") / run_id


def windows(start: datetime, end: datetime, max_days: int = settings.NVD_MAX_WINDOW_DAYS):
    """Yield (a, b) pairs covering [start, end] with each span <= max_days."""
    a = start
    while a < end:
        b = min(a + timedelta(days=max_days), end)
        yield a, b
        a = b + timedelta(seconds=1)


def fetch_pages(base_params: dict, flags: list[str], raw_dir: Path, tag: str) -> tuple[list[Path], int]:
    """Paginate one query. `flags` are value-less NVD params (e.g. hasKev)."""
    files: list[Path] = []
    start_index, total, received = 0, None, 0
    page = 0
    while total is None or start_index < total:
        params = dict(base_params, resultsPerPage=settings.NVD_RESULTS_PER_PAGE, startIndex=start_index)
        url = settings.NVD_BASE_URL + "?" + urlencode(params) + "".join(f"&{f}" for f in flags)
        r = get(url, headers=_headers())
        payload = r.json()
        total = int(payload.get("totalResults", 0))
        n = len(payload.get("vulnerabilities", []))
        received += n
        page += 1
        f = write_json_gz(payload, raw_dir / f"{tag}_p{page:03d}.json.gz")
        files.append(f)
        print(f"  [nvd] {tag} page {page}: {n} records (startIndex={start_index}, total={total})")
        start_index += settings.NVD_RESULTS_PER_PAGE
        if start_index < total:
            time.sleep(settings.NVD_SLEEP_SECONDS)
    return files, received


def ingest_baseline(conn, months: int = settings.BASELINE_MONTHS, include_kev_backfill: bool = True) -> str:
    """Download last `months` of CVEs by published date + all KEV-listed CVEs."""
    run_id = db.new_run_id("nvd")
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(days=int(months * 30.4375))
    params_log = {"pubStartDate": _fmt(start), "pubEndDate": _fmt(end), "kev_backfill": include_kev_backfill}
    db.log_start(conn, run_id, "NVD", "baseline", params_log)
    raw_dir = _raw_dir(run_id)
    files: list[Path] = []
    received = 0
    try:
        for i, (a, b) in enumerate(windows(start, end), 1):
            fl, n = fetch_pages({"pubStartDate": _fmt(a), "pubEndDate": _fmt(b)}, [], raw_dir, f"pub_w{i:02d}")
            files += fl
            received += n
            time.sleep(settings.NVD_SLEEP_SECONDS)
        if include_kev_backfill:
            fl, n = fetch_pages({}, ["hasKev"], raw_dir, "haskev")
            files += fl
            received += n
        db.log_finish(conn, run_id, "success", received=received, raw_files=[str(p) for p in files])
    except Exception as exc:  # noqa: BLE001
        db.log_finish(conn, run_id, "failed", received=received, raw_files=[str(p) for p in files],
                      error_log=repr(exc))
        raise
    return run_id


def ingest_incremental(conn, since: datetime | None = None) -> str:
    """Download CVEs modified since `since` (default: last successful NVD run end_time, else 2 days)."""
    run_id = db.new_run_id("nvd")
    end = datetime.now(timezone.utc).replace(microsecond=0)
    if since is None:
        row = conn.execute("SELECT end_time FROM ingestion_log WHERE source='NVD' AND status='success' "
                           "ORDER BY end_time DESC LIMIT 1").fetchone()
        since = datetime.strptime(row[0], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) if row \
            else end - timedelta(days=2)
    db.log_start(conn, run_id, "NVD", "incremental", {"lastModStartDate": _fmt(since), "lastModEndDate": _fmt(end)})
    raw_dir = _raw_dir(run_id)
    files, received = [], 0
    try:
        for i, (a, b) in enumerate(windows(since, end), 1):
            fl, n = fetch_pages({"lastModStartDate": _fmt(a), "lastModEndDate": _fmt(b)}, [], raw_dir, f"mod_w{i:02d}")
            files += fl
            received += n
        db.log_finish(conn, run_id, "success", received=received, raw_files=[str(p) for p in files])
    except Exception as exc:  # noqa: BLE001
        db.log_finish(conn, run_id, "failed", received=received, raw_files=[str(p) for p in files], error_log=repr(exc))
        raise
    return run_id


def ingest_by_ids(conn, cve_ids: list[str], tag: str = "byid") -> str:
    """Fetch specific CVEs (e.g. KEV entries missing from master)."""
    run_id = db.new_run_id("nvd")
    db.log_start(conn, run_id, "NVD", "by_id", {"count": len(cve_ids)})
    raw_dir = _raw_dir(run_id)
    files, received, failed = [], 0, 0
    for i, cid in enumerate(cve_ids, 1):
        try:
            fl, n = fetch_pages({"cveId": cid}, [], raw_dir, f"{tag}_{cid}")
            files += fl
            received += n
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  [nvd] failed {cid}: {exc}")
        time.sleep(settings.NVD_SLEEP_SECONDS)
    db.log_finish(conn, run_id, "success" if failed == 0 else "partial", received=received, failed=failed,
                  raw_files=[str(p) for p in files])
    return run_id
