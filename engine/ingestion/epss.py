"""SOURCE 03 — FIRST EPSS daily bulk CSV (gzip). Stored as a dated snapshot: EPSS is a time series."""
from __future__ import annotations

from datetime import datetime, timezone

from engine.config import settings
from engine.database import db
from engine.ingestion._http import get, write_bytes


def ingest_snapshot(conn, score_date: str | None = None) -> str:
    """score_date: YYYY-MM-DD for a historical file; None = current."""
    run_id = db.new_run_id("epss")
    url = settings.EPSS_DATED_URL.format(date=score_date) if score_date else settings.EPSS_CURRENT_URL
    db.log_start(conn, run_id, "EPSS", "snapshot", {"url": url})
    try:
        r = get(url, stream=True)
        data = r.content
        day = score_date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        path = write_bytes(data, settings.RAW_DIR / "epss" / day / f"{run_id}_epss_scores.csv.gz")
        print(f"  [epss] saved {len(data)/1e6:.1f} MB -> {path.name}")
        db.log_finish(conn, run_id, "success", received=len(data), raw_files=[str(path)])
    except Exception as exc:  # noqa: BLE001
        db.log_finish(conn, run_id, "failed", error_log=repr(exc))
        raise
    return run_id
