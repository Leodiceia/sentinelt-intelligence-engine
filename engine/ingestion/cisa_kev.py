"""SOURCE 02 — CISA Known Exploited Vulnerabilities catalog (JSON feed). Full snapshot every run."""
from __future__ import annotations

from datetime import datetime, timezone

from engine.config import settings
from engine.database import db
from engine.ingestion._http import get, write_json_gz


def ingest_snapshot(conn) -> str:
    run_id = db.new_run_id("kev")
    db.log_start(conn, run_id, "CISA_KEV", "snapshot", {"url": settings.KEV_URL})
    try:
        payload = get(settings.KEV_URL).json()
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        path = write_json_gz(payload, settings.RAW_DIR / "cisa_kev" / day / f"{run_id}_kev.json.gz")
        n = len(payload.get("vulnerabilities", []))
        print(f"  [kev] catalogVersion={payload.get('catalogVersion')} count={n}")
        db.log_finish(conn, run_id, "success", received=n, raw_files=[str(path)])
    except Exception as exc:  # noqa: BLE001
        db.log_finish(conn, run_id, "failed", error_log=repr(exc))
        raise
    return run_id
