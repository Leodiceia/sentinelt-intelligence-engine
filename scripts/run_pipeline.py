"""Sentinelt Intelligence Engine v0.1 — Step 02 pipeline runner.

Examples
  python scripts/run_pipeline.py --mode baseline               # 12 months + KEV backfill, KEV, EPSS, master, QC
  python scripts/run_pipeline.py --mode baseline --days 3      # smoke test (tiny window, KEV backfill skipped)
  python scripts/run_pipeline.py --mode incremental            # daily refresh (NVD lastModified, KEV, EPSS)
  python scripts/run_pipeline.py --mode rebuild                # no downloads: normalize pending raw, rebuild master, QC
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.config import settings  # noqa: E402
from engine.database import db  # noqa: E402
from engine.ingestion import cisa_kev as ing_kev, epss as ing_epss, nvd as ing_nvd  # noqa: E402
from engine.processing import build_master, normalize_epss, normalize_kev, normalize_nvd  # noqa: E402
from engine.quality import validate  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["baseline", "incremental", "rebuild"], default="rebuild")
    ap.add_argument("--months", type=int, default=settings.BASELINE_MONTHS)
    ap.add_argument("--days", type=int, help="override baseline window in days (smoke tests)")
    ap.add_argument("--skip-nvd", action="store_true")
    ap.add_argument("--skip-kev", action="store_true")
    ap.add_argument("--skip-epss", action="store_true")
    ap.add_argument("--no-kev-backfill", action="store_true", help="do not fetch NVD records for all KEV CVEs")
    ap.add_argument("--max-backfill-ids", type=int, default=300, help="cap for per-id backfill of KEV CVEs missing from NVD table")
    args = ap.parse_args()

    settings.ensure_dirs()
    conn = db.connect()
    db.init_db(conn)
    print(f"[engine] v{settings.ENGINE_VERSION} · DB {settings.DB_PATH} · NVD key: {'yes' if settings.NVD_API_KEY else 'NO (5 req/30s)'}")

    if args.mode == "baseline" and not args.skip_nvd:
        months = args.months
        if args.days:
            months = args.days / 30.4375
        print(f"[1/7] NVD baseline ({args.days or args.months} {'days' if args.days else 'months'})")
        ing_nvd.ingest_baseline(conn, months=months, include_kev_backfill=not (args.no_kev_backfill or args.days))
    elif args.mode == "incremental" and not args.skip_nvd:
        print("[1/7] NVD incremental")
        ing_nvd.ingest_incremental(conn)
    if args.mode != "rebuild" and not args.skip_kev:
        print("[2/7] CISA KEV snapshot")
        ing_kev.ingest_snapshot(conn)
    if args.mode != "rebuild" and not args.skip_epss:
        print("[3/7] EPSS snapshot")
        ing_epss.ingest_snapshot(conn)

    print("[4/7] Normalize NVD (pending runs)")
    normalize_nvd.load_pending_runs(conn)
    print("[5/7] Normalize KEV + EPSS (latest snapshots)")
    normalize_kev.load_latest(conn)
    # KEV backfill by id for KEV CVEs still missing in NVD table (population rule 3.1)
    missing = [r[0] for r in conn.execute("SELECT cve_id FROM cisa_kev WHERE cve_id NOT IN (SELECT cve_id FROM nvd_vulnerabilities)")]
    if missing and args.mode != "rebuild" and not args.skip_nvd and not args.days:
        ids = missing[: args.max_backfill_ids]
        print(f"      KEV backfill by id: {len(ids)} of {len(missing)} missing")
        rid = ing_nvd.ingest_by_ids(conn, ids, tag="kev")
        normalize_nvd.load_run(conn, rid)
    normalize_epss.load_latest(conn)

    print("[6/7] Build master")
    build_master.build(conn, months=args.months)
    print("[7/7] Quality control")
    checks = validate.run_checks(conn)
    path, ok = validate.write_report(conn, checks)
    for ch in checks:
        print(f"      {ch.id} {ch.status:4} {ch.name}: {ch.detail}")
    print(f"[engine] counts: {db.table_counts(conn)}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
