"""Normalize RAW CISA KEV snapshot -> cisa_kev (full replace; the catalog is a snapshot).

Rule: knownRansomwareCampaignUse "Known" -> 1 ; "Unknown" -> NULL. CISA never asserts "no".
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from engine.config import settings
from engine.ingestion._http import read_json_gz


def map_ransomware(value: str | None) -> int | None:
    return 1 if (value or "").strip().lower() == "known" else None


def normalize_entry(v: dict, meta: dict, retrieved_at: str, run_id: str) -> dict:
    return {
        "cve_id": v.get("cveID"),
        "vendor_project": v.get("vendorProject"),
        "product": v.get("product"),
        "vulnerability_name": v.get("vulnerabilityName"),
        "date_added": v.get("dateAdded"),
        "short_description": v.get("shortDescription"),
        "required_action": v.get("requiredAction"),
        "due_date": v.get("dueDate"),
        "known_ransomware_campaign_use_raw": v.get("knownRansomwareCampaignUse"),
        "known_ransomware_use": map_ransomware(v.get("knownRansomwareCampaignUse")),
        "notes": v.get("notes"),
        "cwes": json.dumps(v.get("cwes") or []),
        "catalog_version": meta.get("catalogVersion"),
        "date_released": meta.get("dateReleased"),
        "source_url": settings.KEV_CATALOG_PAGE,
        "retrieved_at": retrieved_at,
        "run_id": run_id,
    }


def load_run(conn, run_id: str) -> dict:
    row = conn.execute("SELECT raw_files, end_time FROM ingestion_log WHERE run_id=?", (run_id,)).fetchone()
    files = [Path(p) for p in json.loads(row[0] or "[]")]
    payload = read_json_gz(files[0])
    meta = {k: payload.get(k) for k in ("catalogVersion", "dateReleased", "count", "title")}
    rows = [normalize_entry(v, meta, row[1], run_id) for v in payload.get("vulnerabilities", [])]
    rows = [r for r in rows if r["cve_id"]]
    cols = list(rows[0].keys())
    conn.execute("DELETE FROM cisa_kev")
    conn.executemany(f"INSERT OR REPLACE INTO cisa_kev ({','.join(cols)}) VALUES ({','.join('?'*len(cols))})",
                     [[r[c] for c in cols] for r in rows])
    conn.execute("UPDATE ingestion_log SET records_added=? WHERE run_id=?", (len(rows), run_id))
    conn.commit()
    out = settings.STD_DIR / "cisa_kev"
    out.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(out / f"cisa_kev_{run_id}.csv", index=False)
    print(f"  [kev-norm] {run_id}: {len(rows)} entries, catalogVersion={meta.get('catalogVersion')}")
    return {"rows": len(rows), "catalog_version": meta.get("catalogVersion")}


def load_latest(conn) -> dict | None:
    r = conn.execute("SELECT run_id FROM ingestion_log WHERE source='CISA_KEV' AND status='success' "
                     "ORDER BY start_time DESC LIMIT 1").fetchone()
    return load_run(conn, r[0]) if r else None
