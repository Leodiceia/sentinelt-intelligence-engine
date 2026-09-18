"""Normalize RAW EPSS daily CSV -> epss_scores (cve_id, score_date) time series.

Only CVEs known to the engine (nvd_vulnerabilities ∪ cisa_kev) are kept in the DB; the full daily
file stays in RAW. If the engine is empty, everything is loaded (with a warning).
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import pandas as pd

from engine.config import settings


def read_epss_file(path: Path) -> tuple[pd.DataFrame, dict]:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        first = f.readline().strip()
    meta = {}
    if first.startswith("#"):
        for kv in first.lstrip("#").split(","):
            if ":" in kv:
                k, v = kv.split(":", 1)
                meta[k.strip()] = v.strip()
    df = pd.read_csv(path, comment="#", compression="gzip")
    df.columns = [c.strip().lower() for c in df.columns]
    return df[["cve", "epss", "percentile"]], meta


def load_run(conn, run_id: str) -> dict:
    row = conn.execute("SELECT raw_files, end_time FROM ingestion_log WHERE run_id=?", (run_id,)).fetchone()
    path = Path(json.loads(row[0])[0])
    df, meta = read_epss_file(path)
    score_date = (meta.get("score_date") or path.parent.name)[:10]
    model_version = meta.get("model_version")
    known = {r[0] for r in conn.execute("SELECT cve_id FROM nvd_vulnerabilities UNION SELECT cve_id FROM cisa_kev")}
    if known:
        df = df[df["cve"].isin(known)]
    else:
        print("  [epss-norm] WARNING: engine has no CVEs yet; loading full EPSS file")
    records = [(c, score_date, float(e), float(p), model_version, path.name, row[1])
               for c, e, p in df.itertuples(index=False)]
    conn.executemany("INSERT OR REPLACE INTO epss_scores (cve_id,score_date,epss,percentile,model_version,source_file,retrieved_at) "
                     "VALUES (?,?,?,?,?,?,?)", records)
    conn.execute("UPDATE ingestion_log SET records_added=? WHERE run_id=?", (len(records), run_id))
    conn.commit()
    out = settings.STD_DIR / "epss"
    out.mkdir(parents=True, exist_ok=True)
    df.assign(score_date=score_date, model_version=model_version).to_csv(out / f"epss_{score_date}.csv", index=False)
    print(f"  [epss-norm] {run_id}: {len(records)} scores for {score_date} (model {model_version})")
    return {"rows": len(records), "score_date": score_date, "model_version": model_version}


def load_latest(conn) -> dict | None:
    r = conn.execute("SELECT run_id FROM ingestion_log WHERE source='EPSS' AND status='success' "
                     "ORDER BY start_time DESC LIMIT 1").fetchone()
    return load_run(conn, r[0]) if r else None
