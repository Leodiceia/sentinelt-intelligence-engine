"""Build master_vulnerabilities = NVD(baseline window) ∪ NVD(KEV-listed), joined with KEV, latest EPSS,
products (primary vendor/product), weaknesses and selected vendor advisories. Records dataset_version.
"""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone

import pandas as pd

from engine.config import settings
from engine.database import db

MASTER_SQL = """
WITH latest_epss AS (
    SELECT e.cve_id, e.epss, e.percentile, e.score_date, e.source_file
    FROM epss_scores e
    JOIN (SELECT cve_id, MAX(score_date) AS d FROM epss_scores GROUP BY cve_id) m
      ON m.cve_id = e.cve_id AND m.d = e.score_date
),
prod_counts AS (
    SELECT cve_id, vendor, product, COUNT(*) AS n
    FROM cve_products WHERE vulnerable = 1 AND vendor IS NOT NULL
    GROUP BY cve_id, vendor, product
),
prod_top AS (
    SELECT cve_id, vendor, product FROM (
        SELECT cve_id, vendor, product,
               ROW_NUMBER() OVER (PARTITION BY cve_id ORDER BY n DESC, vendor, product) AS rn
        FROM prod_counts) WHERE rn = 1
),
prod_n AS (SELECT cve_id, COUNT(*) AS affected_product_count FROM prod_counts GROUP BY cve_id),
cwes AS (SELECT cve_id, GROUP_CONCAT(DISTINCT cwe_id) AS cwe_ids FROM cve_weaknesses GROUP BY cve_id),
adv AS (
    SELECT cve_id, patch_available, fixed_version, mitigation_available, advisory_url FROM (
        SELECT *, ROW_NUMBER() OVER (PARTITION BY cve_id ORDER BY retrieved_at DESC) AS rn FROM vendor_advisories)
    WHERE rn = 1
)
SELECT
    n.cve_id,
    CASE WHEN n.published_date >= :baseline_start THEN 1 ELSE 0 END AS in_baseline_window,
    n.description,
    COALESCE(k.vendor_project, pt.vendor)  AS primary_vendor,
    COALESCE(k.product, pt.product)        AS primary_product,
    COALESCE(pn.affected_product_count, 0) AS affected_product_count,
    c.cwe_ids,
    n.vuln_status,
    n.published_date, n.modified_date,
    k.date_added AS kev_date_added, k.due_date AS kev_due_date,
    CASE WHEN k.date_added IS NOT NULL
         THEN CAST(julianday(k.date_added) - julianday(substr(n.published_date,1,10)) AS INTEGER) END AS days_published_to_kev,
    n.cvss_version, n.cvss_source, n.cvss_score, n.cvss_severity,
    n.attack_vector, n.attack_complexity, n.privileges_required, n.user_interaction,
    n.confidentiality_impact, n.integrity_impact, n.availability_impact,
    CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END AS kev_status,
    k.vulnerability_name AS kev_vulnerability_name,
    k.required_action    AS kev_required_action,
    k.known_ransomware_use,
    le.epss AS epss_score_latest, le.percentile AS epss_percentile_latest, le.score_date AS epss_date,
    n.public_exploit_reference, n.exploit_reference_count,
    n.patch_reference_available,
    a.patch_available, a.fixed_version, a.mitigation_available, a.advisory_url AS vendor_advisory_url,
    n.source_url AS nvd_source_url,
    k.source_url AS cisa_source_url,
    le.source_file AS epss_source_file,
    n.retrieved_at,
    :dataset_version AS dataset_version,
    :built_at AS built_at
FROM nvd_vulnerabilities n
LEFT JOIN cisa_kev   k  ON k.cve_id  = n.cve_id
LEFT JOIN latest_epss le ON le.cve_id = n.cve_id
LEFT JOIN prod_top   pt ON pt.cve_id = n.cve_id
LEFT JOIN prod_n     pn ON pn.cve_id = n.cve_id
LEFT JOIN cwes       c  ON c.cve_id  = n.cve_id
LEFT JOIN adv        a  ON a.cve_id  = n.cve_id
"""


def git_commit() -> str | None:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=settings.REPO_ROOT,
                                       stderr=subprocess.DEVNULL).decode().strip()
    except Exception:  # noqa: BLE001
        return None


def build(conn, months: int = settings.BASELINE_MONTHS, notes: str | None = None) -> dict:
    built_at = db.utcnow()
    baseline_start = (datetime.now(timezone.utc) - timedelta(days=int(months * 30.4375))).strftime("%Y-%m-%dT%H:%M:%S")
    params = {"baseline_start": baseline_start, "dataset_version": settings.DATASET_VERSION, "built_at": built_at}
    df = pd.read_sql_query(MASTER_SQL, conn, params=params)
    conn.execute("DELETE FROM master_vulnerabilities")
    df.to_sql("master_vulnerabilities", conn, if_exists="append", index=False)
    counts = db.table_counts(conn)
    conn.execute("INSERT INTO dataset_version (version, created_at, git_commit, row_counts, notes) VALUES (?,?,?,?,?)",
                 (settings.DATASET_VERSION, built_at, git_commit(), json.dumps(counts), notes))
    conn.commit()
    settings.MASTER_DIR.mkdir(parents=True, exist_ok=True)
    out = settings.MASTER_DIR / f"master_vulnerabilities_{built_at[:10]}.csv"
    df.to_csv(out, index=False)
    summary = {"rows": len(df), "in_window": int(df["in_baseline_window"].sum()), "kev": int(df["kev_status"].sum()),
               "with_epss": int(df["epss_score_latest"].notna().sum()), "with_cvss": int(df["cvss_score"].notna().sum()),
               "csv": str(out)}
    print(f"  [master] {summary}")
    return summary
