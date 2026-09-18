"""Data Quality Control — 10 original checks (Step 02 §18) + 5 added by the 2026-09-18 review.
Writes quality/qc_report_<date>.md. Statuses: PASS | WARN | FAIL | INFO.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from engine.config import settings
from engine.database import db

CVE_RE = r"^CVE-[0-9]{4}-[0-9]{4,}$"


@dataclass
class Check:
    id: str
    name: str
    status: str
    detail: str


def _one(conn, sql, params=()):
    return conn.execute(sql, params).fetchone()[0]


def run_checks(conn) -> list[Check]:
    c: list[Check] = []
    total = _one(conn, "SELECT COUNT(*) FROM master_vulnerabilities")
    if total == 0:
        return [Check("00", "Master populated", "FAIL", "master_vulnerabilities is empty")]

    # 01 CVE format
    bad = [r[0] for r in conn.execute("SELECT cve_id FROM master_vulnerabilities") if not re.match(CVE_RE, r[0])]
    c.append(Check("01", "CVE ID format", "PASS" if not bad else "FAIL", f"{len(bad)} invalid ids {bad[:5]}"))
    # 02 unique
    dup = _one(conn, "SELECT COUNT(*) - COUNT(DISTINCT cve_id) FROM master_vulnerabilities")
    c.append(Check("02", "Unique CVE IDs", "PASS" if dup == 0 else "FAIL", f"{dup} duplicates"))
    # 03 dates
    bad_dates = _one(conn, "SELECT COUNT(*) FROM master_vulnerabilities WHERE published_date IS NULL "
                           "OR modified_date < published_date OR (kev_due_date IS NOT NULL AND kev_due_date < kev_date_added)")
    c.append(Check("03", "Dates valid and ordered", "PASS" if bad_dates == 0 else "FAIL", f"{bad_dates} rows with invalid/unordered dates"))
    # 04 CVSS range
    n = _one(conn, "SELECT COUNT(*) FROM master_vulnerabilities WHERE cvss_score IS NOT NULL AND (cvss_score < 0 OR cvss_score > 10)")
    c.append(Check("04", "CVSS in 0-10 or NULL", "PASS" if n == 0 else "FAIL", f"{n} out of range"))
    # 05 EPSS range
    n = _one(conn, "SELECT COUNT(*) FROM epss_scores WHERE epss < 0 OR epss > 1")
    c.append(Check("05", "EPSS in 0-1 or NULL", "PASS" if n == 0 else "FAIL", f"{n} out of range"))
    # 06 percentile
    n = _one(conn, "SELECT COUNT(*) FROM epss_scores WHERE percentile < 0 OR percentile > 1")
    c.append(Check("06", "EPSS percentile in 0-1 or NULL", "PASS" if n == 0 else "FAIL", f"{n} out of range"))
    # 07 KEV mapping (population rule: ALL KEV CVEs must exist in master)
    kev_total = _one(conn, "SELECT COUNT(*) FROM cisa_kev")
    kev_missing = [r[0] for r in conn.execute("SELECT cve_id FROM cisa_kev WHERE cve_id NOT IN (SELECT cve_id FROM master_vulnerabilities)")]
    c.append(Check("07", "KEV CVEs map to master", "PASS" if not kev_missing else ("WARN" if len(kev_missing) < 0.02 * max(kev_total, 1) else "FAIL"),
                   f"{len(kev_missing)}/{kev_total} KEV CVEs missing from master {kev_missing[:10]}"))
    # 08 EPSS mapping
    with_epss = _one(conn, "SELECT COUNT(*) FROM master_vulnerabilities WHERE epss_score_latest IS NOT NULL")
    pct = 100 * with_epss / total
    c.append(Check("08", "EPSS coverage of master", "PASS" if pct >= 80 else "WARN", f"{with_epss}/{total} ({pct:.1f}%) have an EPSS score"))
    # 09 provenance
    n = _one(conn, "SELECT COUNT(*) FROM master_vulnerabilities WHERE retrieved_at IS NULL OR nvd_source_url IS NULL OR dataset_version IS NULL")
    c.append(Check("09", "Provenance present", "PASS" if n == 0 else "FAIL", f"{n} rows without source/retrieved_at/version"))
    # 10 missing data report
    cols = ["cvss_score", "primary_vendor", "cwe_ids", "epss_score_latest", "description"]
    parts = []
    for col in cols:
        nn = _one(conn, f"SELECT COUNT(*) FROM master_vulnerabilities WHERE {col} IS NULL")
        parts.append(f"{col}={100*nn/total:.1f}%")
    c.append(Check("10", "Missingness identified (not discarded)", "INFO", "NULL rates: " + ", ".join(parts)))
    # 11 freshness
    latest = _one(conn, "SELECT MAX(retrieved_at) FROM master_vulnerabilities")
    age_h = (datetime.now(timezone.utc) - datetime.strptime(latest, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)).total_seconds() / 3600
    c.append(Check("11", "Freshness < 48h", "PASS" if age_h < 48 else "WARN", f"latest retrieval {age_h:.1f}h ago"))
    # 12 row delta vs previous dataset_version
    rows = conn.execute("SELECT row_counts FROM dataset_version ORDER BY created_at DESC LIMIT 2").fetchall()
    if len(rows) == 2:
        cur = json.loads(rows[0][0]).get("master_vulnerabilities", 0)
        prev = json.loads(rows[1][0]).get("master_vulnerabilities", 0)
        delta = (cur - prev) / prev * 100 if prev else 0
        c.append(Check("12", "Row delta vs previous build", "PASS" if abs(delta) <= 50 else "WARN", f"{prev} -> {cur} ({delta:+.1f}%)"))
    else:
        c.append(Check("12", "Row delta vs previous build", "INFO", "first build; no previous version"))
    # 13 CVSS / CPE null rate (NVD enrichment backlog indicator)
    cvss_null = 100 * _one(conn, "SELECT COUNT(*) FROM master_vulnerabilities WHERE cvss_score IS NULL") / total
    cpe_null = 100 * _one(conn, "SELECT COUNT(*) FROM master_vulnerabilities WHERE affected_product_count = 0") / total
    cna = _one(conn, "SELECT COUNT(*) FROM master_vulnerabilities WHERE cvss_source='cna'")
    c.append(Check("13", "NVD enrichment health", "PASS" if cvss_null < 40 else "WARN",
                   f"CVSS null {cvss_null:.1f}%, CPE null {cpe_null:.1f}%, CVSS from CNA {cna} rows"))
    # 14 KEV in-window coverage
    kev_in_window = _one(conn, "SELECT COUNT(*) FROM cisa_kev WHERE date_added >= date('now', ?)", (f"-{settings.BASELINE_MONTHS} months",))
    kev_in_window_ok = _one(conn, "SELECT COUNT(*) FROM cisa_kev k JOIN master_vulnerabilities m ON m.cve_id=k.cve_id "
                                  "WHERE k.date_added >= date('now', ?)", (f"-{settings.BASELINE_MONTHS} months",))
    c.append(Check("14", "KEV added in baseline window present in master", "PASS" if kev_in_window_ok == kev_in_window else "FAIL",
                   f"{kev_in_window_ok}/{kev_in_window}"))
    # 15 composite keys
    d1 = _one(conn, "SELECT COUNT(*) - COUNT(DISTINCT cve_id||'|'||score_date) FROM epss_scores")
    d2 = _one(conn, "SELECT COUNT(*) - COUNT(DISTINCT cve_id||'|'||cpe23||'|'||ifnull(version_start_including,'')||'|'||ifnull(version_end_excluding,'')||'|'||ifnull(version_start_excluding,'')||'|'||ifnull(version_end_including,'')) FROM cve_products")
    c.append(Check("15", "Composite keys unique (epss_scores, cve_products)", "PASS" if d1 == 0 and d2 == 0 else "FAIL", f"epss dups={d1}, product dups={d2}"))
    return c


def write_report(conn, checks: list[Check]) -> tuple[str, bool]:
    settings.QUALITY_DIR.mkdir(parents=True, exist_ok=True)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = settings.QUALITY_DIR / f"qc_report_{today}.md"
    counts = db.table_counts(conn)
    ok = all(ch.status != "FAIL" for ch in checks)
    lines = [f"# Sentinelt Cyber Dataset — QC Report {today}", "",
             f"Dataset version: {settings.DATASET_VERSION} · Engine {settings.ENGINE_VERSION} · Overall: {'PASS' if ok else 'FAIL'}", "",
             "## Row counts", "", "| table | rows |", "|---|---|"]
    lines += [f"| {t} | {n} |" for t, n in counts.items()]
    lines += ["", "## Checks", "", "| # | check | status | detail |", "|---|---|---|---|"]
    lines += [f"| {ch.id} | {ch.name} | {ch.status} | {ch.detail} |" for ch in checks]
    path.write_text("\n".join(lines) + "\n")
    print(f"  [qc] {'PASS' if ok else 'FAIL'} -> {path}")
    return str(path), ok
