"""Normalize RAW NVD pages -> nvd_vulnerabilities, cve_products, cve_weaknesses (+ standardized CSV).

Rules (review 2026-09-18):
  3.3  vendor/product is 1:N  -> cve_products table; primary vendor/product decided in build_master.
  3.4  CVSS selection: V3.1 Primary(NVD) > V3.1 Secondary(CNA) > V4.0 > V3.0 > V2.0. cvss_source recorded.
  3.5  Reference tags -> exploit/patch counts. Absence of a tag yields NULL, never FALSE.
  NULL means "not available". Nothing is invented.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import pandas as pd

from engine.config import settings
from engine.database import db
from engine.ingestion._http import read_json_gz

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CVSS_PREFERENCE = ["cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"]
EXPLOIT_TAGS = {"Exploit"}
PATCH_TAGS = {"Patch", "Vendor Advisory"}


def parse_cpe23(cpe: str) -> dict:
    """cpe:2.3:part:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other"""
    parts = re.split(r"(?<!\\):", cpe)
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return {"part": None, "vendor": None, "product": None, "version": None}
    clean = lambda s: None if s in ("*", "-", "") else s.replace("\\", "")  # noqa: E731
    return {"part": clean(parts[2]), "vendor": clean(parts[3]), "product": clean(parts[4]), "version": clean(parts[5])}


def select_cvss(metrics: dict | None) -> dict:
    """Pick one CVSS metric by preference order and Primary before Secondary. Returns normalized dict."""
    empty = {k: None for k in ("cvss_version", "cvss_source", "cvss_score", "cvss_severity", "cvss_vector",
                                "attack_vector", "attack_complexity", "privileges_required", "user_interaction",
                                "confidentiality_impact", "integrity_impact", "availability_impact")}
    if not metrics:
        return empty
    for key in CVSS_PREFERENCE:
        entries = metrics.get(key) or []
        for wanted in ("Primary", "Secondary"):
            for m in entries:
                if m.get("type") != wanted:
                    continue
                d = m.get("cvssData", {})
                out = dict(empty)
                out["cvss_version"] = d.get("version")
                out["cvss_source"] = "nvd" if wanted == "Primary" else "cna"
                out["cvss_score"] = d.get("baseScore")
                out["cvss_severity"] = d.get("baseSeverity") or m.get("baseSeverity")
                out["cvss_vector"] = d.get("vectorString")
                if key == "cvssMetricV2":
                    out["attack_vector"] = d.get("accessVector")
                    out["attack_complexity"] = d.get("accessComplexity")
                    out["confidentiality_impact"] = d.get("confidentialityImpact")
                    out["integrity_impact"] = d.get("integrityImpact")
                    out["availability_impact"] = d.get("availabilityImpact")
                elif key == "cvssMetricV40":
                    out["attack_vector"] = d.get("attackVector")
                    out["attack_complexity"] = d.get("attackComplexity")
                    out["privileges_required"] = d.get("privilegesRequired")
                    out["user_interaction"] = d.get("userInteraction")
                    out["confidentiality_impact"] = d.get("vulnConfidentialityImpact")
                    out["integrity_impact"] = d.get("vulnIntegrityImpact")
                    out["availability_impact"] = d.get("vulnAvailabilityImpact")
                else:
                    out["attack_vector"] = d.get("attackVector")
                    out["attack_complexity"] = d.get("attackComplexity")
                    out["privileges_required"] = d.get("privilegesRequired")
                    out["user_interaction"] = d.get("userInteraction")
                    out["confidentiality_impact"] = d.get("confidentialityImpact")
                    out["integrity_impact"] = d.get("integrityImpact")
                    out["availability_impact"] = d.get("availabilityImpact")
                return out
    return empty


def reference_signals(references: list[dict] | None) -> dict:
    refs = references or []
    exploit = sum(1 for r in refs if EXPLOIT_TAGS & set(r.get("tags") or []))
    patch = sum(1 for r in refs if PATCH_TAGS & set(r.get("tags") or []))
    return {
        "reference_count": len(refs),
        "exploit_reference_count": exploit,
        "patch_reference_count": patch,
        "public_exploit_reference": 1 if exploit > 0 else None,      # absence of tag != proof of absence
        "patch_reference_available": 1 if patch > 0 else None,
    }


def normalize_record(item: dict, retrieved_at: str, run_id: str) -> tuple[dict, list[dict], list[dict]]:
    cve = item["cve"]
    cve_id = cve["id"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
    row = {
        "cve_id": cve_id,
        "source_identifier": cve.get("sourceIdentifier"),
        "published_date": cve.get("published"),
        "modified_date": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "description": desc,
        **select_cvss(cve.get("metrics")),
        **reference_signals(cve.get("references")),
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "retrieved_at": retrieved_at,
        "run_id": run_id,
    }
    hash_src = json.dumps({k: v for k, v in row.items() if k not in ("retrieved_at", "run_id")}, sort_keys=True)
    row["record_hash"] = hashlib.sha256(hash_src.encode()).hexdigest()

    products: list[dict] = []
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                crit = m.get("criteria", "")
                products.append({
                    "cve_id": cve_id, "cpe23": crit, **parse_cpe23(crit),
                    "version_start_including": m.get("versionStartIncluding"),
                    "version_start_excluding": m.get("versionStartExcluding"),
                    "version_end_including": m.get("versionEndIncluding"),
                    "version_end_excluding": m.get("versionEndExcluding"),
                    "vulnerable": 1 if m.get("vulnerable") else 0,
                    "match_criteria_id": m.get("matchCriteriaId"),
                })
    weaknesses: list[dict] = []
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []) or []:
            if d.get("value", "").startswith("CWE-") or d.get("value") in ("NVD-CWE-Other", "NVD-CWE-noinfo"):
                weaknesses.append({"cve_id": cve_id, "cwe_id": d["value"], "source": w.get("source"), "type": w.get("type")})
    return row, products, weaknesses


def _raw_files_for_run(conn, run_id: str) -> list[Path]:
    row = conn.execute("SELECT raw_files FROM ingestion_log WHERE run_id=?", (run_id,)).fetchone()
    return [Path(p) for p in json.loads(row[0] or "[]")] if row else []


def load_run(conn, run_id: str) -> dict:
    """Parse all raw pages of a run and upsert into standardized tables."""
    files = _raw_files_for_run(conn, run_id)
    retrieved_at = conn.execute("SELECT end_time FROM ingestion_log WHERE run_id=?", (run_id,)).fetchone()[0]
    added = updated = unchanged = failed = 0
    rows_for_csv: list[dict] = []
    cols = None
    for f in files:
        payload = read_json_gz(f)
        for item in payload.get("vulnerabilities", []):
            try:
                row, products, weaknesses = normalize_record(item, retrieved_at, run_id)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                print(f"  [nvd-norm] failed record: {exc}")
                continue
            if not CVE_RE.match(row["cve_id"]):
                failed += 1
                continue
            existing = conn.execute("SELECT record_hash, modified_date FROM nvd_vulnerabilities WHERE cve_id=?",
                                    (row["cve_id"],)).fetchone()
            if existing and existing[0] == row["record_hash"]:
                unchanged += 1
                continue
            if existing and existing[1] and row["modified_date"] and existing[1] > row["modified_date"]:
                unchanged += 1  # DB has a newer version (raw pages may overlap)
                continue
            cols = cols or list(row.keys())
            conn.execute(f"INSERT OR REPLACE INTO nvd_vulnerabilities ({','.join(cols)}) VALUES ({','.join('?'*len(cols))})",
                         [row[c] for c in cols])
            conn.execute("DELETE FROM cve_products WHERE cve_id=?", (row["cve_id"],))
            conn.execute("DELETE FROM cve_weaknesses WHERE cve_id=?", (row["cve_id"],))
            if products:
                pcols = list(products[0].keys())
                conn.executemany(f"INSERT OR IGNORE INTO cve_products ({','.join(pcols)}) VALUES ({','.join('?'*len(pcols))})",
                                 [[p[c] for c in pcols] for p in products])
            if weaknesses:
                conn.executemany("INSERT OR IGNORE INTO cve_weaknesses (cve_id,cwe_id,source,type) VALUES (?,?,?,?)",
                                 [(w["cve_id"], w["cwe_id"], w["source"], w["type"]) for w in weaknesses])
            added += 0 if existing else 1
            updated += 1 if existing else 0
            rows_for_csv.append(row)
    conn.commit()
    conn.execute("UPDATE ingestion_log SET records_added=?, records_updated=?, records_failed=? WHERE run_id=?",
                 (added, updated, failed, run_id))
    conn.commit()
    if rows_for_csv:
        out = settings.STD_DIR / "nvd"
        out.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(rows_for_csv).to_csv(out / f"nvd_vulnerabilities_{run_id}.csv", index=False)
    stats = {"files": len(files), "added": added, "updated": updated, "unchanged": unchanged, "failed": failed}
    print(f"  [nvd-norm] {run_id}: {stats}")
    return stats


def load_pending_runs(conn) -> list[dict]:
    """Normalize every successful NVD run not yet normalized (records_added+updated == 0 and status success)."""
    runs = conn.execute("SELECT run_id FROM ingestion_log WHERE source='NVD' AND status IN ('success','partial') "
                        "AND records_added=0 AND records_updated=0 AND records_received>0 ORDER BY start_time").fetchall()
    return [load_run(conn, r[0]) for r in runs]


def top_vendor_product(products: list[dict]) -> tuple[str | None, str | None, int]:
    vulnerable = [(p["vendor"], p["product"]) for p in products if p.get("vulnerable") and p.get("vendor")]
    if not vulnerable:
        return None, None, 0
    (vendor, product), _ = Counter(vulnerable).most_common(1)[0]
    return vendor, product, len(set(vulnerable))
