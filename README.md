# Sentinelt Intelligence Engine — Data Foundation (v0.1)

**Question the full engine answers:** *Which publicly known vulnerabilities should an organization consider prioritizing for attention, and why?*

This repository publishes the **data foundation** of the Sentinelt Intelligence Engine: acquisition of public
authoritative sources, normalization, master build and quality control.

Public authoritative sources → RAW (immutable) → STANDARDIZED → MASTER → QC.

The layers built on top of it — analytics, the **Sentinelt Cyber Priority Score (SCPS)**, the Intelligence Brief
generator and the client Assessment generator — are proprietary to Sentinelt LLC and are **not published here**.
Their outputs are: *Sentinelt Cyber Intelligence Brief #001* (see Releases) and the Sentinelt Cyber Intelligence Assessment.

## Status — v0.1 (2026-09-21)
Baseline of 2026-09-20: 86,297 CVEs (NVD 12 months ∪ all CISA KEV), 1,716 KEV entries, EPSS coverage 97%, 15 QC checks PASS.

## Setup (once)
```bash
python3 -m pip install -r requirements.txt
cp .env.example .env            # then paste your NVD_API_KEY (https://nvd.nist.gov/developers/request-an-api-key)
python3 -m pytest -q            # unit tests (no network)
```

## Run
```bash
python3 scripts/run_pipeline.py --mode baseline --days 3      # smoke test: tiny NVD window + KEV + EPSS + master + QC
python3 scripts/run_pipeline.py --mode baseline               # 12 months + all KEV CVEs (30–60 min without key)
python3 scripts/run_pipeline.py --mode incremental            # daily refresh
python3 scripts/run_pipeline.py --mode rebuild                # no downloads: re-normalize pending raw, rebuild master, QC
```
Exit code 1 means a QC check FAILED; read `sentinelt-data/quality/qc_report_<date>.md`.
Data lives outside the repo (default `~/Developer/sentinelt/sentinelt-data`, set by `SENTINELT_DATA_DIR`). The DB is fully rebuildable from RAW.

## Layout
```
engine/
  config/settings.py      paths, sources, population rule, rate limits
  ingestion/              nvd.py  cisa_kev.py  epss.py   — download only; write RAW; log to ingestion_log
  processing/             normalize_nvd.py  normalize_kev.py  normalize_epss.py  build_master.py
  database/               schema.sql  db.py
  quality/validate.py     15 QC checks -> markdown report
docs/                     data_dictionary.md  source_registry.md  methodology_acquisition.md
scripts/run_pipeline.py   orchestrator
tests/                    pytest (no network)
```

## Rules that must not be broken
1. RAW is never modified. Every RAW file is referenced by an `ingestion_log.run_id`.
2. `NULL` = not available. `0/FALSE` only when the source explicitly says no. (`knownRansomwareCampaignUse: Unknown` → NULL.)
3. Population: `master = NVD(published last 12 months) ∪ NVD(all CISA KEV CVEs)`; `in_baseline_window` separates them.
4. EPSS is a time series (`epss_scores` keyed by `cve_id, score_date`). Master carries only the latest.
5. One CVE → many products (`cve_products`). `primary_vendor/product` in master is a convenience, not the truth.
6. CVSS selection: v3.1 Primary (NVD) → v3.1 Secondary (CNA) → v4.0 → v3.0 → v2.0; `cvss_source` says which.
7. Every master row carries `nvd_source_url`, `retrieved_at`, `dataset_version`.
8. Secrets in `.env` only. Client data never enters this repo.
9. Sentinelt scores measure **priority**, not organizational risk. Wording matters.

## Authorship
Designed and built by **Leodiceia Hinchley**, founder of Sentinelt LLC (Miami, FL), September 2026, with AI pair-programming.
The commit history and `CHANGELOG.md` record each step. See `LICENSE` (source-available, all rights reserved).

## Data attribution
NIST National Vulnerability Database (public domain) · CISA Known Exploited Vulnerabilities Catalog · FIRST.org EPSS.
Sentinelt outputs must credit these sources and must never imply endorsement by NIST, CISA or FIRST.
