# Changelog (data foundation)

## v0.1.0 — 2026-09-18 — Step 02 scaffold
- SQLite schema: nvd_vulnerabilities, cve_products (1:N), cve_weaknesses, cisa_kev, epss_scores (time series),
  vendor_advisories, client_inventory (Level 2 contract), master_vulnerabilities, data_sources, ingestion_log, dataset_version.
- Ingestion: NVD API 2.0 (120-day windows, pagination, rate limit, hasKev backfill, incremental by lastModified, by-id),
  CISA KEV JSON snapshot, EPSS daily CSV snapshot. RAW stored gzip, immutable.
- Normalization: CVSS selection rule with cvss_source; reference-tag exploit/patch signals with NULL semantics;
  Known/Unknown ransomware mapping; CPE 2.3 parsing.
- Master build with population rule (baseline window ∪ KEV) and dataset_version registry.
- QC: 15 checks -> markdown report. Unit tests (no network).

## v0.1.1 — 2026-09-21 — Publication
- LICENSE (source-available, all rights reserved), README, .gitignore hardening.
- Full 12-month baseline run 2026-09-20 (86,297 CVEs, QC PASS). Analytics, scoring and reporting layers kept private.
