# Acquisition Methodology — Step 02 (v0.1)

## Architecture
SOURCE → RAW (gzip, immutable, per run) → STANDARDIZED (tables + CSV) → MASTER (`master_vulnerabilities`) → QC report.

## Population rule
`master = NVD(published within last 12 months) ∪ NVD(every CVE listed in CISA KEV)`.
Column `in_baseline_window` (1/0) distinguishes the two. Brief #001 uses a 90-day filter on top of the master.
Rationale: KEV regularly adds CVEs published years earlier; without the union, QC check 07 would fail by design.

## NVD
1. Baseline: windows of ≤120 days back 12 months (`pubStartDate/pubEndDate`), paginated at 2000 records.
2. KEV backfill: one query with flag `hasKev`; any KEV CVE still missing is fetched by `cveId`.
3. Incremental (daily): `lastModStartDate/lastModEndDate` since last successful run.
4. Rate limit: sleep 6.5 s without key, 0.7 s with key; retry with backoff on 403/429/5xx.
5. Every page saved to `raw/nvd/<date>/<run_id>/<tag>_pNNN.json.gz` and listed in `ingestion_log.raw_files`.

## CISA KEV
Full JSON snapshot each run → `cisa_kev` replaced entirely (the catalog is a snapshot). `Known`→1, `Unknown`→NULL.

## EPSS
Daily CSV snapshot → `epss_scores(cve_id, score_date)`. Only CVEs known to the engine are loaded to the DB; the full file stays in RAW.

## Normalization rules
- CVE id must match `CVE-YYYY-NNNN+`.
- Dates kept as ISO strings (UTC) as published.
- CVSS: v3.1 Primary → v3.1 Secondary (CNA) → v4.0 → v3.0 → v2.0; `cvss_source` = nvd|cna. Missing → NULL (never dropped).
- Products: each `cpeMatch` → one row in `cve_products`; `primary_vendor/product` = KEV vendor/product if in KEV, else most frequent vulnerable CPE pair.
- Reference tags: `Exploit` → `exploit_reference_count`, `public_exploit_reference=1`; `Patch`/`Vendor Advisory` → `patch_reference_available=1`. No tag → NULL.
- `record_hash` (sha256 of normalized fields) detects changes between runs; unchanged records are skipped.

## Quality control (15 checks)
01 CVE format · 02 unique ids · 03 dates valid/ordered · 04 CVSS 0–10 · 05 EPSS 0–1 · 06 percentile 0–1 ·
07 all KEV CVEs in master · 08 EPSS coverage ≥80% · 09 provenance present · 10 missingness report ·
11 freshness <48 h · 12 row delta vs previous build ≤50% · 13 NVD enrichment health (CVSS/CPE null rate) ·
14 KEV added in window all present · 15 composite keys unique.

## Versioning
`dataset_version` row per build (version, git commit, row counts). Freeze Step 02 with git tag `v0.1` when DoD is met.

## Definition of Done (Step 02)
DATA: NVD, KEV, EPSS acquired; source metadata stored. DATABASE: SQLite, master, unique ids, provenance.
ENGINE: repeatable ingestion, normalization, validation, logging. DOCUMENTATION: data dictionary, source registry, this file, version recorded.
