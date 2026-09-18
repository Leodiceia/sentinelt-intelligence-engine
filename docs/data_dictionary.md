# Data Dictionary — Sentinelt Cyber Dataset v0.1 (living document)

Conventions: `NULL` = not available from any source. `1/0` booleans only when the source is explicit.
Types are SQLite affinities. "Score" = used by the Priority Framework (Step 05, hypothesis).

## master_vulnerabilities (one row per CVE)

| Field | Definition | Type | Source | Required | Values | Use | Score |
|---|---|---|---|---|---|---|---|
| cve_id | CVE identifier, master key | TEXT | NVD | Yes | `CVE-YYYY-NNNN+` | key | — |
| in_baseline_window | Published within the last 12 months (1) or present only because it is KEV-listed (0) | INT | Sentinelt | Yes | 1/0 | population | — |
| description | English description | TEXT | NVD | Yes | text | context | — |
| primary_vendor / primary_product | KEV vendor/product when in KEV; else most frequent vulnerable CPE pair. Convenience only; see cve_products | TEXT | CISA/NVD | Preferred | text/NULL | analytics | — |
| affected_product_count | Distinct vulnerable (vendor, product) pairs | INT | NVD | Yes | ≥0 | concentration | — |
| cwe_ids | Comma-separated CWE ids | TEXT | NVD | Preferred | `CWE-79,...`/NULL | pattern analysis | — |
| vuln_status | NVD analysis status | TEXT | NVD | Preferred | Analyzed, Awaiting Analysis, Modified, … | data health | — |
| published_date / modified_date | NVD publication / last modification | TEXT ISO | NVD | Yes | datetime | recency | Recency |
| kev_date_added / kev_due_date | Date CISA catalogued it / federal remediation due date | TEXT | CISA | If KEV | date/NULL | urgency | Remediation |
| days_published_to_kev | kev_date_added − published_date (catalog latency caveat) | INT | derived | If KEV | days/NULL | velocity | Recency |
| cvss_version / cvss_source | Selected metric version and origin (nvd = NVD Primary, cna = CNA Secondary) | TEXT | NVD | Preferred | 3.1/4.0/3.0/2.0 · nvd/cna | severity | Severity |
| cvss_score / cvss_severity / cvss_vector | Base score, qualitative severity, vector string | REAL/TEXT | NVD | Preferred | 0–10 / LOW…CRITICAL | severity | Severity |
| attack_vector … availability_impact | CVSS components (v2 maps accessVector→attack_vector; privileges/UI NULL) | TEXT | NVD | Preferred | CVSS enums/NULL | context | Severity |
| kev_status | Listed in CISA KEV | INT | CISA | Yes | 1/0 (always known) | exploitation | Exploitation |
| kev_vulnerability_name / kev_required_action | CISA name and official required action text | TEXT | CISA | If KEV | text/NULL | brief actions | — |
| known_ransomware_use | CISA "Known" → 1; "Unknown" → NULL (CISA does not assert no) | INT | CISA | If KEV | 1/NULL | priority context | Exploitation |
| epss_score_latest / epss_percentile_latest / epss_date | Latest EPSS probability, percentile and its date (history in epss_scores) | REAL/TEXT | EPSS | Preferred | 0–1 / 0–1 / date | likelihood | Likelihood |
| public_exploit_reference / exploit_reference_count | NVD references tagged "Exploit" (1 / count); no tag → NULL | INT | NVD | Preferred | 1/NULL · ≥0 | evidence convergence | Exploitation |
| patch_reference_available | NVD references tagged "Patch" or "Vendor Advisory"; no tag → NULL | INT | NVD | Preferred | 1/NULL | remediation | Remediation |
| patch_available / fixed_version / mitigation_available / vendor_advisory_url | From verified vendor advisory (selected CVEs) | INT/TEXT | Vendor | Selected | 1/0/NULL, text, URL | remediation | Remediation |
| nvd_source_url / cisa_source_url / epss_source_file | Evidence links / file | TEXT | Sentinelt | Yes | URL/file | provenance | — |
| retrieved_at | UTC time the NVD record was retrieved | TEXT | Sentinelt | Yes | ISO | provenance | — |
| dataset_version / built_at | Dataset version and build time | TEXT | Sentinelt | Yes | `v0.1` | provenance | — |

## Supporting tables
- **nvd_vulnerabilities** — standardized NVD record (same severity/reference fields as above + `record_hash`, `run_id`, `source_identifier`).
- **cve_products** — 1:N `cve_id → cpe23, part, vendor, product, version, version_start/end (incl/excl), vulnerable, match_criteria_id`.
- **cve_weaknesses** — 1:N `cve_id → cwe_id, source, type`.
- **cisa_kev** — full KEV entry incl. `known_ransomware_campaign_use_raw`, `catalog_version`, `date_released`.
- **epss_scores** — `(cve_id, score_date) → epss, percentile, model_version, source_file`.
- **vendor_advisories** — manual evidence rows with `evidence_status` (verified/unverified) and `analyst_note`.
- **client_inventory** — Level 2 contract: `client_id, product_name_raw, vendor_guess, product_guess, version, internet_facing, business_critical, cpe_match, match_confidence`. Empty in v0.1.
- **data_sources**, **ingestion_log** (`run_id, source, mode, times, records_received/added/updated/failed, status, error_log, raw_files, params`), **dataset_version**.

## Important semantics (repeat in every Brief)
`kev_status = 1` means CISA lists the CVE as known exploited somewhere; it does **not** mean any specific organization is compromised.
EPSS is a population-level 30-day exploitation probability; it is not the client's risk.
The Sentinelt Priority Score (Step 05) expresses **priority for attention** based on public evidence, never "% risk".
