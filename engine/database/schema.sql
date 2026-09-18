-- Sentinelt Intelligence Engine v0.1 — SQLite schema
-- Rules: NULL means "not available"; FALSE means the source explicitly says no.
-- cve_id is the master key everywhere. Raw files are never modified; DB is rebuildable from raw.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS data_sources (
    source_name       TEXT PRIMARY KEY,          -- NVD | CISA_KEV | EPSS | VENDOR
    description       TEXT NOT NULL,
    url               TEXT NOT NULL,
    license_or_terms  TEXT,
    update_frequency  TEXT,
    role              TEXT                       -- primary | exploitation | likelihood | remediation
);

CREATE TABLE IF NOT EXISTS ingestion_log (
    run_id            TEXT PRIMARY KEY,          -- e.g. 20260918T143000_nvd
    source            TEXT NOT NULL,
    mode              TEXT,                      -- baseline | kev_backfill | incremental | snapshot
    start_time        TEXT NOT NULL,
    end_time          TEXT,
    records_received  INTEGER DEFAULT 0,
    records_added     INTEGER DEFAULT 0,
    records_updated   INTEGER DEFAULT 0,
    records_failed    INTEGER DEFAULT 0,
    status            TEXT NOT NULL,             -- running | success | partial | failed
    error_log         TEXT,
    raw_files         TEXT,                      -- JSON list of raw file paths written
    params            TEXT                       -- JSON of request params (windows, dates)
);

-- ---------- STANDARDIZED: NVD ----------
CREATE TABLE IF NOT EXISTS nvd_vulnerabilities (
    cve_id                  TEXT PRIMARY KEY,
    source_identifier       TEXT,
    published_date          TEXT,               -- ISO 8601 UTC
    modified_date           TEXT,
    vuln_status             TEXT,               -- NVD vulnStatus (Analyzed, Awaiting Analysis, ...)
    description             TEXT,
    cvss_version            TEXT,               -- 3.1 | 4.0 | 2.0 | NULL
    cvss_source             TEXT,               -- nvd | cna | NULL  (selection rule, review 3.4)
    cvss_score              REAL,
    cvss_severity           TEXT,
    cvss_vector             TEXT,
    attack_vector           TEXT,
    attack_complexity       TEXT,
    privileges_required     TEXT,
    user_interaction        TEXT,
    confidentiality_impact  TEXT,
    integrity_impact        TEXT,
    availability_impact     TEXT,
    reference_count         INTEGER,
    exploit_reference_count INTEGER,            -- references tagged "Exploit"
    patch_reference_count   INTEGER,            -- references tagged "Patch" or "Vendor Advisory"
    public_exploit_reference INTEGER,           -- 1 if exploit_reference_count>0 else NULL (absence != proof)
    patch_reference_available INTEGER,          -- 1 if patch_reference_count>0 else NULL
    record_hash             TEXT,               -- sha256 of normalized record (change detection)
    source_url              TEXT,
    retrieved_at            TEXT NOT NULL,
    run_id                  TEXT
);

CREATE TABLE IF NOT EXISTS cve_products (
    cve_id                   TEXT NOT NULL,
    cpe23                    TEXT NOT NULL,
    part                     TEXT,               -- a | o | h
    vendor                   TEXT,
    product                  TEXT,
    version                  TEXT,
    version_start_including  TEXT,
    version_start_excluding  TEXT,
    version_end_including    TEXT,
    version_end_excluding    TEXT,
    vulnerable               INTEGER,           -- 1/0
    match_criteria_id        TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cve_products
    ON cve_products (cve_id, cpe23, ifnull(version_start_including,''), ifnull(version_start_excluding,''),
                     ifnull(version_end_including,''), ifnull(version_end_excluding,''));
CREATE INDEX IF NOT EXISTS ix_cve_products_vendor ON cve_products (vendor, product);

CREATE TABLE IF NOT EXISTS cve_weaknesses (
    cve_id   TEXT NOT NULL,
    cwe_id   TEXT NOT NULL,
    source   TEXT,
    type     TEXT,                               -- Primary | Secondary
    UNIQUE (cve_id, cwe_id, source)
);

-- ---------- STANDARDIZED: CISA KEV ----------
CREATE TABLE IF NOT EXISTS cisa_kev (
    cve_id                          TEXT PRIMARY KEY,
    vendor_project                  TEXT,
    product                         TEXT,
    vulnerability_name              TEXT,
    date_added                      TEXT,
    short_description               TEXT,
    required_action                 TEXT,
    due_date                        TEXT,
    known_ransomware_campaign_use_raw TEXT,      -- "Known" | "Unknown" exactly as published
    known_ransomware_use            INTEGER,     -- Known -> 1 ; Unknown -> NULL (never 0)
    notes                           TEXT,
    cwes                            TEXT,        -- JSON list
    catalog_version                 TEXT,
    date_released                   TEXT,
    source_url                      TEXT,
    retrieved_at                    TEXT NOT NULL,
    run_id                          TEXT
);

-- ---------- STANDARDIZED: EPSS (time series) ----------
CREATE TABLE IF NOT EXISTS epss_scores (
    cve_id         TEXT NOT NULL,
    score_date     TEXT NOT NULL,                -- YYYY-MM-DD
    epss           REAL,
    percentile     REAL,
    model_version  TEXT,
    source_file    TEXT,
    retrieved_at   TEXT NOT NULL,
    PRIMARY KEY (cve_id, score_date)
);

-- ---------- EVIDENCE: vendor advisories (manual/selected) ----------
CREATE TABLE IF NOT EXISTS vendor_advisories (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id               TEXT NOT NULL,
    vendor               TEXT,
    advisory_url         TEXT NOT NULL,
    affected_versions    TEXT,
    fixed_version        TEXT,
    patch_available      INTEGER,               -- 1/0/NULL
    mitigation_available INTEGER,               -- 1/0/NULL
    evidence_status      TEXT,                  -- verified | unverified
    analyst_note         TEXT,
    retrieved_at         TEXT NOT NULL
);

-- ---------- LEVEL 2 contract: client inventory (empty in v0.1) ----------
CREATE TABLE IF NOT EXISTS client_inventory (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id          TEXT NOT NULL,
    product_name_raw   TEXT NOT NULL,            -- as written by the client
    vendor_guess       TEXT,
    product_guess      TEXT,
    version            TEXT,
    internet_facing    INTEGER,                  -- 1/0/NULL
    business_critical  INTEGER,                  -- 1/0/NULL
    cpe_match          TEXT,                     -- cpe:2.3 vendor:product resolved
    match_confidence   REAL,
    notes              TEXT,
    created_at         TEXT NOT NULL
);

-- ---------- MASTER ----------
CREATE TABLE IF NOT EXISTS master_vulnerabilities (
    cve_id                    TEXT PRIMARY KEY,
    in_baseline_window        INTEGER NOT NULL,  -- 1 if published within BASELINE_MONTHS, else 0 (KEV backfill)
    -- identity
    description               TEXT,
    primary_vendor            TEXT,
    primary_product           TEXT,
    affected_product_count    INTEGER,
    cwe_ids                   TEXT,              -- comma-separated
    vuln_status               TEXT,
    -- time
    published_date            TEXT,
    modified_date             TEXT,
    kev_date_added            TEXT,
    kev_due_date              TEXT,
    days_published_to_kev     INTEGER,           -- exploitation velocity (catalog latency caveat)
    -- severity
    cvss_version              TEXT,
    cvss_source               TEXT,
    cvss_score                REAL,
    cvss_severity             TEXT,
    attack_vector             TEXT,
    attack_complexity         TEXT,
    privileges_required       TEXT,
    user_interaction          TEXT,
    confidentiality_impact    TEXT,
    integrity_impact          TEXT,
    availability_impact       TEXT,
    -- exploitation
    kev_status                INTEGER NOT NULL,  -- 1/0 (KEV membership is always known)
    kev_vulnerability_name    TEXT,
    kev_required_action       TEXT,
    known_ransomware_use      INTEGER,           -- 1/NULL
    epss_score_latest         REAL,
    epss_percentile_latest    REAL,
    epss_date                 TEXT,
    public_exploit_reference  INTEGER,
    exploit_reference_count   INTEGER,
    -- remediation
    patch_reference_available INTEGER,
    patch_available           INTEGER,           -- from vendor_advisories when present
    fixed_version             TEXT,
    mitigation_available      INTEGER,
    vendor_advisory_url       TEXT,
    -- provenance
    nvd_source_url            TEXT,
    cisa_source_url           TEXT,
    epss_source_file          TEXT,
    retrieved_at              TEXT NOT NULL,
    dataset_version           TEXT NOT NULL,
    built_at                  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dataset_version (
    version      TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    git_commit   TEXT,
    row_counts   TEXT,                           -- JSON
    notes        TEXT
);
