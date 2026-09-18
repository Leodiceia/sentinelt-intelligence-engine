"""Central configuration for the Sentinelt Intelligence Engine v0.1.

All paths point OUTSIDE iCloud by default. Secrets come from .env (never committed).
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(REPO_ROOT / ".env")

ENGINE_VERSION = "0.1.0"
DATASET_VERSION = "v0.1"

# --- Storage layers: SOURCE -> RAW -> STANDARDIZED -> MASTER -> QUALITY ---
DATA_DIR = Path(os.getenv("SENTINELT_DATA_DIR") or Path.home() / "Developer" / "sentinelt" / "sentinelt-data")
RAW_DIR = DATA_DIR / "raw"
STD_DIR = DATA_DIR / "standardized"
MASTER_DIR = DATA_DIR / "master"
QUALITY_DIR = DATA_DIR / "quality"
DB_PATH = MASTER_DIR / "sentinelt_cyber.db"

# --- Sources ---
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY") or None
NVD_RESULTS_PER_PAGE = 2000
NVD_MAX_WINDOW_DAYS = 120          # hard limit of the NVD API per request
# NVD rate limit: 5 req/30s without key, 50 req/30s with key. NVD recommends ~6s sleep without key.
NVD_SLEEP_SECONDS = 0.7 if NVD_API_KEY else 6.5
NVD_MAX_RETRIES = 5

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CATALOG_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

EPSS_CURRENT_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EPSS_DATED_URL = "https://epss.cyentia.com/epss_scores-{date}.csv.gz"   # date = YYYY-MM-DD
EPSS_SITE = "https://www.first.org/epss/"

# --- Population rule (Step 02, section 3.1 of the review) ---
# master = NVD(published in last BASELINE_MONTHS) UNION NVD(all CVEs listed in CISA KEV)
BASELINE_MONTHS = 12
BRIEF_WINDOW_DAYS = 90

HTTP_TIMEOUT = 60
USER_AGENT = f"Sentinelt-Intelligence-Engine/{ENGINE_VERSION} (research; contact: sentinelt.ai)"


def ensure_dirs() -> None:
    for d in (RAW_DIR / "nvd", RAW_DIR / "cisa_kev", RAW_DIR / "epss", RAW_DIR / "vendor",
              STD_DIR, MASTER_DIR, QUALITY_DIR, DATA_DIR / "clients"):
        d.mkdir(parents=True, exist_ok=True)
