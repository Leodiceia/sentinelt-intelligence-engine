# Source Registry — Sentinelt Cyber Dataset v0.1

| Source | Role | Endpoint / file | Update | Key fields | Terms / attribution |
|---|---|---|---|---|---|
| NIST NVD (CVE API 2.0) | Primary vulnerability record | `https://services.nvd.nist.gov/rest/json/cves/2.0` — params `pubStartDate/pubEndDate` (≤120 days), `lastModStartDate/lastModEndDate`, `cveId`, flag `hasKev`; `resultsPerPage ≤ 2000` | Continuous; we pull daily | id, published, lastModified, vulnStatus, descriptions, metrics (cvssMetricV31/V40/V30/V2, Primary/Secondary), weaknesses, configurations→cpeMatch, references[tags] | US Government work, public domain. Rate limit 5 req/30 s (50 with free API key). Attribution: "This product uses data from the NVD API but is not endorsed or certified by the NVD." |
| CISA KEV | Known exploitation | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | As CISA publishes (near daily) | cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse (Known/Unknown), notes, cwes | Public. Note: dateAdded = catalog date, not first observed exploitation. Due dates bind federal agencies (BOD 22-01), used by us as urgency context only. |
| FIRST EPSS | Exploitation likelihood (30-day, population level) | `https://epss.cyentia.com/epss_scores-current.csv.gz` and `epss_scores-YYYY-MM-DD.csv.gz` (header comment has `model_version`, `score_date`) | Daily | cve, epss (0–1), percentile (0–1) | Free; credit FIRST.org. EPSS v4 model since 2025-03. Scores change daily → stored as a time series. EPSS is not organizational risk. |
| Vendor advisories | Remediation evidence (selected CVEs only) | Official vendor pages, recorded manually in `vendor_advisories` | On demand | affected/fixed versions, patch, mitigation, URL | Per vendor. `evidence_status` verified/unverified. |

**Not used in v0.1 (by decision):** dark web, social media, paid threat feeds, Shodan, VirusTotal, scanners, client internal data.
**Candidate for v0.2:** CISA Vulnrichment (ADP) SSVC + CVSS for CVEs lacking NVD enrichment; CVE.org JSON 5.x records.
