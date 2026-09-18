from datetime import datetime, timedelta, timezone

from engine.ingestion.nvd import windows
from engine.processing.normalize_kev import map_ransomware
from engine.processing.normalize_nvd import CVE_RE, normalize_record, parse_cpe23, reference_signals, select_cvss


def test_cve_regex():
    assert CVE_RE.match("CVE-2026-12345")
    assert CVE_RE.match("CVE-2021-44228")
    assert not CVE_RE.match("CVE-21-1")


def test_parse_cpe23():
    p = parse_cpe23("cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_12:*:*:*:*:*:*")
    assert p == {"part": "a", "vendor": "microsoft", "product": "exchange_server", "version": "2019"}
    assert parse_cpe23("cpe:2.3:o:cisco:ios:*:*:*:*:*:*:*:*")["version"] is None
    assert parse_cpe23("garbage")["vendor"] is None


def test_cvss_prefers_v31_primary_then_cna():
    metrics = {
        "cvssMetricV31": [
            {"type": "Secondary", "source": "cna@vendor", "cvssData": {"version": "3.1", "baseScore": 7.5, "baseSeverity": "HIGH", "attackVector": "NETWORK"}},
            {"type": "Primary", "source": "nvd@nist.gov", "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL", "attackVector": "NETWORK"}},
        ]
    }
    out = select_cvss(metrics)
    assert out["cvss_score"] == 9.8 and out["cvss_source"] == "nvd"
    only_cna = {"cvssMetricV31": [metrics["cvssMetricV31"][0]]}
    out = select_cvss(only_cna)
    assert out["cvss_score"] == 7.5 and out["cvss_source"] == "cna"


def test_cvss_v2_fallback_and_null():
    v2 = {"cvssMetricV2": [{"type": "Primary", "baseSeverity": "MEDIUM", "cvssData": {"version": "2.0", "baseScore": 5.0, "accessVector": "NETWORK"}}]}
    out = select_cvss(v2)
    assert out["cvss_version"] == "2.0" and out["cvss_severity"] == "MEDIUM" and out["attack_vector"] == "NETWORK"
    assert out["privileges_required"] is None
    assert select_cvss(None)["cvss_score"] is None


def test_reference_signals_null_semantics():
    refs = [{"url": "x", "tags": ["Exploit", "Third Party Advisory"]}, {"url": "y", "tags": ["Patch"]}]
    s = reference_signals(refs)
    assert s["exploit_reference_count"] == 1 and s["public_exploit_reference"] == 1 and s["patch_reference_available"] == 1
    s = reference_signals([{"url": "z", "tags": []}])
    assert s["public_exploit_reference"] is None  # absence is NULL, never FALSE
    assert s["patch_reference_available"] is None


def test_ransomware_mapping():
    assert map_ransomware("Known") == 1
    assert map_ransomware("Unknown") is None
    assert map_ransomware(None) is None


def test_normalize_record_products_1_to_n():
    item = {"cve": {
        "id": "CVE-2026-0001", "published": "2026-09-01T10:00:00.000", "lastModified": "2026-09-02T10:00:00.000",
        "descriptions": [{"lang": "en", "value": "desc"}],
        "metrics": {}, "references": [],
        "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-79"}]}],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:app:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:acme:other:1.0:*:*:*:*:*:*:*"},
        ]}]}],
    }}
    row, products, weaknesses = normalize_record(item, "2026-09-18T00:00:00Z", "run")
    assert row["cvss_score"] is None and row["public_exploit_reference"] is None
    assert len(products) == 2 and products[0]["version_end_excluding"] == "2.0"
    assert weaknesses == [{"cve_id": "CVE-2026-0001", "cwe_id": "CWE-79", "source": "nvd@nist.gov", "type": "Primary"}]
    assert len(row["record_hash"]) == 64


def test_nvd_windows_never_exceed_120_days():
    end = datetime(2026, 9, 18, tzinfo=timezone.utc)
    start = end - timedelta(days=365)
    ws = list(windows(start, end))
    assert len(ws) == 4
    assert all((b - a).days <= 120 for a, b in ws)
    assert ws[0][0] == start and ws[-1][1] == end
