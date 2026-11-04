from dataclasses import replace

from s1triage.analyzer import Iocs
from s1triage.enrichment import Enricher

from .conftest import FakeResponse, FakeSession


def test_disabled_without_keys(settings):
    e = Enricher(settings, session=FakeSession({}))
    assert not e.enabled
    assert e.enrich(Iocs(ips={"8.8.8.8"})) == []


def test_vt_and_abuseipdb(settings):
    s = replace(settings, vt_api_key="vt", abuseipdb_api_key="ab", enrich_max_lookups=10)
    session = FakeSession({
        ("GET", "/files/" + "a" * 64): FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 50}}}}),
        ("GET", "/domains/evil.example.com"): FakeResponse(404, {}),
        ("GET", "/api/v2/check"): FakeResponse(200, {"data": {"abuseConfidenceScore": 90, "totalReports": 5, "countryCode": "NL"}}),
    })
    results = Enricher(s, session=session).enrich(Iocs(ips={"203.0.113.9"}, domains={"evil.example.com"}, sha256={"a" * 64}))
    by_src = {(v.source, v.ioc_type): v for v in results}
    assert by_src[("VirusTotal", "file")].malicious
    assert by_src[("AbuseIPDB", "ip")].malicious
    assert not by_src[("VirusTotal", "domain")].malicious


def test_lookup_budget(settings):
    s = replace(settings, vt_api_key="vt", enrich_max_lookups=1)
    session = FakeSession({("GET", "/ip_addresses/1.1.1.1"): FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": {}}}})})
    results = Enricher(s, session=session).enrich(Iocs(ips={"1.1.1.1", "8.8.8.8"}))
    assert len(results) == 1
    assert len(session.calls) == 1
