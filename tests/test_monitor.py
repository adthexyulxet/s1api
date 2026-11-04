import json

from s1triage.client import S1Client
from s1triage.enrichment import Enricher
from s1triage.monitor import TriagePipeline
from s1triage.state import SeenThreats

from .conftest import FakeResponse, FakeSession, threat_payload


def dv_routes(events):
    return {
        ("POST", "/dv/init-query"): FakeResponse(200, {"data": {"queryId": "q"}}),
        ("GET", "/dv/query-status"): FakeResponse(200, {"data": {"responseState": "FINISHED", "progressStatus": 100}}),
        ("GET", "/dv/events"): FakeResponse(200, {"data": events, "pagination": {}}),
    }


def make_pipeline(settings, routes, fixed_now, seen=None, tmp_path=None):
    session = FakeSession(routes)
    client = S1Client(settings, session=session, sleep=lambda s: None, now=fixed_now)
    out = []
    p = TriagePipeline(settings, client=client, enricher=Enricher(settings, session=session),
                       seen=seen if seen is not None else SeenThreats(""), out=out.append)
    return p, session, out


def test_processes_all_new_threats_oldest_first_and_dedupes(settings, fixed_now):
    routes = {("GET", "/threats"): FakeResponse(200, {"data": [threat_payload("3"), threat_payload("2"), threat_payload("1")]})}
    routes.update(dv_routes([{"tgtProcName": "powershell.exe", "tgtProcCmdLine": "powershell -enc AAAAAAAAAAAAAAAAAAAAAAAA"}]))
    p, _, out = make_pipeline(settings, routes, fixed_now)

    reports = p.poll_once()
    assert [r.threat.threat_id for r in reports] == ["1", "2", "3"]
    assert all(r.analysis.findings for r in reports)
    assert reports[0].level in {"MEDIUM", "HIGH"}
    assert p.poll_once() == []  # 두 번째 폴링에서는 재분석하지 않음
    assert any("Analysis Report" in line for line in out)


def test_failed_dv_query_is_retried_next_poll(settings, fixed_now):
    routes = {
        ("GET", "/threats"): FakeResponse(200, {"data": [threat_payload("1")]}),
        ("POST", "/dv/init-query"): FakeResponse(500, {"errors": ["boom"]}),
    }
    p, _, _ = make_pipeline(settings, routes, fixed_now)
    reports = p.poll_once()
    assert reports[0].error
    assert "1" not in p.seen


def test_threat_without_storyline_is_marked_seen(settings, fixed_now):
    routes = {("GET", "/threats"): FakeResponse(200, {"data": [threat_payload("9", storyline=None)]})}
    p, _, _ = make_pipeline(settings, routes, fixed_now)
    p.poll_once()
    assert "9" in p.seen


def test_state_persists_and_report_saved(settings, fixed_now, tmp_path):
    from dataclasses import replace
    s = replace(settings, report_dir=str(tmp_path / "reports"))
    state_file = tmp_path / "state" / "seen.json"
    routes = {("GET", "/threats"): FakeResponse(200, {"data": [threat_payload("42")]})}
    routes.update(dv_routes([{"dstIp": "8.8.8.8"}]))
    p, _, _ = make_pipeline(s, routes, fixed_now, seen=SeenThreats(str(state_file)))
    p.poll_once()

    assert "42" in SeenThreats(str(state_file))
    data = json.loads((tmp_path / "reports" / "threat_42.json").read_text(encoding="utf-8"))
    assert data["threat"]["storyline_id"] == "SL-1"
    assert data["dv"]["iocs"]["ips"] == ["8.8.8.8"]


def test_skip_backlog(settings, fixed_now):
    routes = {("GET", "/threats"): FakeResponse(200, {"data": [threat_payload("1"), threat_payload("2")]})}
    p, _, _ = make_pipeline(settings, routes, fixed_now)
    assert p.mark_backlog_seen() == 2
    assert p.poll_once() == []


def test_zero_events_message(settings, fixed_now):
    routes = {("GET", "/threats"): FakeResponse(200, {"data": [threat_payload("5")]})}
    routes.update(dv_routes([]))
    p, _, out = make_pipeline(settings, routes, fixed_now)
    p.poll_once()
    text = "\n".join(out)
    assert "DV 이벤트를 찾지 못했습니다" in text
    assert "수집된 이벤트는 있으나" not in text
