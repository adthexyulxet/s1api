import json
import time

import pytest

from s1triage.client import S1Client
from s1triage.jobs import JobManager

from .conftest import FakeResponse, FakeSession, threat_payload
from .test_narrative import ATTACK, report


def wait(job, timeout=5):
    end = time.time() + timeout
    while job.status not in ("done", "error") and time.time() < end:
        time.sleep(0.02)
    return job


def test_saved_report_analysis(tmp_path):
    (tmp_path / "threat_123.json").write_text(json.dumps(report(ATTACK)), encoding="utf-8")
    jm = JobManager(str(tmp_path))
    assert not jm.can_query
    job = wait(jm.submit("123", refresh=False))
    assert job.status == "done", job.logs
    data = json.loads((tmp_path / "analysis_123.json").read_text(encoding="utf-8"))
    assert data["conclusion"]["verdict"] == "정탐 가능성 높음"
    assert data["options"]["refresh"] is False


def test_refresh_requires_token_and_saved_requires_report(tmp_path):
    jm = JobManager(str(tmp_path))
    with pytest.raises(ValueError):
        jm.submit("123", refresh=True)
    with pytest.raises(ValueError):
        jm.submit("999", refresh=False)


def test_fresh_analysis_queries_console(tmp_path, settings, fixed_now):
    routes = {
        ("GET", "/threats"): FakeResponse(200, {"data": [threat_payload("777")]}),
        ("POST", "/dv/init-query"): FakeResponse(200, {"data": {"queryId": "q"}}),
        ("GET", "/dv/query-status"): FakeResponse(200, {"data": {"responseState": "FINISHED", "progressStatus": 100}}),
        ("GET", "/dv/events"): FakeResponse(200, {"data": ATTACK, "pagination": {}}),
    }
    seen = {}

    def factory(s):
        seen["timeout"] = s.dv_timeout_seconds
        seen["vt"] = s.vt_api_key
        return S1Client(s, session=FakeSession(routes), sleep=lambda x: None, now=fixed_now)

    from dataclasses import replace
    jm = JobManager(str(tmp_path), replace(settings, vt_api_key="k"), client_factory=factory)
    job = wait(jm.submit("777", refresh=True, use_ti=False, timeout=5))  # 30초 미만은 30으로 보정
    assert job.status == "done", job.logs
    assert seen == {"timeout": 30, "vt": ""}
    assert (tmp_path / "threat_777.json").is_file() and (tmp_path / "analysis_777.json").is_file()
    assert any("정밀 분석 완료" in line for line in job.logs)


def test_unknown_threat_reports_error(tmp_path, settings, fixed_now):
    routes = {("GET", "/threats"): FakeResponse(200, {"data": []})}
    jm = JobManager(str(tmp_path), settings,
                    client_factory=lambda s: S1Client(s, session=FakeSession(routes), sleep=lambda x: None, now=fixed_now))
    job = wait(jm.submit("404"))
    assert job.status == "error" and "찾을 수 없습니다" in job.error


def test_ai_verdict_included_when_requested(tmp_path):
    (tmp_path / "threat_123.json").write_text(json.dumps(report(ATTACK)), encoding="utf-8")
    calls = []

    def fake_ai(rep, conclusion):
        calls.append(conclusion["verdict"])
        return {"model": "m", "verdict": "정탐", "confidence": "높음"}

    jm = JobManager(str(tmp_path), ai_fn=fake_ai)
    job = wait(jm.submit("123", refresh=False, use_ai=True))
    assert job.status == "done", job.logs
    data = json.loads((tmp_path / "analysis_123.json").read_text(encoding="utf-8"))
    assert data["ai_verdict"]["verdict"] == "정탐" and calls == ["정탐 가능성 높음"]
    job = wait(jm.submit("123", refresh=False, use_ai=False))
    assert "ai_verdict" not in json.loads((tmp_path / "analysis_123.json").read_text(encoding="utf-8"))
    assert len(calls) == 1
