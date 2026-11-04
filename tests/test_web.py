import json
import threading
import urllib.error
import urllib.request

import pytest

from s1triage.analyzer import analyze_events
from s1triage.client import Threat
from s1triage.report import TriageReport
from s1triage.web import build_server

from .conftest import threat_payload


@pytest.fixture
def server(tmp_path):
    events = [{"eventType": "File Modification", "srcProcName": "bash",
               "tgtFilePath": "/root/.ssh/authorized_keys", "createdAt": "2026-11-03T01:00:00Z"}]
    TriageReport(Threat.from_api(threat_payload("111")), analyze_events(events)).save(str(tmp_path))
    TriageReport(Threat.from_api(threat_payload("222", created="2026-11-03T12:00:00Z")), None, error="boom").save(str(tmp_path))
    (tmp_path / "threat_bad.json").write_text("{not json")
    status = {"last_poll_at": "2026-11-03T12:00:00+00:00", "last_error": None, "analyzed": 2, "polls": 1}
    srv = build_server(str(tmp_path), "127.0.0.1", 0, status)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def get(url):
    with urllib.request.urlopen(url) as r:
        return r.status, r.headers.get("Content-Type"), r.read()


def test_index_served(server):
    code, ctype, body = get(server + "/")
    assert code == 200 and ctype.startswith("text/html")
    assert "SentinelOne DV 트리아지".encode() in body


def test_report_list_sorted_and_summarized(server):
    _, _, body = get(server + "/api/reports")
    items = json.loads(body)
    assert [i["id"] for i in items] == ["222", "111"]  # 최신 위협 먼저, 깨진 파일은 무시
    assert "SSH 키 등록(백도어)" in items[1]["highlights"]
    assert items[0]["error"] == "boom"


def test_report_detail_and_status(server):
    _, _, body = get(server + "/api/reports/111")
    detail = json.loads(body)
    assert detail["dv"]["behavior"]["timeline"][0]["description"].endswith("authorized_keys")
    status = json.loads(get(server + "/api/status")[2])
    assert status["monitoring"] is True and status["analyzed"] == 2


@pytest.mark.parametrize("bad", ["../../etc/passwd", "..%2F..%2Fsecret", "nope"])
def test_unknown_or_traversal_ids_404(server, bad):
    with pytest.raises(urllib.error.HTTPError) as exc:
        get(server + "/api/reports/" + bad)
    assert exc.value.code == 404


def post(url, body, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req) as r:
        return r.status, json.loads(r.read())


def test_analyze_requires_csrf_header_and_same_origin(server):
    for headers in ({}, {"X-S1Triage": "1", "Origin": "http://evil.example.com"}):
        with pytest.raises(urllib.error.HTTPError) as exc:
            post(server + "/api/analyze", {"threat_id": "111", "refresh": False}, headers)
        assert exc.value.code == 403


def test_analyze_saved_report_end_to_end(server):
    import time
    code, job = post(server + "/api/analyze", {"threat_id": "111", "refresh": False}, {"X-S1Triage": "1"})
    assert code == 202
    for _ in range(100):
        job = json.loads(get(server + "/api/jobs/" + job["id"])[2])
        if job["status"] in ("done", "error"):
            break
        time.sleep(0.05)
    assert job["status"] == "done", job
    recent = json.loads(get(server + "/api/analyses")[2])
    assert recent[0]["id"] == "111" and recent[0]["verdict"]
    detail = json.loads(get(server + "/api/analyses/111")[2])
    assert {"conclusion", "main_report", "beginner_guide", "console_note", "report"} <= set(detail)


def test_analyze_rejects_bad_input(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        post(server + "/api/analyze", {"threat_id": "../x"}, {"X-S1Triage": "1"})
    assert exc.value.code == 400
    with pytest.raises(urllib.error.HTTPError) as exc:  # 보기 전용 서버는 DV 재조회 불가
        post(server + "/api/analyze", {"threat_id": "111", "refresh": True}, {"X-S1Triage": "1"})
    assert exc.value.code == 400
