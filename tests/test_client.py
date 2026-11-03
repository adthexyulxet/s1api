import pytest

from s1triage.client import DvQueryTimeout, S1ApiError, S1Client

from .conftest import FakeResponse, FakeSession, threat_payload


def make_client(settings, routes, fixed_now):
    session = FakeSession(routes)
    return S1Client(settings, session=session, sleep=lambda s: None, now=fixed_now), session


def test_get_unresolved_threats(settings, fixed_now):
    client, session = make_client(settings, {
        ("GET", "/threats"): FakeResponse(200, {"data": [threat_payload("1"), threat_payload("2", storyline=None)]}),
    }, fixed_now)
    threats = client.get_unresolved_threats()
    assert [t.threat_id for t in threats] == ["1", "2"]
    assert threats[0].storyline_id == "SL-1"
    assert threats[0].agent_name == "PC-01"
    assert threats[1].storyline_id is None
    params = session.calls[0][2]["params"]
    assert params["resolved"] == "false" and params["sortOrder"] == "desc"


def test_http_error_raises(settings, fixed_now):
    client, _ = make_client(settings, {("GET", "/threats"): FakeResponse(401, {"errors": ["bad token"]})}, fixed_now)
    with pytest.raises(S1ApiError) as exc:
        client.get_unresolved_threats()
    assert exc.value.status_code == 401


def test_storyline_events_full_flow_with_pagination(settings, fixed_now):
    client, session = make_client(settings, {
        ("POST", "/dv/init-query"): FakeResponse(200, {"data": {"queryId": "q1"}}),
        ("GET", "/dv/query-status"): [
            FakeResponse(200, {"data": {"responseState": "RUNNING", "progressStatus": 50}}),
            FakeResponse(200, {"data": {"responseState": "FINISHED", "progressStatus": 100}}),
        ],
        ("GET", "/dv/events"): [
            FakeResponse(200, {"data": [{"id": 1}, {"id": 2}], "pagination": {"nextCursor": "c2"}}),
            FakeResponse(200, {"data": [{"id": 3}], "pagination": {"nextCursor": None}}),
        ],
    }, fixed_now)
    progress = []
    events = client.get_storyline_events("SL-1", "2026-11-03T11:00:00.000Z", on_progress=progress.append)
    assert [e["id"] for e in events] == [1, 2, 3]
    assert progress == [50, 100]

    init = next(c for c in session.calls if c[0] == "POST")
    assert init[2]["json"]["query"] == 'storyline = "SL-1"'
    assert init[2]["json"]["fromDate"] == "2026-11-02T11:00:00.000Z"
    assert init[2]["json"]["toDate"] == "2026-11-03T12:00:00.000Z"
    event_calls = [c for c in session.calls if c[1].endswith("/dv/events")]
    assert "cursor" not in event_calls[0][2]["params"]
    assert event_calls[1][2]["params"]["cursor"] == "c2"


def test_dv_max_events_caps_pagination(settings, fixed_now):
    from dataclasses import replace
    s = replace(settings, dv_max_events=2)
    client, session = make_client(s, {
        ("GET", "/dv/events"): FakeResponse(200, {"data": [{"id": 1}, {"id": 2}], "pagination": {"nextCursor": "more"}}),
    }, fixed_now)
    assert len(list(client.iter_dv_events("q"))) == 2
    assert len(session.calls) == 1


def test_legacy_is_finished_flag(settings, fixed_now):
    client, _ = make_client(settings, {
        ("GET", "/dv/query-status"): FakeResponse(200, {"data": {"isFinished": True, "progressPercentage": 100}}),
    }, fixed_now)
    client.wait_dv_query("q")


def test_dv_query_failed_and_timeout(settings, fixed_now):
    client, _ = make_client(settings, {
        ("GET", "/dv/query-status"): FakeResponse(200, {"data": {"responseState": "FAILED", "responseError": "bad"}}),
    }, fixed_now)
    with pytest.raises(S1ApiError):
        client.wait_dv_query("q")

    client, _ = make_client(settings, {
        ("GET", "/dv/query-status"): FakeResponse(200, {"data": {"responseState": "RUNNING", "progressStatus": 10}}),
    }, fixed_now)
    with pytest.raises(DvQueryTimeout):
        client.wait_dv_query("q")


def test_query_escapes_quotes(settings, fixed_now):
    client, _ = make_client(settings, {}, fixed_now)
    assert client.build_storyline_query('a"b') == 'storyline = "a\\"b"'


def test_429_waits_and_retries(settings, fixed_now):
    session = FakeSession({
        ("POST", "/dv/init-query"): [
            FakeResponse(429, {}),
            FakeResponse(429, {}),
            FakeResponse(200, {"data": {"queryId": "q1"}}),
        ],
    })
    sleeps = []
    client = S1Client(settings, session=session, sleep=sleeps.append, now=fixed_now)
    assert client.init_dv_query("x", fixed_now(), fixed_now()) == "q1"
    assert sleeps == [15, 30]


def test_429_gives_up_after_retries_and_strips_html(settings, fixed_now):
    from dataclasses import replace
    s = replace(settings, rate_limit_retries=1)
    resp = FakeResponse(429, {})
    resp.text = "<html><head><title>429 Too Many Requests</title></head><body>nginx</body></html>"
    client = S1Client(s, session=FakeSession({("GET", "/threats"): resp}), sleep=lambda x: None, now=fixed_now)
    with pytest.raises(S1ApiError) as exc:
        client.get_unresolved_threats()
    assert exc.value.status_code == 429
    assert "<html>" not in str(exc.value) and "429 Too Many Requests" in str(exc.value)


def test_retry_after_header_respected(settings, fixed_now):
    resp = FakeResponse(429, {})
    resp.headers = {"Retry-After": "7"}
    assert S1Client._retry_after(resp, 0) == 7
    assert S1Client._retry_after(FakeResponse(429, {}), 5) == 120


def test_dv_queries_are_spaced(settings, fixed_now):
    session = FakeSession({("POST", "/dv/init-query"): FakeResponse(200, {"data": {"queryId": "q"}})})
    sleeps = []
    client = S1Client(settings, session=session, sleep=sleeps.append, now=fixed_now)
    t = [100.0]
    client._clock = lambda: t[0]
    client.init_dv_query("a", fixed_now(), fixed_now())
    t[0] += 3
    client.init_dv_query("b", fixed_now(), fixed_now())
    assert sleeps == [settings.dv_min_interval - 3]
