import json
from datetime import datetime, timezone

import pytest

from s1triage.config import Settings


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = json.dumps(self._payload)

    def json(self):
        return self._payload


class FakeSession:
    """(method, path 접미사) -> 응답 목록 을 순서대로 돌려주는 가짜 세션."""

    def __init__(self, routes):
        self.routes = {k: list(v) if isinstance(v, list) else [v] for k, v in routes.items()}
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        for (m, suffix), responses in self.routes.items():
            if m == method and url.split("?")[0].endswith(suffix):
                return responses.pop(0) if len(responses) > 1 else responses[0]
        raise AssertionError(f"예상치 못한 요청: {method} {url}")

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)


@pytest.fixture
def settings():
    return Settings(
        api_url="https://example.sentinelone.net/web/api/v2.1",
        api_token="test-token",
        dv_poll_seconds=1,
        dv_timeout_seconds=5,
        state_file="",
    )


@pytest.fixture
def fixed_now():
    return lambda: datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)


def threat_payload(tid, storyline="SL-1", created="2026-11-03T11:00:00.000000Z"):
    return {
        "id": tid,
        "createdAt": created,
        "threatInfo": {
            "threatName": f"evil-{tid}.exe",
            "storyline": storyline,
            "classification": "Malware",
            "confidenceLevel": "malicious",
            "sha1": "a" * 40,
        },
        "agentRealtimeInfo": {"agentId": "agent-1", "agentComputerName": "PC-01"},
    }
