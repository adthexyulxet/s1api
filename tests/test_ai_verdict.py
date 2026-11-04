import json
from types import SimpleNamespace

import anthropic
import httpx2 as httpx
import pytest

from s1triage.ai_verdict import MAX_TIMELINE, ai_available, build_payload, get_ai_verdict
from s1triage.narrative import build_conclusion

from .test_narrative import ATTACK, report

GOOD = {
    "verdict": "정탐", "confidence": "높음", "summary": "SSH 키 백도어가 설치됐습니다.",
    "attack_narrative": "로그인 실패 후 스크립트를 내려받아 실행하고 authorized_keys 를 수정했습니다.",
    "reasoning": ["authorized_keys 수정"], "false_positive_considerations": ["관리자 키 배포 가능성"],
    "recommended_actions": ["키 삭제"], "questions_for_analyst": ["키 배포 일정이 있었나요?"],
}


class FakeMessages:
    def __init__(self, response=None, exc=None):
        self.response, self.exc, self.kwargs = response, exc, None

    def create(self, **kwargs):
        self.kwargs = kwargs
        if self.exc:
            raise self.exc
        return self.response


def fake_client(messages):
    return lambda: SimpleNamespace(beta=SimpleNamespace(messages=messages))


def response(text, stop="end_turn", details=None):
    return SimpleNamespace(stop_reason=stop, stop_details=details, model="claude-opus-5-5",
                           usage=SimpleNamespace(input_tokens=100, output_tokens=50),
                           content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=text)])


def test_success_parses_structured_output_and_sends_expected_request():
    r = report(ATTACK)
    msgs = FakeMessages(response(json.dumps(GOOD, ensure_ascii=False)))
    out = get_ai_verdict(r, build_conclusion(r), client_factory=fake_client(msgs))
    assert out["verdict"] == "정탐" and out["model"] == "claude-opus-5-5" and "error" not in out
    kw = msgs.kwargs
    assert kw["model"] == "claude-opus-5-5"
    assert kw["fallbacks"] == "default" and kw["betas"] == ["server-side-fallback-2026-07-01"]
    assert kw["output_config"]["format"]["type"] == "json_schema"
    assert kw["output_config"]["effort"] == "high"
    assert "thinking" not in kw and "temperature" not in kw
    assert "<triage_report>" in kw["messages"][0]["content"]
    assert "authorized_keys" in kw["messages"][0]["content"]


def test_refusal_and_truncation_are_reported():
    r = report(ATTACK)
    c = build_conclusion(r)
    out = get_ai_verdict(r, c, client_factory=fake_client(FakeMessages(response("", "refusal", SimpleNamespace(category="cyber")))))
    assert "거절" in out["error"] and "cyber" in out["error"]
    out = get_ai_verdict(r, c, client_factory=fake_client(FakeMessages(response("{", "max_tokens"))))
    assert "잘렸" in out["error"]


def test_api_errors_become_messages():
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    err = anthropic.AuthenticationError("bad key", response=httpx.Response(401, request=req), body=None)
    r = report(ATTACK)
    out = get_ai_verdict(r, build_conclusion(r), client_factory=fake_client(FakeMessages(exc=err)))
    assert "ANTHROPIC_API_KEY" in out["error"]
    out = get_ai_verdict(r, build_conclusion(r),
                         client_factory=fake_client(FakeMessages(exc=anthropic.APIConnectionError(request=req))))
    assert "연결" in out["error"]


def test_payload_excludes_raw_events_and_caps_timeline():
    r = report(ATTACK)
    r["raw_events"] = [{"secret": "x"}]
    r["dv"]["behavior"]["timeline"] = [{"description": str(i)} for i in range(MAX_TIMELINE + 20)]
    p = build_payload(r, build_conclusion(r))
    assert "raw_events" not in p
    assert len(p["dv"]["behavior"]["timeline"]) == MAX_TIMELINE
    assert "timeline_truncated" in p["dv"]["behavior"]


def test_ai_available_needs_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    assert not ai_available()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert ai_available()
