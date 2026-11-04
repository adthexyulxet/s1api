"""정밀 분석 산출물 생성.

트리아지 리포트(dict, TriageReport.to_dict() 형식)를 받아 다음을 만듭니다.
- 결론 요약: 정탐/오탐 추정, 근본원인, 킬체인(MITRE ATT&CK 전술), 핵심 IOC, 후속 조치
- 메인 보고서 / 초보자용 해설서 / 콘솔 Notes 붙여넣기 초안 (텍스트)

규칙 기반 추정이므로 최종 판정은 분석가가 확인해야 합니다.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# MITRE ATT&CK 기법 → 전술(킬체인 단계)
TACTIC_ORDER = [
    "초기 침투", "실행", "지속성", "권한 상승", "방어 회피", "인증정보 접근",
    "탐색", "측면 이동", "수집", "명령제어(C2)", "유출", "영향",
]
TECHNIQUE_TACTIC = {
    "T1190": "초기 침투", "T1133": "초기 침투", "T1078": "초기 침투", "T1566": "초기 침투",
    "T1059": "실행", "T1204": "실행", "T1047": "실행", "T1569": "실행", "T1053": "지속성",
    "T1098": "지속성", "T1136": "지속성", "T1543": "지속성", "T1546": "지속성", "T1547": "지속성",
    "T1574": "지속성", "T1197": "방어 회피",
    "T1548": "권한 상승", "T1055": "방어 회피",
    "T1070": "방어 회피", "T1027": "방어 회피", "T1562": "방어 회피", "T1564": "방어 회피",
    "T1218": "방어 회피", "T1222": "방어 회피",
    "T1003": "인증정보 접근", "T1110": "인증정보 접근",
    "T1033": "탐색", "T1082": "탐색", "T1016": "탐색", "T1087": "탐색",
    "T1021": "측면 이동", "T1074": "수집",
    "T1105": "명령제어(C2)", "T1071": "명령제어(C2)", "T1095": "명령제어(C2)", "T1571": "명령제어(C2)",
    "T1041": "유출", "T1490": "영향", "T1486": "영향",
}

# 태그 이름 키워드 → 후속 조치
ACTION_RULES: List[Tuple[str, str]] = [
    ("복구 기능 무력화", "랜섬웨어 의심: 엔드포인트를 즉시 네트워크 격리하고 백업 상태를 확인하세요."),
    ("LSASS", "인증정보 탈취 의심: 해당 호스트에 로그인했던 계정의 비밀번호를 재설정하고 엔드포인트 격리를 검토하세요."),
    ("리버스 셸", "원격 제어 의심: 연결 대상 IP 를 방화벽에서 차단하고 엔드포인트 격리를 검토하세요."),
    ("의심 포트", "연결 대상 IP/포트를 방화벽에서 차단하고 다른 호스트에서도 같은 목적지로 통신했는지 조회하세요."),
    ("SSH 키", "~/.ssh/authorized_keys 내용을 확인해 승인되지 않은 키를 삭제하고 해당 계정 비밀번호를 변경하세요."),
    ("계정", "계정 목록과 sudoers 를 이전 상태와 비교해 승인되지 않은 계정/권한을 비활성화하세요."),
    ("cron", "crontab 및 /etc/cron* 에 등록된 항목을 확인하고 승인되지 않은 작업을 제거하세요."),
    ("예약 작업", "예약 작업 목록을 확인하고 승인되지 않은 작업을 제거하세요."),
    ("서비스", "새로 생성/변경된 서비스(systemd, Windows 서비스)를 확인하고 승인되지 않은 항목을 제거하세요."),
    ("셸 시작 스크립트", ".bashrc/.profile 등에 추가된 명령을 확인하고 제거하세요."),
    ("자동 실행", "Run/RunOnce 등 자동 실행 레지스트리 값을 확인하고 승인되지 않은 항목을 제거하세요."),
    ("시작프로그램", "시작프로그램 폴더에 추가된 파일을 확인하고 제거하세요."),
    ("라이브러리 하이재킹", "/etc/ld.so.preload 내용을 확인하고 루트킷 여부를 점검하세요."),
    ("다운로드", "다운로드한 URL/파일을 확보해 해시를 위협 인텔리전스로 조회하고, 해당 도메인을 차단하세요."),
    ("흔적", "로컬 로그가 변조됐을 수 있으니 SIEM 등 외부에 수집된 원본 로그로 행위를 다시 확인하세요."),
    ("로그인 실패", "출발지 IP 를 차단하고 계정 잠금 정책과 같은 IP 의 다른 로그인 시도를 확인하세요."),
    ("보안 제품", "보안 제품 설정 변경 이력을 확인하고 원래 설정으로 복구하세요."),
    ("정찰", "정찰 명령을 실행한 세션(사용자, 출발지)을 확인해 정상 관리 작업인지 담당자에게 확인하세요."),
    ("임시 폴더", "임시 폴더의 실행 파일을 확보해 해시를 조회하고, 출처(다운로드 경로)를 확인하세요."),
]

IOC_LABELS = {"ips": "외부 IP", "domains": "도메인", "sha256": "SHA256", "sha1": "SHA1", "md5": "MD5"}

GLOSSARY = [
    ("Storyline", "SentinelOne 이 하나의 행위 흐름(부모·자식 프로세스와 그들이 한 일)에 붙이는 ID 입니다. 같은 Storyline 의 이벤트는 한 사건으로 묶어 볼 수 있습니다."),
    ("Deep Visibility(DV)", "엔드포인트에서 일어난 프로세스·파일·네트워크·레지스트리 활동의 원본 기록입니다. 이번 분석의 근거 데이터입니다."),
    ("MITRE ATT&CK", "공격자가 쓰는 기법을 정리한 표준 분류입니다. T1059 같은 번호로 기법을 가리킵니다."),
    ("킬체인", "공격이 침투 → 실행 → 지속성 확보 → … → 목적 달성으로 진행되는 단계입니다. 어느 단계까지 진행됐는지 보면 심각도를 가늠할 수 있습니다."),
    ("IOC", "침해 지표. 악성 IP, 도메인, 파일 해시처럼 다른 곳에서 같은 공격을 찾는 데 쓰는 값입니다."),
    ("정탐 / 오탐", "정탐(True Positive)은 실제 위협을 맞게 탐지한 것, 오탐(False Positive)은 정상 행위를 위협으로 잘못 탐지한 것입니다."),
]


def _tactics_for(technique: str) -> List[str]:
    out = []
    for tid in re.findall(r"T\d{4}", technique or ""):
        tactic = TECHNIQUE_TACTIC.get(tid)
        if tactic and tactic not in out:
            out.append(tactic)
    return out


def build_conclusion(report: Dict[str, Any]) -> Dict[str, Any]:
    threat = report.get("threat") or {}
    dv = report.get("dv") or {}
    behavior = dv.get("behavior") or {}
    highlights = behavior.get("highlights") or []
    findings = dv.get("findings") or []
    ti = report.get("threat_intel") or []
    risk = report.get("risk") or {}
    score = int(risk.get("score") or 0)
    event_count = dv.get("event_count") or 0
    malicious_ti = [v for v in ti if v.get("malicious")]
    max_weight = max([int(h.get("weight") or 0) for h in highlights] or [0])

    reasons: List[str] = []
    if report.get("error") and not dv:
        verdict, confidence = "판단 보류", "낮음"
        reasons.append(f"DV 조회에 실패했습니다: {report.get('error')}")
    elif not event_count:
        verdict, confidence = "판단 보류", "낮음"
        reasons.append("Storyline 에 해당하는 DV 이벤트가 없어 행위 근거가 부족합니다. 인덱싱 지연이면 잠시 후 다시 분석하세요.")
    elif max_weight >= 4 or malicious_ti or score >= 10:
        verdict, confidence = "정탐 가능성 높음", "높음" if (max_weight >= 4 and (malicious_ti or score >= 10)) else "중간"
        if max_weight >= 4:
            reasons.append("고위험 행위가 확인됐습니다: " + ", ".join(h["name"] for h in highlights if int(h.get("weight") or 0) >= 4))
        if malicious_ti:
            reasons.append("위협 인텔리전스에서 악성으로 판정된 IOC: " + ", ".join(v.get("value", "") for v in malicious_ti[:5]))
        if score >= 10:
            reasons.append(f"위험 점수 {score} 로 HIGH 등급입니다.")
    elif highlights or findings or score >= 4:
        verdict, confidence = "추가 확인 필요", "중간"
        if highlights:
            reasons.append("주의가 필요한 행위: " + ", ".join(h["name"] for h in highlights[:5]))
        if findings:
            reasons.append("의심 프로세스/명령줄: " + ", ".join(sorted({f.get('category', '') for f in findings}))[:200])
        reasons.append("단독으로는 악성이라 단정하기 어려워 담당자 확인이 필요합니다.")
    else:
        verdict, confidence = "오탐 가능성 높음", "중간"
        reasons.append("수집된 행위 중 알려진 공격 패턴(지속성, 계정 조작, 다운로드·실행, 흔적 삭제 등)에 해당하는 것이 없습니다.")
        if (threat.get("confidence_level") or "").lower() == "suspicious":
            reasons.append("콘솔 신뢰도도 malicious 가 아닌 suspicious 입니다.")

    # 킬체인
    chain: "OrderedDict[str, List[str]]" = OrderedDict((t, []) for t in TACTIC_ORDER)
    for h in highlights:
        for tactic in _tactics_for(h.get("technique", "")):
            label = f"{h['name']} ({h.get('technique')})"
            if label not in chain[tactic]:
                chain[tactic].append(label)
    for f in findings:
        for tactic in _tactics_for(f.get("technique", "")):
            label = f"{f.get('category')} ({f.get('technique')})"
            if label not in chain[tactic]:
                chain[tactic].append(label)
    kill_chain = [{"tactic": t, "items": items} for t, items in chain.items() if items]

    # 근본원인 (최초 행위 + 주체)
    timeline = behavior.get("timeline") or []
    summary = behavior.get("summary") or []
    root = []
    if summary:
        root.append(summary[0])
    if timeline:
        root.append(f"가장 먼저 기록된 행위: {timeline[0].get('description')}")
        risky = next((t for t in timeline if t.get("tags")), None)
        if risky and risky is not timeline[0]:
            root.append(f"처음으로 위험 행위가 나타난 지점: {risky.get('description')}")
    if threat.get("name"):
        root.append(f"SentinelOne 탐지 대상: {threat.get('name')} (분류 {threat.get('classification') or '-'}, 신뢰도 {threat.get('confidence_level') or '-'})")

    # 후속 조치
    actions: List[str] = []
    names = " ".join(h.get("name", "") for h in highlights)
    for key, action in ACTION_RULES:
        if key in names and action not in actions:
            actions.append(action)
    if verdict == "정탐 가능성 높음":
        actions.insert(0, "콘솔에서 위협을 Mitigate(Kill/Quarantine) 하고, 확산 우려가 있으면 엔드포인트 네트워크 격리를 검토하세요.")
    elif verdict == "오탐 가능성 높음":
        actions.append("담당자 확인 후 위협을 False Positive 로 처리하고, 같은 탐지가 반복되면 예외(Exclusion) 등록을 검토하세요.")
    elif verdict == "판단 보류":
        actions.append("잠시 후 다시 정밀 분석을 실행하거나, 콘솔에서 Storyline 을 직접 확인하세요.")
    else:
        actions.append("해당 호스트 담당자에게 행위 시각의 작업 내역(배포, 관리 작업 등)을 확인하세요.")

    iocs = dv.get("iocs") or {}
    key_iocs = {k: v[:10] for k, v in iocs.items() if v}

    return {
        "verdict": verdict,
        "confidence": confidence,
        "risk": risk,
        "reasons": reasons,
        "root_cause": root,
        "kill_chain": kill_chain,
        "key_iocs": key_iocs,
        "actions": actions,
        "disclaimer": "규칙 기반 자동 추정입니다. 최종 판정은 분석가가 근거를 확인한 뒤 결정하세요.",
    }


# ------------------------------------------------------------ 텍스트 산출물
def _bullets(items: List[str], prefix: str = "- ") -> List[str]:
    return [prefix + s for s in items] if items else [prefix + "(없음)"]


def _threat_lines(t: Dict[str, Any]) -> List[str]:
    return [
        f"- 위협: {t.get('name') or '-'} (ID {t.get('id') or '-'})",
        f"- 엔드포인트: {t.get('agent_name') or '-'} ({t.get('agent_id') or '-'})",
        f"- 분류/신뢰도: {t.get('classification') or '-'} / {t.get('confidence_level') or '-'}",
        f"- 탐지 시각: {t.get('created_at') or '-'}",
        f"- Storyline: {t.get('storyline_id') or '-'}",
    ]


def build_main_report(report: Dict[str, Any], c: Dict[str, Any]) -> str:
    t = report.get("threat") or {}
    dv = report.get("dv") or {}
    b = dv.get("behavior") or {}
    lines = ["# 정밀 분석 보고서", "", f"판정(추정): {c['verdict']} · 신뢰도 {c['confidence']} · 위험도 {c['risk'].get('level', '-')} ({c['risk'].get('score', 0)}점)", ""]
    lines += ["## 1. 위협 정보"] + _threat_lines(t) + [""]
    lines += ["## 2. 판정 근거"] + _bullets(c["reasons"]) + [""]
    lines += ["## 3. 근본원인 요약"] + _bullets(c["root_cause"]) + [""]
    lines += ["## 4. 킬체인"]
    lines += [f"- {k['tactic']}: {', '.join(k['items'])}" for k in c["kill_chain"]] or ["- 해당 단계 없음"]
    lines += [""]
    lines += ["## 5. 행위 요약"] + _bullets(b.get("summary") or []) + [""]
    hl = b.get("highlights") or []
    if hl:
        lines += ["## 6. 주목할 행위"]
        for h in hl:
            lines.append(f"- {h['name']} [{h.get('technique')}]: {h.get('meaning')}")
            lines += [f"    근거: {ex}" for ex in h.get("examples") or []]
        lines += [""]
    tl = b.get("timeline") or []
    lines += [f"## 7. 행위 타임라인 ({len(tl)})"]
    for i in tl:
        cnt = f" ×{i['count']}" if i.get("count", 1) > 1 else ""
        mark = " ⚠" if i.get("tags") else ""
        lines.append(f"- {i.get('time') or '-'}  {i.get('description')}{cnt}{mark}")
    if not tl:
        lines.append("- (행위 없음)")
    lines += ["", "## 8. IOC"]
    if c["key_iocs"]:
        for k, v in c["key_iocs"].items():
            lines.append(f"- {IOC_LABELS.get(k, k)}: {', '.join(v)}")
    else:
        lines.append("- 추출된 IOC 없음")
    ti = report.get("threat_intel") or []
    if ti:
        lines += ["", "## 9. 위협 인텔리전스"]
        lines += [f"- {'[악성] ' if v.get('malicious') else ''}{v.get('source')} {v.get('ioc_type')} {v.get('value')}: {v.get('summary')}" for v in ti]
    lines += ["", "## 후속 조치"] + _bullets(c["actions"])
    lines += ["", f"※ {c['disclaimer']}"]
    return "\n".join(lines)


def build_beginner_guide(report: Dict[str, Any], c: Dict[str, Any]) -> str:
    t = report.get("threat") or {}
    dv = report.get("dv") or {}
    b = dv.get("behavior") or {}
    hl = b.get("highlights") or []
    lines = ["# 초보자용 해설서", ""]
    lines += ["## 한 줄 요약"]
    host = t.get("agent_name") or "해당 엔드포인트"
    if c["verdict"] == "정탐 가능성 높음":
        lines.append(f"{host} 에서 실제 공격으로 보이는 행위가 확인됐습니다. 빠른 대응이 필요합니다.")
    elif c["verdict"] == "오탐 가능성 높음":
        lines.append(f"{host} 의 탐지는 정상 프로그램 동작일 가능성이 높습니다. 담당자 확인 후 종료하면 됩니다.")
    elif c["verdict"] == "판단 보류":
        lines.append("판단에 필요한 행위 기록이 부족합니다. 잠시 후 다시 분석해 보세요.")
    else:
        lines.append(f"{host} 에서 주의가 필요한 행위가 있지만 악성이라 단정하기는 어렵습니다. 아래 내용을 확인해 보세요.")
    lines += ["", "## 무슨 일이 있었나요?"]
    lines.append(f"SentinelOne 이 '{t.get('name') or '?'}' 를 위협으로 탐지했고, 이 프로그램은 그 행위 흐름(Storyline)에서 일어난 일을 Deep Visibility 기록으로 다시 조회했습니다.")
    lines += _bullets(b.get("summary") or [])
    lines += ["", "## 시간 순서로 보면"]
    tl = b.get("timeline") or []
    for n, i in enumerate(tl[:10], 1):
        lines.append(f"{n}. {i.get('description')}" + (" ← 주의" if i.get("tags") else ""))
    if len(tl) > 10:
        lines.append(f"... 외 {len(tl) - 10}건은 메인 보고서를 참고하세요.")
    if not tl:
        lines.append("(기록된 행위가 없습니다)")
    lines += ["", "## 왜 위험한가요?"]
    if hl:
        for h in hl:
            lines.append(f"- {h['name']}: {h.get('meaning')}")
    else:
        lines.append("- 알려진 공격 패턴에 해당하는 행위는 보이지 않았습니다. 위험 점수가 낮은 이유입니다.")
    if c["kill_chain"]:
        lines += ["", "## 공격이 어디까지 진행됐나요? (킬체인)"]
        lines.append("공격은 보통 아래 순서로 진행됩니다. 이번 사건에서 확인된 단계만 표시합니다.")
        lines += [f"- {k['tactic']}: {', '.join(k['items'])}" for k in c["kill_chain"]]
    lines += ["", "## 이제 무엇을 하면 되나요?"]
    lines += [f"{n}. {a}" for n, a in enumerate(c["actions"], 1)]
    lines += ["", "## 용어 설명"]
    lines += [f"- {term}: {desc}" for term, desc in GLOSSARY]
    lines += ["", f"※ {c['disclaimer']}"]
    return "\n".join(lines)


def build_console_note(report: Dict[str, Any], c: Dict[str, Any], max_len: int = 1800) -> str:
    t = report.get("threat") or {}
    hl = ((report.get("dv") or {}).get("behavior") or {}).get("highlights") or []
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"[자동 트리아지 {date}] 판정(추정): {c['verdict']} / 신뢰도 {c['confidence']} / 위험도 {c['risk'].get('level', '-')}({c['risk'].get('score', 0)})",
        "근거:",
    ]
    lines += [f"- {r}" for r in c["reasons"][:4]]
    if hl:
        lines.append("주요 행위: " + "; ".join(f"{h['name']}({h.get('technique')})" for h in hl[:5]))
    if c["kill_chain"]:
        lines.append("킬체인: " + " → ".join(k["tactic"] for k in c["kill_chain"]))
    if c["key_iocs"]:
        lines.append("IOC: " + "; ".join(f"{IOC_LABELS.get(k, k)} {', '.join(v[:3])}" for k, v in c["key_iocs"].items()))
    lines.append("조치 권고:")
    lines += [f"- {a}" for a in c["actions"][:4]]
    lines.append(f"(Storyline {t.get('storyline_id') or '-'}, 분석가 확인 필요)")
    text = "\n".join(lines)
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


def build_outputs(report: Dict[str, Any]) -> Dict[str, Any]:
    conclusion = build_conclusion(report)
    return {
        "conclusion": conclusion,
        "main_report": build_main_report(report, conclusion),
        "beginner_guide": build_beginner_guide(report, conclusion),
        "console_note": build_console_note(report, conclusion),
    }
