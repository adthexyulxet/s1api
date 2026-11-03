"""행위 기반 분석: DV 이벤트를 "누가 무엇을 했는지" 한국어 문장으로 풀어 설명합니다.

규칙 기반이라 외부 서비스 없이 동작합니다.
1) 이벤트 유형별로 행위 문장을 만들고 (예: "[sshd] 파일 수정: /etc/passwd")
2) 대상 경로/명령줄/포트 등을 보고 위험 행위 태그와 그 의미를 붙이고
3) 같은 행위는 묶어서 시간순 타임라인과 전체 요약을 만듭니다.
"""

from __future__ import annotations

import re
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .analyzer import CMDLINE_KEYS, PROCESS_NAME_KEYS, first_of, normalize_process_name

ACTOR_KEYS = ("srcProcName", "srcProcessName", "processName")
ACTOR_CMD_KEYS = ("srcProcCmdLine", "srcProcessCmdLine", "processCmd", "cmdLine")
ACTOR_PARENT_KEYS = ("srcProcParentName", "parentProcessName")
ACTOR_USER_KEYS = ("srcProcUser", "user", "processUserName")
CHILD_KEYS = ("tgtProcName", "tgtProcessName")
CHILD_CMD_KEYS = ("tgtProcCmdLine", "tgtProcessCmdLine")
FILE_KEYS = ("tgtFilePath", "fileFullName", "filePath", "tgtFileName")
FILE_OLD_KEYS = ("tgtFileOldPath", "oldFileName", "fileOldPath")
REG_KEYS = ("registryPath", "registryKeyPath", "regKeyPath")
REG_VALUE_KEYS = ("registryValue", "registryValueName")
DST_IP_KEYS = ("dstIp", "networkDestinationIp")
DST_PORT_KEYS = ("dstPort", "networkDestinationPort")
SRC_IP_KEYS = ("srcIp", "networkSourceIp")
SRC_PORT_KEYS = ("srcPort", "networkSourcePort")
DNS_KEYS = ("dnsRequest",)
DNS_RESP_KEYS = ("dnsResponse",)
URL_KEYS = ("networkUrl", "url", "tgtUrl")
TASK_KEYS = ("taskName", "scheduledTaskName", "taskPath")
LOGIN_USER_KEYS = ("loginsUserName", "loginAccountName", "user")
INDICATOR_NAME_KEYS = ("indicatorName", "behavioralIndicatorName")
INDICATOR_DESC_KEYS = ("indicatorDescription",)
INDICATOR_CAT_KEYS = ("indicatorCategory",)
TIME_KEYS = ("eventTime", "createdAt")
TYPE_KEYS = ("eventType", "objectType")
UNKNOWN_ACTOR = "알 수 없는 프로세스"


@dataclass(frozen=True)
class Tag:
    name: str
    meaning: str
    technique: str
    weight: int


@dataclass
class Behavior:
    time: Optional[str]
    event_type: str
    actor: str
    sentence: str
    tags: List[Tag] = field(default_factory=list)
    count: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "time": self.time,
            "event_type": self.event_type,
            "actor": self.actor,
            "description": self.sentence,
            "count": self.count,
            "tags": [{"name": t.name, "meaning": t.meaning, "technique": t.technique} for t in self.tags],
        }


@dataclass
class BehaviorAnalysis:
    summary: List[str]
    timeline: List[Behavior]
    highlights: List[Tuple[Tag, List[str]]]  # (태그, 예시 문장들)

    @property
    def score(self) -> int:
        return sum(tag.weight for tag, _ in self.highlights)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "highlights": [
                {"name": t.name, "meaning": t.meaning, "technique": t.technique, "examples": ex}
                for t, ex in self.highlights
            ],
            "timeline": [b.to_dict() for b in self.timeline],
        }


# ---------------------------------------------------------------- 태그 규칙
TAG_LOG_NAME_LITERAL = "로그/흔적 변경"


def _t(name, meaning, technique, weight):
    return Tag(name, meaning, technique, weight)


# (정규식, 태그): 파일 경로에 적용
PATH_RULES: List[Tuple[re.Pattern, Tag]] = [
    (re.compile(r"/\.ssh/authorized_keys2?$", re.I), _t("SSH 키 등록(백도어)", "공격자가 자신의 SSH 공개키를 넣어 비밀번호 없이 다시 접속할 수 있게 만드는 대표적인 지속성 수법입니다.", "T1098.004", 4)),
    (re.compile(r"^/etc/(passwd|shadow|group|gshadow)$|^/etc/sudoers(\.d/.*)?$", re.I), _t("계정/권한 파일 변경", "계정 추가, 비밀번호 변경, sudo 권한 부여 등에 쓰이는 파일입니다. 정상 관리 작업이 아니라면 계정 조작이나 권한 상승 시도입니다.", "T1136 / T1548.003", 4)),
    (re.compile(r"^/etc/cron|^/var/spool/cron|/etc/anacrontab", re.I), _t("예약 작업(cron) 등록", "주기적으로 명령을 실행하도록 등록하는 것으로, 재부팅 후에도 악성 코드를 계속 실행하는 지속성 수법입니다.", "T1053.003", 3)),
    (re.compile(r"^/(etc|lib|usr/lib)/systemd/system/|/\.config/systemd/user/|^/etc/init\.d/|^/etc/rc\.local$", re.I), _t("서비스/부팅 스크립트 등록", "시스템 시작 시 자동 실행되는 서비스나 스크립트를 만들거나 바꾼 것입니다. 지속성 확보에 자주 쓰입니다.", "T1543.002", 3)),
    (re.compile(r"/\.(bashrc|bash_profile|profile|zshrc)$|^/etc/profile(\.d/.*)?$|^/etc/bash\.bashrc$", re.I), _t("셸 시작 스크립트 변경", "사용자가 로그인하거나 셸을 열 때마다 실행되는 파일입니다. 여기에 명령을 넣으면 접속할 때마다 악성 코드가 실행됩니다.", "T1546.004", 3)),
    (re.compile(r"^/etc/ld\.so\.preload$", re.I), _t("라이브러리 하이재킹", "모든 프로세스에 공격자 라이브러리를 강제로 로드시키는 설정으로, 루트킷이 주로 사용합니다.", "T1574.006", 4)),
    (re.compile(r"^/var/log/|/\.bash_history$|/(wtmp|btmp|lastlog)$", re.I), _t(TAG_LOG_NAME_LITERAL, "셸이나 일반 도구로 시스템 로그·명령 기록을 지우거나 고쳤습니다. 흔적 지우기 시도일 수 있습니다.", "T1070.002", 2)),
    (re.compile(r"^/(tmp|dev/shm|var/tmp)/|\\(appdata\\local\\temp|windows\\temp)\\", re.I), _t("임시 폴더 사용", "임시 폴더는 누구나 쓸 수 있어 악성 파일을 내려받아 실행하는 위치로 자주 쓰입니다.", "T1074.001", 1)),
    (re.compile(r"\\start menu\\programs\\startup\\", re.I), _t("시작프로그램 등록", "Windows 로그인 시 자동 실행되는 폴더입니다. 지속성 확보 수법입니다.", "T1547.001", 3)),
    (re.compile(r"\\windows\\system32\\tasks\\", re.I), _t("예약 작업 등록", "Windows 예약 작업 파일입니다. 주기적/부팅 시 실행을 위한 지속성 수법입니다.", "T1053.005", 3)),
]

REGISTRY_RULES: List[Tuple[re.Pattern, Tag]] = [
    (re.compile(r"\\currentversion\\(run|runonce|runservices)\b", re.I), _t("자동 실행 레지스트리 등록", "로그인/부팅 시 프로그램을 자동 실행하도록 등록하는 대표적인 지속성 수법입니다.", "T1547.001", 3)),
    (re.compile(r"\\currentcontrolset\\services\\", re.I), _t("서비스 레지스트리 변경", "서비스를 새로 만들거나 실행 경로를 바꿔 지속성이나 권한 상승에 이용할 수 있습니다.", "T1543.003", 3)),
    (re.compile(r"\\winlogon\\(shell|userinit)|\\image file execution options\\", re.I), _t("실행 흐름 하이재킹", "로그인 셸이나 특정 프로그램 실행 시 다른 프로그램이 대신 실행되도록 바꾸는 설정입니다.", "T1546.012", 4)),
    (re.compile(r"\\windows defender\\|\\policies\\microsoft\\windows defender", re.I), _t("보안 제품 설정 변경", "백신/보안 설정을 끄거나 예외를 추가하는 방어 회피 행위일 수 있습니다.", "T1562.001", 4)),
]

CMD_RULES: List[Tuple[re.Pattern, Tag]] = [
    (re.compile(r"\b(curl|wget)\b.*https?://|invoke-webrequest|downloadstring|downloadfile|certutil.*-urlcache|bitsadmin.*/transfer", re.I), _t("외부 파일 다운로드", "명령줄로 외부에서 파일을 내려받았습니다. 추가 악성 도구를 들여오는 단계일 수 있습니다.", "T1105", 2)),
    (re.compile(r"\|\s*(ba)?sh\b|\|\s*python[23]?\b|\biex\b", re.I), _t("다운로드 즉시 실행", "내려받은 내용을 파일로 저장하지 않고 바로 실행하는 패턴으로, 공격에서 흔히 쓰입니다.", "T1059", 3)),
    (re.compile(r"^\s*(\S*[\\/])?(whoami|id|hostname|uname|ipconfig|ifconfig|systeminfo|netstat|arp|nltest|quser)(\.exe)?(\s|$)|\bnet(\.exe)?\s+(user|group|localgroup|view|share)\b|cat\s+/etc/(passwd|shadow)", re.I), _t("시스템/계정 정찰", "현재 사용자, 호스트, 네트워크, 계정 정보를 확인하는 명령입니다. 침투 직후 환경을 파악하는 단계에서 자주 보입니다.", "T1033 / T1082", 1)),
    (re.compile(r"\b(nc|ncat|netcat)\b.*\s-(e|c)\s|/dev/tcp/|bash\s+-i\s*>&|socat\s.*exec", re.I), _t("리버스 셸", "외부 서버로 셸을 연결해 원격에서 명령을 내릴 수 있게 하는 패턴입니다.", "T1059.004", 4)),
    (re.compile(r"\bchmod\s+(\+x|[0-7]*7[0-7]{0,2})\s+/(tmp|dev/shm|var/tmp)/", re.I), _t("임시 폴더 파일에 실행 권한 부여", "내려받은 파일을 실행하려고 권한을 바꾸는 흔한 단계입니다.", "T1222.002", 2)),
    (re.compile(r"\b(useradd|adduser|usermod|passwd)\b|\bnet(\.exe)?\s+user\s+\S+\s+\S+\s+/add", re.I), _t("계정 생성/변경 명령", "새 계정을 만들거나 기존 계정을 바꾸는 명령입니다.", "T1136", 3)),
    (re.compile(r"\b(history\s+-c|shred|wevtutil\s+cl|clear-eventlog)\b|rm\s+-[rf]+\s+/var/log", re.I), _t("흔적 삭제 명령", "명령 기록이나 이벤트 로그를 지우는 명령입니다.", "T1070", 3)),
    (re.compile(r"vssadmin.*delete\s+shadows|wbadmin.*delete|bcdedit.*recoveryenabled\s+no", re.I), _t("복구 기능 무력화", "백업/섀도 복사본을 삭제하는 것으로 랜섬웨어 실행 직전에 자주 보입니다.", "T1490", 4)),
    (re.compile(r"\s-(e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", re.I), _t("인코딩된 명령", "명령을 Base64 로 숨겨 실행했습니다. 탐지를 피하려는 목적이 흔합니다.", "T1027", 3)),
]

SUSPICIOUS_PORTS = {
    4444: "Metasploit 기본 포트", 1337: "공격 도구에서 흔한 포트", 31337: "공격 도구에서 흔한 포트",
    6667: "IRC(봇넷 C2에 자주 사용)", 9001: "Tor", 9050: "Tor",
}
LATERAL_PORTS = {22: "SSH", 23: "Telnet", 445: "SMB", 135: "RPC", 3389: "RDP", 5985: "WinRM", 5986: "WinRM"}

TAG_OUTBOUND_SUSPICIOUS = lambda port, desc: _t("의심 포트로 외부 통신", f"{port}번 포트({desc})로 연결했습니다. C2(원격 제어) 서버 통신일 수 있습니다.", "T1571", 3)
TAG_LATERAL = lambda port, desc: _t("원격 접속 프로토콜 연결", f"다른 호스트의 {desc}({port})로 연결했습니다. 내부 측면 이동이나 원격 관리일 수 있습니다.", "T1021", 1)
TAG_LISTEN = _t("포트 대기(리슨)", "외부 접속을 받기 위해 포트를 열었습니다. 정상 서비스가 아니라면 백도어일 수 있습니다.", "T1571", 1)
TAG_REMOTE_HANDLE = _t("다른 프로세스 메모리 접근", "다른 프로세스의 핸들을 열거나 복제했습니다. 인증정보 덤프(lsass 등)나 코드 인젝션 전 단계일 수 있습니다.", "T1055 / T1003", 2)
TAG_LSASS = _t("LSASS 접근(인증정보 탈취 시도)", "Windows 로그인 정보가 저장된 lsass 프로세스에 접근했습니다. 비밀번호 해시 탈취의 전형적인 징후입니다.", "T1003.001", 5)
TAG_LOG_NAME = TAG_LOG_NAME_LITERAL
LOG_TAMPER_TOOLS = {"bash", "sh", "zsh", "dash", "ksh", "rm", "shred", "truncate", "dd", "cat", "echo",
                    "sed", "perl", "python", "python2", "python3", "vi", "vim", "nano", "cmd", "powershell", "pwsh"}


def _is_log_tampering(et: str, actor: str) -> bool:
    if et in {"file deletion", "file rename"}:
        return True
    return normalize_process_name(actor) in LOG_TAMPER_TOOLS


TEMP_PATH_RE = re.compile(r"^/(tmp|dev/shm|var/tmp)/|\\(appdata\\local\\temp|windows\\temp)\\", re.I)
TAG_TEMP_EXEC = _t("임시 폴더에서 실행", "임시 폴더에 있는 실행 파일이 실행됐습니다. 내려받은 악성 파일 실행에서 흔한 패턴입니다.", "T1204.002", 2)
TAG_SCHED_TASK = _t("예약 작업 등록", "예약 작업을 등록/변경했습니다. 주기적·부팅 시 실행을 위한 지속성 수법입니다.", "T1053", 3)
TAG_LOGIN_FAIL = _t("로그인 실패", "로그인 실패가 반복되면 무차별 대입(브루트포스) 시도일 수 있습니다.", "T1110", 1)


# -------------------------------------------------------- 이벤트 → 문장
def _short(text: Optional[str], n: int = 120) -> str:
    if not text:
        return ""
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 3] + "..."


def _actor(event: Dict[str, Any]) -> str:
    name = first_of(event, ACTOR_KEYS) or first_of(event, PROCESS_NAME_KEYS) or UNKNOWN_ACTOR
    return re.split(r"[\\/]", name)[-1]


def _match(rules, text: Optional[str]) -> List[Tag]:
    if not text:
        return []
    return [tag for pattern, tag in rules if pattern.search(text)]


def _port(event, keys) -> Optional[int]:
    v = first_of(event, keys)
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None


def describe_event(event: Dict[str, Any]) -> Behavior:
    etype = first_of(event, TYPE_KEYS) or "Unknown"
    et = etype.lower()
    actor = _actor(event)
    who = actor
    tags: List[Tag] = []

    if "process creation" in et or et in {"process", "process start"}:
        child = first_of(event, CHILD_KEYS) or "프로세스"
        cmd = first_of(event, CHILD_CMD_KEYS) or first_of(event, CMDLINE_KEYS)
        child_name = re.split(r"[\\/]", child)[-1]
        sentence = f"[{who}] {child_name} 실행"
        if cmd:
            sentence += f" (명령: {_short(cmd)})"
        tags += _match(CMD_RULES, cmd)
        if TEMP_PATH_RE.search(first_of(event, ("tgtProcImagePath", "tgtProcessImagePath")) or ""):
            tags.append(TAG_TEMP_EXEC)
    elif "file" in et:
        path = first_of(event, FILE_KEYS) or "(경로 불명)"
        verb = {
            "file creation": "생성", "file modification": "수정", "file deletion": "삭제",
            "file rename": "이름 변경", "file scan": "읽기/검사",
        }.get(et, "접근")
        if et == "file rename":
            old = first_of(event, FILE_OLD_KEYS)
            sentence = f"[{who}] 파일 이름 변경: {old or '?'} → {path}"
        else:
            sentence = f"[{who}] 파일 {verb}: {path}"
        for tag in _match(PATH_RULES, path):
            if tag.name == TAG_LOG_NAME and not _is_log_tampering(et, actor):
                continue  # sshd/rsyslogd 등이 로그를 기록하는 것은 정상
            tags.append(tag)
    elif "registry" in et:
        key = first_of(event, REG_KEYS) or "(키 불명)"
        value = first_of(event, REG_VALUE_KEYS)
        if "delete" in et:
            verb = "삭제"
        elif "create" in et:
            verb = "생성"
        else:
            verb = "변경"
        sentence = f"[{who}] 레지스트리 {verb}: {key}" + (f" = {_short(value, 80)}" if value else "")
        tags += _match(REGISTRY_RULES, key)
    elif "ip connect" in et or "network" in et or et in {"ip", "connect"}:
        dst, port = first_of(event, DST_IP_KEYS), _port(event, DST_PORT_KEYS)
        status = first_of(event, ("netConnStatus", "connectionStatus"))
        direction = (first_of(event, ("netEventDirection", "direction")) or "").upper()
        if direction == "INCOMING":
            src = first_of(event, SRC_IP_KEYS)
            sentence = f"[{who}] {src or '?'} 에서 들어온 연결 수신 (포트 {_port(event, DST_PORT_KEYS) or '?'})"
        else:
            sentence = f"[{who}] {dst or '?'}:{port or '?'} 로 네트워크 연결"
            if port in SUSPICIOUS_PORTS:
                tags.append(TAG_OUTBOUND_SUSPICIOUS(port, SUSPICIOUS_PORTS[port]))
            elif port in LATERAL_PORTS:
                tags.append(TAG_LATERAL(port, LATERAL_PORTS[port]))
        if status:
            sentence += f" [{status}]"
    elif "ip listen" in et:
        sentence = f"[{who}] 포트 {_port(event, SRC_PORT_KEYS) or _port(event, DST_PORT_KEYS) or '?'} 에서 접속 대기"
        tags.append(TAG_LISTEN)
    elif "dns" in et:
        domain = first_of(event, DNS_KEYS) or "?"
        resp = first_of(event, DNS_RESP_KEYS)
        ok = "unresolved" not in et
        sentence = f"[{who}] 도메인 조회: {domain}" + (f" → {_short(resp, 60)}" if resp and ok else "" if ok else " (응답 없음)")
    elif et in {"get", "post", "put", "url", "http request"} or "url" in et:
        url = first_of(event, URL_KEYS) or "?"
        sentence = f"[{who}] 웹 요청({etype}): {_short(url)}"
    elif "login" in et or "logon" in et:
        user = first_of(event, LOGIN_USER_KEYS) or "?"
        src = first_of(event, SRC_IP_KEYS)
        failed = (first_of(event, ("loginIsSuccessful",)) or "").lower() == "false" or "fail" in et
        sentence = f"사용자 {user} 로그인 {'실패' if failed else '성공'}" + (f" (출발지 {src})" if src else "")
        if failed:
            tags.append(TAG_LOGIN_FAIL)
    elif "logout" in et:
        sentence = f"사용자 {first_of(event, LOGIN_USER_KEYS) or '?'} 로그아웃"
    elif "scheduled task" in et or "task" in et:
        sentence = f"[{who}] 예약 작업 {etype}: {first_of(event, TASK_KEYS) or '?'}"
        tags.append(TAG_SCHED_TASK)
    elif "remote process handle" in et or ("duplicate" in et and "handle" in et):
        target = first_of(event, CHILD_KEYS) or "다른 프로세스"
        sentence = f"[{who}] {target} 프로세스 핸들 획득 ({etype})"
        tags.append(TAG_LSASS if normalize_process_name(target) == "lsass" else TAG_REMOTE_HANDLE)
    elif "behavioral indicator" in et or "indicator" in et:
        name = first_of(event, INDICATOR_NAME_KEYS) or "행위 지표"
        desc = first_of(event, INDICATOR_DESC_KEYS)
        cat = first_of(event, INDICATOR_CAT_KEYS)
        sentence = f"SentinelOne 행위 지표 탐지: {name}" + (f" [{cat}]" if cat else "") + (f" - {_short(desc)}" if desc else "")
    elif "command script" in et:
        sentence = f"[{who}] 스크립트 실행: {_short(first_of(event, ('originalCmdScript', 'cmdScript')) or '', 150)}"
        tags += _match(CMD_RULES, first_of(event, ("originalCmdScript", "cmdScript")))
    elif "module load" in et or "driver load" in et:
        sentence = f"[{who}] {'드라이버' if 'driver' in et else '모듈'} 로드: {first_of(event, ('modulePath', 'tgtFilePath', 'fileFullName')) or '?'}"
    else:
        sentence = f"[{who}] {etype} 이벤트"

    # 행위 주체 자신의 명령줄도 위험 패턴 확인 (중복 태그 제거)
    tags += _match(CMD_RULES, first_of(event, ACTOR_CMD_KEYS))
    uniq = list(OrderedDict((t.name, t) for t in tags).values())
    return Behavior(first_of(event, TIME_KEYS), etype, actor, sentence, uniq)


# ----------------------------------------------------------- 요약/타임라인
def _collapse(behaviors: Iterable[Behavior]) -> List[Behavior]:
    grouped: "OrderedDict[str, Behavior]" = OrderedDict()
    for b in behaviors:
        if b.sentence in grouped:
            grouped[b.sentence].count += 1
        else:
            grouped[b.sentence] = b
    return list(grouped.values())


def _counts_sentence(events_by_type: Counter) -> str:
    labels = []
    groups = [
        ("프로세스 실행", ("process creation",)), ("파일 생성", ("file creation",)), ("파일 수정", ("file modification",)),
        ("파일 삭제", ("file deletion",)), ("네트워크 연결", ("ip connect",)), ("DNS 조회", ("dns resolved", "dns unresolved")),
        ("레지스트리 변경", ("registry",)), ("로그인", ("login",)), ("행위 지표", ("behavioral indicators",)),
    ]
    used = set()
    for label, keys in groups:
        n = sum(c for t, c in events_by_type.items() if any(k in t for k in keys))
        for t in events_by_type:
            if any(k in t for k in keys):
                used.add(t)
        if n:
            labels.append(f"{label} {n}건")
    other = sum(c for t, c in events_by_type.items() if t not in used)
    if other:
        labels.append(f"기타 {other}건")
    return ", ".join(labels)


def analyze_behavior(events: List[Dict[str, Any]], max_timeline: int = 40) -> BehaviorAnalysis:
    events = sorted(events, key=lambda e: first_of(e, TIME_KEYS) or "")
    behaviors = [describe_event(e) for e in events]
    timeline = _collapse(behaviors)

    hl: "OrderedDict[str, Tuple[Tag, List[str]]]" = OrderedDict()
    for b in timeline:
        for t in b.tags:
            entry = hl.setdefault(t.name, (t, []))
            if len(entry[1]) < 3:
                entry[1].append(b.sentence)
    highlights = sorted(hl.values(), key=lambda x: -x[0].weight)

    summary: List[str] = []
    if not events:
        summary.append("이 Storyline 에서 수집된 행위가 없습니다.")
    else:
        actors = Counter(b.actor for b in behaviors if b.actor != UNKNOWN_ACTOR) or Counter({UNKNOWN_ACTOR: 1})
        main_actor, _ = actors.most_common(1)[0]
        parent = next((first_of(e, ACTOR_PARENT_KEYS) for e in events
                       if _actor(e) == main_actor and first_of(e, ACTOR_PARENT_KEYS)), None)
        types = Counter((first_of(e, TYPE_KEYS) or "unknown").lower() for e in events)
        first_t, last_t = first_of(events[0], TIME_KEYS), first_of(events[-1], TIME_KEYS)
        span = f" ({first_t} ~ {last_t})" if first_t and last_t and first_t != last_t else ""
        head = f"주요 행위 주체는 {main_actor}" + (f"(부모: {parent})" if parent else "")
        others = [a for a, _ in actors.most_common(4) if a != main_actor]
        if others:
            head += f", 함께 등장한 프로세스: {', '.join(others)}"
        summary.append(head + ".")
        summary.append(f"총 {len(events)}개 이벤트{span}: {_counts_sentence(types)}.")
        if highlights:
            names = ", ".join(t.name for t, _ in highlights[:5])
            summary.append(f"주목할 행위: {names}.")
        else:
            summary.append("알려진 공격 패턴(지속성, 계정 조작, 다운로드·실행, 흔적 삭제 등)에 해당하는 행위는 보이지 않습니다.")

    return BehaviorAnalysis(summary, timeline[:max_timeline] if max_timeline else timeline, highlights)
