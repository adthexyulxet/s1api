"""DV 이벤트 분석: LOLBin/의심 프로세스 탐지 + IOC(IP/도메인/해시) 추출."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

# 이벤트 필드명은 콘솔/API 버전에 따라 다를 수 있어 후보를 순서대로 확인합니다.
PROCESS_NAME_KEYS = ("tgtProcName", "tgtProcessName", "processName", "srcProcName", "srcProcessName")
CMDLINE_KEYS = ("tgtProcCmdLine", "tgtProcessCmdLine", "processCmd", "cmdLine", "srcProcCmdLine", "srcProcessCmdLine")
PARENT_NAME_KEYS = ("srcProcParentName", "parentProcessName", "srcProcName")
SHA1_KEYS = ("fileSha1", "tgtFileSha1", "tgtProcImageSha1", "tgtProcessFileSha1", "srcProcImageSha1", "srcProcessFileSha1", "processImageSha1Hash")
SHA256_KEYS = ("fileSha256", "tgtFileSha256", "tgtProcImageSha256", "srcProcImageSha256")
MD5_KEYS = ("fileMd5", "tgtFileMd5", "srcProcImageMd5")
IP_KEYS = ("dstIp", "srcIp", "networkDestinationIp", "remoteIp")
DOMAIN_KEYS = ("dnsRequest", "dnsResponse", "networkUrl", "url", "tgtUrl")


@dataclass(frozen=True)
class Rule:
    category: str
    technique: str  # MITRE ATT&CK
    weight: int


# 프로세스 "이름"(경로/확장자 제거 후 소문자)과 정확히 일치할 때만 탐지합니다.
# 기존 프로토타입은 부분 문자열 매칭이라 'nc' 가 'sync.exe', 'cmd' 가 'cmdagent.exe' 등에 오탐했습니다.
SUSPICIOUS_PROCESSES: Dict[str, Rule] = {
    "powershell": Rule("LOLBin: 스크립트 실행", "T1059.001", 2),
    "pwsh": Rule("LOLBin: 스크립트 실행", "T1059.001", 2),
    "cmd": Rule("LOLBin: 명령 셸", "T1059.003", 1),
    "wscript": Rule("LOLBin: 스크립트 실행", "T1059.005", 2),
    "cscript": Rule("LOLBin: 스크립트 실행", "T1059.005", 2),
    "certutil": Rule("LOLBin: 파일 다운로드/디코딩", "T1105", 3),
    "bitsadmin": Rule("LOLBin: 파일 다운로드", "T1197", 3),
    "mshta": Rule("LOLBin: 프록시 실행", "T1218.005", 3),
    "rundll32": Rule("LOLBin: 프록시 실행", "T1218.011", 2),
    "regsvr32": Rule("LOLBin: 프록시 실행", "T1218.010", 3),
    "msiexec": Rule("LOLBin: 프록시 실행", "T1218.007", 1),
    "installutil": Rule("LOLBin: 프록시 실행", "T1218.004", 3),
    "regasm": Rule("LOLBin: 프록시 실행", "T1218.009", 3),
    "regsvcs": Rule("LOLBin: 프록시 실행", "T1218.009", 3),
    "wmic": Rule("LOLBin: WMI 실행", "T1047", 2),
    "schtasks": Rule("지속성: 예약 작업", "T1053.005", 2),
    "vssadmin": Rule("영향: 섀도 복사본 삭제", "T1490", 3),
    "wbadmin": Rule("영향: 백업 삭제", "T1490", 3),
    "bcdedit": Rule("영향: 복구 비활성화", "T1490", 3),
    "nc": Rule("원격 접속 도구", "T1095", 3),
    "ncat": Rule("원격 접속 도구", "T1095", 3),
    "netcat": Rule("원격 접속 도구", "T1095", 3),
    "sshd": Rule("원격 접속 서비스", "T1021.004", 1),
    "psexec": Rule("측면 이동", "T1569.002", 3),
    "psexesvc": Rule("측면 이동", "T1569.002", 3),
}

# 명령줄 패턴 (프로세스 이름과 무관하게 탐지)
CMDLINE_PATTERNS: List[Tuple[re.Pattern, Rule]] = [
    (re.compile(r"\s-(e|en|enc|enco|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", re.I), Rule("인코딩된 PowerShell 명령", "T1027", 3)),
    (re.compile(r"(iex|invoke-expression)\b.*(downloadstring|invoke-webrequest|iwr|net\.webclient)", re.I), Rule("PowerShell 다운로드 후 실행", "T1059.001", 3)),
    (re.compile(r"certutil(\.exe)?\b.*-(urlcache|decode)", re.I), Rule("certutil 다운로드/디코딩", "T1105", 3)),
    (re.compile(r"vssadmin(\.exe)?\b.*delete\s+shadows", re.I), Rule("섀도 복사본 삭제", "T1490", 4)),
    (re.compile(r"-w(indowstyle)?\s+hidden", re.I), Rule("숨김 창 실행", "T1564.003", 1)),
]

HASH_RE = {
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
}
URL_IN_TEXT_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)


@dataclass
class Finding:
    category: str
    technique: str
    weight: int
    process: Optional[str]
    cmdline: Optional[str]
    sha1: Optional[str]
    parent: Optional[str] = None
    event_type: Optional[str] = None
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class Iocs:
    ips: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    sha1: Set[str] = field(default_factory=set)
    sha256: Set[str] = field(default_factory=set)
    md5: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, List[str]]:
        return {k: sorted(v) for k, v in self.__dict__.items()}

    def total(self) -> int:
        return sum(len(v) for v in self.__dict__.values())


@dataclass
class AnalysisResult:
    event_count: int
    findings: List[Finding]
    iocs: Iocs
    event_types: Dict[str, int]


def first_of(event: Dict[str, Any], keys: Iterable[str]) -> Optional[str]:
    for key in keys:
        value = event.get(key)
        if value not in (None, "", [], {}):
            return str(value)
    return None


def normalize_process_name(name: Optional[str]) -> str:
    """'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.EXE' -> 'powershell'"""
    if not name:
        return ""
    base = re.split(r"[\\/]", name.strip())[-1].lower()
    for ext in (".exe", ".com", ".bat", ".cmd", ".dll"):
        if base.endswith(ext):
            base = base[: -len(ext)]
            break
    return base


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def normalize_domain(value: str) -> Optional[str]:
    v = value.strip().lower()
    if not v:
        return None
    if "://" in v:
        v = urlparse(v).hostname or ""
    else:
        v = v.split("/")[0].split(":")[0]
    v = v.rstrip(".")
    if not v or is_public_ip(v) or not DOMAIN_RE.match(v):
        return None
    return v


def _add_host(iocs: Iocs, host: Optional[str]) -> None:
    if not host:
        return
    host = host.strip().strip("[]")
    if is_public_ip(host):
        iocs.ips.add(host)
        return
    d = normalize_domain(host)
    if d:
        iocs.domains.add(d)


def extract_iocs(events: Iterable[Dict[str, Any]]) -> Iocs:
    iocs = Iocs()
    for event in events:
        for key in IP_KEYS:
            value = event.get(key)
            if value and is_public_ip(str(value)):
                iocs.ips.add(str(value).strip())
        for key in DOMAIN_KEYS:
            value = event.get(key)
            if value:
                d = normalize_domain(str(value))
                if d:
                    iocs.domains.add(d)
        for keys, bucket, kind in ((SHA1_KEYS, iocs.sha1, "sha1"), (SHA256_KEYS, iocs.sha256, "sha256"), (MD5_KEYS, iocs.md5, "md5")):
            for key in keys:
                value = event.get(key)
                if value and HASH_RE[kind].match(str(value)):
                    bucket.add(str(value).lower())
        cmd = first_of(event, CMDLINE_KEYS)
        if cmd:
            for url in URL_IN_TEXT_RE.findall(cmd):
                _add_host(iocs, urlparse(url).hostname)
    return iocs


def detect(event: Dict[str, Any]) -> List[Finding]:
    process = first_of(event, PROCESS_NAME_KEYS)
    cmdline = first_of(event, CMDLINE_KEYS)
    common = dict(
        process=process,
        cmdline=cmdline,
        sha1=first_of(event, SHA1_KEYS),
        parent=first_of(event, PARENT_NAME_KEYS),
        event_type=first_of(event, ("eventType", "objectType")),
        created_at=first_of(event, ("createdAt", "eventTime")),
    )
    found: List[Finding] = []
    rule = SUSPICIOUS_PROCESSES.get(normalize_process_name(process))
    if rule:
        found.append(Finding(rule.category, rule.technique, rule.weight, **common))
    if cmdline:
        for pattern, prule in CMDLINE_PATTERNS:
            if pattern.search(" " + cmdline):
                found.append(Finding(prule.category, prule.technique, prule.weight, **common))
    return found


def analyze_events(events: List[Dict[str, Any]]) -> AnalysisResult:
    findings: List[Finding] = []
    seen: Set[Tuple[str, str, str]] = set()
    event_types: Dict[str, int] = {}
    for event in events:
        et = first_of(event, ("eventType", "objectType")) or "unknown"
        event_types[et] = event_types.get(et, 0) + 1
        for f in detect(event):
            key = (f.category, (f.process or "").lower(), f.cmdline or "")
            if key in seen:  # 같은 프로세스/명령줄이 여러 이벤트에 반복되는 경우 1건으로
                continue
            seen.add(key)
            findings.append(f)
    findings.sort(key=lambda f: f.weight, reverse=True)
    return AnalysisResult(len(events), findings, extract_iocs(events), event_types)
