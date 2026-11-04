"""업로드한 파일 / 격리(quarantine) ZIP 의 정적 분석.

- ZIP 은 디스크에 풀지 않고 메모리에서만 읽습니다 (ZipCrypto / AES 패스워드 지원, AES 는 pyzipper 필요).
- 샘플은 절대 실행하지 않습니다. 해시, 엔트로피, 파일 형식, 문자열, PE/ELF 구조만 읽습니다.
- 외부 서비스로는 아무것도 보내지 않습니다. (옵션을 켜고 VT 키가 있을 때만 SHA256 해시를 VirusTotal 에 조회)
"""

from __future__ import annotations

import hashlib
import io
import ipaddress
import math
import re
import struct
import time
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:  # AES 암호화 ZIP 지원 (선택)
    import pyzipper  # type: ignore
except ImportError:  # pragma: no cover - 설치 여부에 따라 다름
    pyzipper = None

MAX_UPLOAD = 64 * 1024 * 1024          # 업로드 1건 최대 크기
MAX_MEMBER = 64 * 1024 * 1024          # ZIP 안 파일 1개 최대 크기
MAX_TOTAL_UNPACKED = 256 * 1024 * 1024  # ZIP 전체 해제 크기 상한 (압축 폭탄 방지)
MAX_MEMBERS = 200
MAX_DEPTH = 2                           # ZIP 안의 ZIP 은 2단계까지만
MAX_STRINGS_SCANNED = 50_000
MAX_STRINGS_SHOWN = 300
ENTROPY_SAMPLE = 16 * 1024 * 1024
DEFAULT_PASSWORDS = ("infected", "malware", "virus")

VERDICT_HIGH, VERDICT_CHECK, VERDICT_LOW = "악성 가능성 높음", "추가 확인 필요", "악성 징후 적음"


class SampleError(ValueError):
    """사용자에게 그대로 보여줄 수 있는 분석 오류 (패스워드 틀림 등)."""


# ------------------------------------------------------------------ 기본 유틸

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:ENTROPY_SAMPLE]
    n = len(sample)
    ent = 0.0
    for b in range(256):
        c = sample.count(b)
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return round(ent, 3)


def hashes(data: bytes) -> Dict[str, str]:
    return {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def detect_type(data: bytes, name: str = "") -> str:
    head = data[:16]
    if head.startswith(b"MZ"):
        return "PE"
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "Mach-O"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "ZIP"
    if head.startswith(b"%PDF"):
        return "PDF"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "OLE (구형 Office/MSI)"
    if head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        return "LNK (바로가기)"
    if head.startswith(b"Rar!"):
        return "RAR"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "GZIP"
    if head.startswith(b"#!"):
        return "스크립트 (shebang)"
    ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
    script_ext = {"ps1": "PowerShell", "psm1": "PowerShell", "vbs": "VBScript", "vbe": "VBScript", "js": "JScript",
                  "jse": "JScript", "bat": "배치 파일", "cmd": "배치 파일", "hta": "HTA", "sh": "셸 스크립트",
                  "py": "Python", "wsf": "WSF"}
    if ext in script_ext:
        return script_ext[ext] + " 스크립트"
    if data and sum(1 for b in data[:4096] if b in b"\t\r\n" or 32 <= b < 127) / min(len(data), 4096) > 0.95:
        return "텍스트"
    return "알 수 없음 (바이너리)"


# ------------------------------------------------------------------ 문자열 / IOC

ASCII_RE = re.compile(rb"[\x20-\x7e]{5,}")
WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>()\\]{3,}", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL_RE = re.compile(r"\b[\w.+-]{2,}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,10}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|io|ru|cn|xyz|top|online|site|club|cc|tk|su|pw|onion|kr|uk|de|fr|jp|br|ir|kp)\b", re.I)
REG_RE = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[^\s\"']{3,}", re.I)
WINPATH_RE = re.compile(r"\b[A-Za-z]:\\[^\s\"'<>|*?]{3,}|%[A-Za-z]+%\\[^\s\"'<>|*?]{2,}")
B64_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
NOISE_DOMAINS = ("microsoft.com", "windows.com", "w3.org", "verisign.com", "digicert.com", "symantec.com",
                 "globalsign.com", "sectigo.com", "usertrust.com", "comodoca.com", "thawte.com", "entrust.net",
                 "apache.org", "gnu.org", "openssl.org", "xmlsoap.org", "schemas.android.com", "python.org")


def extract_strings(data: bytes, limit: int = MAX_STRINGS_SCANNED) -> List[str]:
    out: List[str] = []
    for rx, enc in ((ASCII_RE, "ascii"), (WIDE_RE, "utf-16-le")):
        for m in rx.finditer(data):
            out.append(m.group().decode(enc, "replace"))
            if len(out) >= limit:
                return out
    return out


def _is_public_ip(v: str) -> bool:
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def _noise(domain: str) -> bool:
    d = domain.lower()
    return any(d == n or d.endswith("." + n) for n in NOISE_DOMAINS)


def extract_iocs(strings: Iterable[str]) -> Dict[str, List[str]]:
    found: Dict[str, set] = {k: set() for k in ("urls", "ips", "domains", "emails", "registry", "paths", "btc_wallets")}
    for s in strings:
        for u in URL_RE.findall(s):
            u = u.rstrip(".,;")
            host = re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0].split(":")[0]
            if not _noise(host):
                found["urls"].add(u[:300])
                if IPV4_RE.fullmatch(host):
                    if _is_public_ip(host):
                        found["ips"].add(host)
                elif "." in host:
                    found["domains"].add(host.lower())
        for ip in IPV4_RE.findall(s):
            # 버전 문자열(1.2.3.4) 오탐을 줄이기 위해 공인 IP 만
            if _is_public_ip(ip) and not re.search(r"(?:version|ver|v)\s*" + re.escape(ip), s, re.I):
                found["ips"].add(ip)
        for m in DOMAIN_RE.finditer(s):
            d = m.group().lower()
            if not _noise(d) and not d.startswith(("system.", "microsoft.")):
                found["domains"].add(d)
        found["emails"].update(e for e in EMAIL_RE.findall(s) if not _noise(e.split("@")[1]))
        found["registry"].update(r[:300] for r in REG_RE.findall(s))
        found["paths"].update(p[:300] for p in WINPATH_RE.findall(s))
        if len(s) < 120:
            found["btc_wallets"].update(w for w in BTC_RE.findall(s) if re.search(r"bitcoin|btc|wallet|ransom|pay", s, re.I) or w.startswith("bc1"))
    return {k: sorted(v)[:100] for k, v in found.items() if v}


# 규칙: (정규식, 이름, MITRE ATT&CK, 가중치)
RULES: List[Tuple[re.Pattern, str, str, int]] = [(re.compile(p, re.I), n, t, w) for p, n, t, w in [
    (r"\b(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtWriteVirtualMemory|QueueUserAPC|NtUnmapViewOfSection|ZwUnmapViewOfSection|SetThreadContext)\b", "프로세스 인젝션 API", "T1055", 3),
    (r"\b(SetWindowsHookEx[AW]?|GetAsyncKeyState|GetKeyboardState)\b", "키로깅 API", "T1056.001", 2),
    (r"\b(IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|OutputDebugString[AW]?)\b", "안티 디버깅", "T1622", 1),
    (r"\b(URLDownloadToFile[AW]?|InternetOpenUrl[AW]?|WinHttpOpen|HttpSendRequest[AW]?|InternetReadFile)\b", "인터넷 다운로드 API", "T1105", 1),
    (r"\b(CryptEncrypt|BCryptEncrypt|CryptGenKey|CryptImportKey)\b", "암호화 API", "T1486", 1),
    (r"vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit.*recoveryenabled\s+no|wbadmin\s+delete", "백업/섀도 복사본 삭제", "T1490", 4),
    (r"your (files|documents).{0,40}(encrypted|locked)|decrypt(ion)? (key|tool)|how[_ -]to[_ -]decrypt|readme.{0,10}\.txt.*ransom|\.onion\b", "랜섬노트 문구", "T1486", 4),
    (r"\b(mimikatz|sekurlsa|lsadump|kerberos::|privilege::debug)\b", "Mimikatz 흔적", "T1003.001", 5),
    (r"\blsass(\.exe)?\b.*(dump|minidump)|MiniDumpWriteDump", "LSASS 메모리 덤프", "T1003.001", 3),
    (r"\\CurrentVersion\\(Run|RunOnce)\b|schtasks(\.exe)?\s+/create|\\Winlogon\\(Shell|Userinit)", "자동 실행(지속성) 등록", "T1547", 2),
    (r"powershell(\.exe)?.{0,60}\s-(e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", "인코딩된 PowerShell", "T1027", 3),
    (r"(iex|invoke-expression)\b.{0,80}(downloadstring|invoke-webrequest|iwr|net\.webclient)|downloadstring\(", "PowerShell 다운로드 후 실행", "T1059.001", 3),
    (r"certutil(\.exe)?.{0,20}-(urlcache|decode)|bitsadmin(\.exe)?\s+/transfer", "LOLBin 다운로드", "T1105", 3),
    (r"\b(AmsiScanBuffer|amsiInitFailed|EtwEventWrite)\b", "AMSI/ETW 우회", "T1562.001", 3),
    (r"Set-MpPreference.{0,40}-Disable|DisableAntiSpyware|Add-MpPreference.{0,30}-ExclusionPath", "Defender 무력화", "T1562.001", 3),
    (r"wevtutil(\.exe)?\s+cl\b|Clear-EventLog", "이벤트 로그 삭제", "T1070.001", 3),
    (r"stratum\+tcp://|\bxmrig\b|cryptonight|monero", "코인 채굴기", "T1496", 4),
    (r"/dev/tcp/\d|\bnc(at)?\s+-e\s|bash\s+-i\s+>&|socket\.socket.{0,80}subprocess", "리버스 셸", "T1059.004", 4),
    (r"(wget|curl)\s+[^|;]{4,120}\|\s*(ba)?sh\b", "다운로드 후 셸 실행", "T1105", 3),
    (r"/etc/(crontab|cron\.d)|crontab\s+-|\.ssh/authorized_keys|/etc/rc\.local|systemctl\s+enable", "리눅스 지속성", "T1053.003", 2),
    (r"\bLD_PRELOAD\b|/etc/ld\.so\.preload", "LD_PRELOAD 후킹", "T1574.006", 3),
    (r"chmod\s+(\+x|[0-7]?7[0-7]{2})\s+/tmp/|/dev/shm/", "임시 경로 실행 파일", "T1036", 1),
    (r"\b(AdjustTokenPrivileges|SeDebugPrivilege)\b", "권한 상승 시도", "T1134", 1),
    (r"\b(CreateToolhelp32Snapshot|Process32(First|Next)W?)\b.*|\b(EnumProcesses)\b", "프로세스 목록 조회", "T1057", 0),
    (r"\b(GetClipboardData|OpenClipboard)\b", "클립보드 접근", "T1115", 1),
    (r"Login Data|\\Google\\Chrome\\User Data|cookies\.sqlite|logins\.json|\\Mozilla\\Firefox\\Profiles", "브라우저 저장 정보 탈취", "T1555.003", 3),
    (r"api\.telegram\.org/bot|discord(app)?\.com/api/webhooks", "메신저 API 유출 채널", "T1567", 3),
]]


def match_rules(strings: List[str]) -> List[Dict[str, Any]]:
    hits: Dict[str, Dict[str, Any]] = {}
    for s in strings:
        for rx, name, technique, weight in RULES:
            m = rx.search(s)
            if m:
                h = hits.setdefault(name, {"name": name, "technique": technique, "weight": weight, "evidence": []})
                ev = s.strip()[:200]
                if ev not in h["evidence"] and len(h["evidence"]) < 5:
                    h["evidence"].append(ev)
    return sorted(hits.values(), key=lambda h: -h["weight"])


# ------------------------------------------------------------------ PE 구조

PE_MACHINES = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64", 0x200: "IA64"}
PE_SUBSYSTEMS = {1: "Native(드라이버)", 2: "GUI", 3: "콘솔(CUI)", 9: "WinCE", 10: "EFI"}
PACKER_SECTIONS = {"upx0": "UPX", "upx1": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".themida": "Themida",
                   ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".mpress1": "MPRESS", ".petite": "Petite",
                   ".nsp0": "NsPack", ".enigma1": "Enigma", "pec1": "PECompact", ".packed": "알 수 없는 패커"}


class _Reader:
    def __init__(self, data: bytes):
        self.d = data

    def u(self, fmt: str, off: int):
        size = struct.calcsize(fmt)
        if off < 0 or off + size > len(self.d):
            raise ValueError("구조가 파일 범위를 벗어났습니다")
        return struct.unpack_from(fmt, self.d, off)

    def cstr(self, off: int, maxlen: int = 256) -> str:
        if off < 0 or off >= len(self.d):
            return ""
        end = self.d.find(b"\x00", off, off + maxlen)
        return self.d[off: end if end != -1 else off + maxlen].decode("latin-1")


def parse_pe(data: bytes) -> Dict[str, Any]:
    r = _Reader(data)
    pe_off = r.u("<I", 0x3c)[0]
    if r.u("<4s", pe_off)[0] != b"PE\x00\x00":
        raise ValueError("PE 시그니처가 없습니다")
    machine, nsec, timestamp, _, _, opt_size, chars = r.u("<HHIIIHH", pe_off + 4)
    opt = pe_off + 24
    magic = r.u("<H", opt)[0]
    is64 = magic == 0x20b
    entry = r.u("<I", opt + 16)[0]
    image_base = r.u("<Q", opt + 24)[0] if is64 else r.u("<I", opt + 28)[0]
    subsystem, dll_chars = r.u("<HH", opt + 68)
    dd_off = opt + (112 if is64 else 96)
    ndd = min(r.u("<I", dd_off - 4)[0], 16)
    dirs = [r.u("<II", dd_off + 8 * i) for i in range(ndd)]

    sections = []
    sec_off = opt + opt_size
    for i in range(min(nsec, 96)):
        o = sec_off + 40 * i
        name = r.u("<8s", o)[0].rstrip(b"\x00").decode("latin-1")
        vsize, vaddr, rsize, rptr = r.u("<IIII", o + 8)
        sc = r.u("<I", o + 36)[0]
        raw = data[rptr: rptr + rsize]
        perms = ("R" if sc & 0x40000000 else "-") + ("W" if sc & 0x80000000 else "-") + ("X" if sc & 0x20000000 else "-")
        sections.append({"name": name, "virtual_address": hex(vaddr), "virtual_size": vsize, "raw_size": rsize,
                         "raw_offset": rptr, "_vaddr": vaddr, "perms": perms, "entropy": entropy(raw)})

    def rva_to_off(rva: int) -> Optional[int]:
        for s in sections:
            size = max(s["virtual_size"], s["raw_size"])
            if s["_vaddr"] <= rva < s["_vaddr"] + size:
                return rva - s["_vaddr"] + s["raw_offset"]
        return rva if rva < len(data) and not sections else None

    imports: Dict[str, List[str]] = {}
    if ndd > 1 and dirs[1][0]:
        off = rva_to_off(dirs[1][0])
        for i in range(512):
            if off is None:
                break
            try:
                oft, _, _, name_rva, ft = r.u("<IIIII", off + 20 * i)
            except ValueError:
                break
            if not (oft or name_rva or ft):
                break
            name_off = rva_to_off(name_rva)
            dll = r.cstr(name_off) if name_off is not None else "?"
            funcs: List[str] = []
            thunk = rva_to_off(oft or ft)
            step, flag = (8, 1 << 63) if is64 else (4, 1 << 31)
            for j in range(2048):
                if thunk is None:
                    break
                try:
                    val = r.u("<Q" if is64 else "<I", thunk + step * j)[0]
                except ValueError:
                    break
                if not val:
                    break
                if val & flag:
                    funcs.append(f"ord{val & 0xffff}")
                else:
                    hn = rva_to_off(val & 0x7fffffff)
                    funcs.append(r.cstr(hn + 2) if hn is not None else "?")
            imports.setdefault(dll, []).extend(funcs)

    exports: List[str] = []
    if ndd > 0 and dirs[0][0]:
        eo = rva_to_off(dirs[0][0])
        try:
            if eo is not None:
                nnames, _, names_rva = r.u("<III", eo + 24)  # NumberOfNames, AddressOfFunctions, AddressOfNames
                no = rva_to_off(names_rva)
                for i in range(min(nnames, 500)):
                    if no is None:
                        break
                    so = rva_to_off(r.u("<I", no + 4 * i)[0])
                    if so is not None:
                        exports.append(r.cstr(so))
        except ValueError:
            pass

    # imphash (pefile 과 같은 방식: 확장자 뺀 dll 소문자 + '.' + 함수 소문자)
    parts = []
    for dll, funcs in imports.items():
        base = dll.lower()
        for ext in (".dll", ".ocx", ".sys"):
            if base.endswith(ext):
                base = base[: -len(ext)]
        parts += [f"{base}.{f.lower()}" for f in funcs]
    imphash = hashlib.md5(",".join(parts).encode()).hexdigest() if parts else None

    last_end = max((s["raw_offset"] + s["raw_size"] for s in sections), default=0)
    if ndd > 4 and dirs[4][0] and dirs[4][0] + dirs[4][1] >= last_end:  # 서명은 overlay 에 붙어 있으므로 제외
        last_end = max(last_end, dirs[4][0] + dirs[4][1])
    overlay = max(0, len(data) - last_end)

    ep_section = next((s["name"] for s in sections if s["_vaddr"] <= entry < s["_vaddr"] + max(s["virtual_size"], s["raw_size"])), None)
    for s in sections:
        s.pop("_vaddr")
    try:
        compiled = datetime.fromtimestamp(timestamp, timezone.utc).isoformat() if timestamp else None
    except (OverflowError, OSError, ValueError):
        compiled = None
    return {
        "machine": PE_MACHINES.get(machine, hex(machine)), "bits": 64 if is64 else 32,
        "kind": "DLL" if chars & 0x2000 else ("드라이버" if subsystem == 1 else "EXE"),
        "subsystem": PE_SUBSYSTEMS.get(subsystem, str(subsystem)),
        "compiled_at": compiled, "timestamp": timestamp,
        "entry_point": hex(entry), "entry_section": ep_section, "image_base": hex(image_base),
        "aslr": bool(dll_chars & 0x40), "dep": bool(dll_chars & 0x100),
        "signed": bool(ndd > 4 and dirs[4][0] and dirs[4][1]),
        "dotnet": bool(ndd > 14 and dirs[14][0]),
        "sections": sections, "imports": {k: v[:300] for k, v in list(imports.items())[:100]},
        "import_count": sum(len(v) for v in imports.values()), "exports": exports[:200],
        "imphash": imphash, "overlay_size": overlay,
    }


def pe_findings(pe: Dict[str, Any], file_size: int) -> List[Dict[str, Any]]:
    out = []

    def add(name, weight, evidence, technique=""):
        out.append({"name": name, "technique": technique, "weight": weight, "evidence": [evidence]})

    packers = {PACKER_SECTIONS[s["name"].lower()] for s in pe["sections"] if s["name"].lower() in PACKER_SECTIONS}
    if packers:
        add("패커 섹션", 3, "섹션 이름: " + ", ".join(sorted(packers)), "T1027.002")
    hi = [s for s in pe["sections"] if s["entropy"] >= 7.2 and s["raw_size"] > 1024]
    if hi:
        add("높은 엔트로피 섹션(압축/암호화 의심)", 2, ", ".join(f"{s['name']}={s['entropy']}" for s in hi), "T1027")
    rwx = [s["name"] for s in pe["sections"] if s["perms"] == "RWX"]
    if rwx:
        add("쓰기+실행(RWX) 섹션", 2, ", ".join(rwx), "T1027")
    if pe["entry_section"] is None:
        add("엔트리포인트가 섹션 밖", 2, pe["entry_point"])
    elif pe["sections"] and pe["entry_section"] == pe["sections"][-1]["name"] and len(pe["sections"]) > 1 \
            and pe["entry_section"].lower() not in (".text", "code", ".code"):
        add("엔트리포인트가 마지막 섹션", 1, pe["entry_section"])
    if not pe["dotnet"] and pe["import_count"] < 10 and pe["kind"] != "DLL":
        add("임포트가 매우 적음(패킹 의심)", 2, f"{pe['import_count']}개", "T1027.002")
    if pe["timestamp"] and pe["timestamp"] > time.time() + 86400:
        add("미래의 컴파일 시각(조작 의심)", 1, pe["compiled_at"] or "", "T1070.006")
    if pe["overlay_size"] > max(1024 * 1024, file_size // 3):
        add("큰 오버레이 데이터(드로퍼/설치본 의심)", 1, f"{pe['overlay_size']:,} bytes")
    if not pe["signed"]:
        add("디지털 서명 없음", 1, "Security 디렉터리 비어 있음")
    return out


# ------------------------------------------------------------------ ELF 구조

ELF_MACHINES = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64", 243: "RISC-V", 2: "SPARC"}
ELF_TYPES = {1: "REL(오브젝트)", 2: "EXEC(실행 파일)", 3: "DYN(공유 라이브러리/PIE)", 4: "CORE"}


def parse_elf(data: bytes) -> Dict[str, Any]:
    r = _Reader(data)
    cls, endian = data[4], data[5]
    if cls not in (1, 2) or endian not in (1, 2):
        raise ValueError("ELF 헤더가 손상되었습니다")
    e = "<" if endian == 1 else ">"
    is64 = cls == 2
    if is64:
        etype, mach, _, entry, phoff, shoff, _, _, phentsz, phnum, shentsz, shnum, shstrndx = r.u(e + "HHIQQQIHHHHHH", 16)
    else:
        etype, mach, _, entry, phoff, shoff, _, _, phentsz, phnum, shentsz, shnum, shstrndx = r.u(e + "HHIIIIIHHHHHH", 16)

    raw_secs = []
    for i in range(min(shnum, 256)):
        o = shoff + i * shentsz
        try:
            if is64:
                name, stype, flags, addr, off, size, link = r.u(e + "IIQQQQI", o)
            else:
                name, stype, flags, addr, off, size, link = r.u(e + "IIIIIII", o)
        except ValueError:
            break
        raw_secs.append((name, stype, flags, off, size, link))
    names_off = raw_secs[shstrndx][3] if shstrndx < len(raw_secs) else None
    sections = []
    for name, stype, flags, off, size, link in raw_secs:
        nm = r.cstr(names_off + name) if names_off is not None else ""
        perms = "R" + ("W" if flags & 1 else "-") + ("X" if flags & 4 else "-")
        sections.append({"name": nm, "type": stype, "size": size, "offset": off, "perms": perms,
                         "entropy": entropy(data[off: off + size]) if stype != 8 else 0.0, "_link": link})

    interp = None
    segments = []
    for i in range(min(phnum, 128)):
        o = phoff + i * phentsz
        try:
            if is64:
                ptype, pflags, poff, _, _, pfilesz = r.u(e + "IIQQQQ", o)
            else:
                ptype, poff, _, _, pfilesz, _, pflags = r.u(e + "IIIIIII", o)
        except ValueError:
            break
        segments.append({"type": ptype, "flags": pflags})
        if ptype == 3:
            interp = r.cstr(poff, min(pfilesz, 256))

    needed: List[str] = []
    dyn = next((s for s in sections if s["type"] == 6), None)
    if dyn and dyn["_link"] < len(sections):
        strtab = sections[dyn["_link"]]["offset"]
        entsz = 16 if is64 else 8
        for i in range(min(dyn["size"] // entsz, 4096)):
            try:
                tag, val = r.u(e + ("qQ" if is64 else "iI"), dyn["offset"] + i * entsz)
            except ValueError:
                break
            if tag == 0:
                break
            if tag == 1:
                needed.append(r.cstr(strtab + val))
    for s in sections:
        s.pop("_link")
    names = {s["name"] for s in sections}
    return {
        "bits": 64 if is64 else 32, "endian": "little" if endian == 1 else "big",
        "kind": ELF_TYPES.get(etype, str(etype)), "machine": ELF_MACHINES.get(mach, str(mach)),
        "entry_point": hex(entry), "interpreter": interp, "static": interp is None and not needed,
        "stripped": ".symtab" not in names, "needed": needed[:100],
        "exec_stack": any(s["type"] == 0x6474e551 and s["flags"] & 1 for s in segments),
        "sections": [s for s in sections if s["name"]][:80], "section_count": len(sections),
    }


def elf_findings(elf: Dict[str, Any], data: bytes) -> List[Dict[str, Any]]:
    out = []

    def add(name, weight, evidence, technique=""):
        out.append({"name": name, "technique": technique, "weight": weight, "evidence": [evidence]})

    if b"UPX!" in data[:4096] or b"UPX!" in data[-4096:]:
        add("UPX 패킹", 3, "UPX! 시그니처", "T1027.002")
    if elf["section_count"] == 0:
        add("섹션 헤더 없음(분석 방해 의심)", 2, "e_shnum=0", "T1027")
    hi = [s for s in elf["sections"] if s["entropy"] >= 7.2 and s["size"] > 1024]
    if hi:
        add("높은 엔트로피 섹션(압축/암호화 의심)", 2, ", ".join(f"{s['name']}={s['entropy']}" for s in hi), "T1027")
    if elf["static"] and elf["stripped"]:
        add("정적 링크 + 심볼 제거", 1, "봇넷/채굴기 바이너리에 흔한 형태")
    if elf["exec_stack"]:
        add("실행 가능한 스택", 1, "PT_GNU_STACK RWX")
    return out


# ------------------------------------------------------------------ ZIP (메모리 전용)

def _open_zip(data: bytes):
    if pyzipper is not None:
        return pyzipper.AESZipFile(io.BytesIO(data))
    return zipfile.ZipFile(io.BytesIO(data))


def _read_member(zf, info, pwd: Optional[bytes]) -> bytes:
    with zf.open(info, pwd=pwd) as fh:
        buf = fh.read(MAX_MEMBER + 1)
    if len(buf) > MAX_MEMBER:
        raise SampleError(f"{info.filename}: 파일이 너무 큽니다 (최대 {MAX_MEMBER // 1024 // 1024}MB)")
    return buf


def unpack_zip(data: bytes, passwords: List[str], budget: List[int]) -> Tuple[List[Tuple[str, bytes]], Optional[str], List[str]]:
    """(이름, 내용) 목록, 사용된 패스워드, 경고 목록을 돌려줍니다. 디스크에는 아무것도 쓰지 않습니다."""
    try:
        zf = _open_zip(data)
    except zipfile.BadZipFile as exc:
        raise SampleError(f"ZIP 파일을 열 수 없습니다: {exc}") from exc
    warnings: List[str] = []
    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_MEMBERS:
            warnings.append(f"ZIP 안 파일이 {len(infos)}개라 앞의 {MAX_MEMBERS}개만 분석합니다.")
            infos = infos[:MAX_MEMBERS]
        encrypted = any(i.flag_bits & 0x1 for i in infos)
        if any(i.compress_type == 99 for i in infos) and pyzipper is None:
            raise SampleError("AES 로 암호화된 ZIP 입니다. 'pip install pyzipper' 후 다시 시도하세요.")
        used: Optional[str] = None
        candidates: List[Optional[str]] = [None]
        if encrypted:
            seen = []
            for p in passwords:
                if p and p not in seen:
                    seen.append(p)
            candidates = seen
            if not candidates:
                raise SampleError("패스워드로 보호된 ZIP 입니다. 패스워드를 입력하세요.")
        out: List[Tuple[str, bytes]] = []
        for info in infos:
            if info.file_size > MAX_MEMBER:
                warnings.append(f"{info.filename}: {info.file_size:,} bytes 로 너무 커서 건너뜀")
                continue
            if budget[0] - info.file_size < 0:
                warnings.append("전체 해제 크기 한도를 넘어 나머지 파일은 건너뜁니다 (압축 폭탄 방지).")
                break
            content = None
            order = [used] if used is not None else candidates
            for p in order:
                try:
                    content = _read_member(zf, info, p.encode() if p else None)
                    used = p
                    break
                except RuntimeError as exc:  # 패스워드 틀림 / 필요
                    if "password" not in str(exc).lower() and "bad" not in str(exc).lower():
                        raise SampleError(f"{info.filename}: {exc}") from exc
                except (zipfile.BadZipFile, NotImplementedError, EOFError, OSError) as exc:
                    warnings.append(f"{info.filename}: 압축 해제 실패 ({exc})")
                    content = b""
                    break
            if content is None:
                if used is None:
                    raise SampleError("ZIP 패스워드가 맞지 않습니다. 패스워드를 확인하세요.")
                warnings.append(f"{info.filename}: 패스워드가 달라 건너뜀")
                continue
            if not content and info.file_size:
                continue
            budget[0] -= len(content)
            out.append((info.filename, content))
    return out, used, warnings


# ------------------------------------------------------------------ 파일 1개 분석

def analyze_file(name: str, data: bytes, depth: int = 0) -> Dict[str, Any]:
    ftype = detect_type(data, name)
    strings = extract_strings(data)
    result: Dict[str, Any] = {
        "name": name, "size": len(data), **hashes(data), "type": ftype, "entropy": entropy(data),
        "string_count": len(strings),
    }
    findings = match_rules(strings)
    if ftype == "PE":
        try:
            result["pe"] = parse_pe(data)
            findings += pe_findings(result["pe"], len(data))
        except (ValueError, struct.error, IndexError) as exc:
            result["parse_error"] = f"PE 구조 해석 실패: {exc}"
            findings.append({"name": "손상되었거나 변조된 PE 헤더", "technique": "T1027", "weight": 2, "evidence": [str(exc)]})
    elif ftype == "ELF":
        try:
            result["elf"] = parse_elf(data)
            findings += elf_findings(result["elf"], data)
        except (ValueError, struct.error, IndexError) as exc:
            result["parse_error"] = f"ELF 구조 해석 실패: {exc}"
            findings.append({"name": "손상되었거나 변조된 ELF 헤더", "technique": "T1027", "weight": 2, "evidence": [str(exc)]})
    elif result["entropy"] >= 7.5 and len(data) > 4096 and ftype.startswith("알 수 없음"):
        findings.append({"name": "형식 불명 + 매우 높은 엔트로피(암호화 페이로드 의심)", "technique": "T1027", "weight": 2,
                         "evidence": [f"entropy={result['entropy']}"]})
    if any(B64_RE.search(s) for s in strings[:20000]):
        findings.append({"name": "긴 Base64 블롭", "technique": "T1027", "weight": 1,
                         "evidence": [next(s for s in strings if B64_RE.search(s))[:120] + "…"]})
    ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
    if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|com|bat|js|vbs)$", name, re.I) or \
            (ftype == "PE" and ext in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "mp4"}):
        findings.append({"name": "확장자 위장", "technique": "T1036.007", "weight": 3, "evidence": [name]})
    result["findings"] = findings
    result["score"] = sum(f["weight"] for f in findings)
    result["iocs"] = extract_iocs(strings)
    result["strings_sample"] = _interesting_strings(strings)
    return result


def _interesting_strings(strings: List[str]) -> List[str]:
    keyword = re.compile(r"https?://|\\\\|\\|/tmp/|/etc/|HKEY|cmd|powershell|\.exe|\.dll|\.ps1|\.sh\b|password|passwd|"
                         r"token|key|socket|connect|http|User-Agent|mozilla|encrypt|decrypt|bitcoin|wallet|admin|inject", re.I)
    seen, picked = set(), []
    for s in strings:
        t = s.strip()
        if len(t) < 6 or t in seen or not keyword.search(t):
            continue
        seen.add(t)
        picked.append(t[:300])
        if len(picked) >= MAX_STRINGS_SHOWN:
            break
    return picked


# ------------------------------------------------------------------ 전체 분석

def verdict_for(score: int) -> Tuple[str, str]:
    if score >= 8:
        return VERDICT_HIGH, "HIGH"
    if score >= 4:
        return VERDICT_CHECK, "MEDIUM"
    return VERDICT_LOW, "LOW"


def analyze_upload(data: bytes, filename: str = "upload.bin", password: str = "",
                   time_limit: int = 300, enricher=None) -> Dict[str, Any]:
    """업로드 1건(단일 파일 또는 ZIP) 을 정적 분석해 dict 로 돌려줍니다."""
    if len(data) > MAX_UPLOAD:
        raise SampleError(f"업로드 최대 크기는 {MAX_UPLOAD // 1024 // 1024}MB 입니다.")
    if not data:
        raise SampleError("빈 파일입니다.")
    started = time.monotonic()
    deadline = started + max(10, time_limit)
    container = {"name": filename, "size": len(data), **hashes(data), "type": detect_type(data, filename)}
    warnings: List[str] = []
    files: List[Dict[str, Any]] = []
    password_used = None
    budget = [MAX_TOTAL_UNPACKED]
    queue: List[Tuple[str, bytes, int]] = []
    if container["type"] == "ZIP":
        members, password_used, w = unpack_zip(data, [password, *DEFAULT_PASSWORDS], budget)
        warnings += w
        queue = [(n, c, 1) for n, c in members]
        container["member_count"] = len(members)
    else:
        queue = [(filename, data, 0)]
    while queue:
        name, content, depth = queue.pop(0)
        if time.monotonic() > deadline:
            warnings.append(f"시간 한도({time_limit}초)를 넘어 나머지 {len(queue) + 1}개 파일은 분석하지 않았습니다.")
            break
        if detect_type(content, name) == "ZIP" and 0 < depth < MAX_DEPTH:
            try:
                inner, _, w = unpack_zip(content, [password, *DEFAULT_PASSWORDS], budget)
                warnings += [f"{name} 내부: {x}" for x in w]
                queue += [(f"{name}/{n}", c, depth + 1) for n, c in inner]
            except SampleError as exc:
                warnings.append(f"{name}: 내부 ZIP 을 열지 못했습니다 ({exc})")
        files.append(analyze_file(name, content, depth))

    ti = []
    if enricher is not None and getattr(enricher, "enabled", False) and getattr(enricher.settings, "vt_api_key", ""):
        from .analyzer import Iocs
        ti = [v.to_dict() for v in enricher.enrich(Iocs(sha256={f["sha256"] for f in files}))]
        for f in files:
            for v in ti:
                if v.get("value") == f["sha256"] and v.get("malicious"):
                    f["findings"].insert(0, {"name": "VirusTotal 악성 판정", "technique": "", "weight": 8,
                                             "evidence": [v.get("summary", "")]})
                    f["score"] += 8

    for f in files:
        f["verdict"], f["level"] = verdict_for(f["score"])
    top = max(files, key=lambda f: f["score"], default=None)
    score = top["score"] if top else 0
    verdict, level = verdict_for(score)
    result = {
        "id": container["sha256"][:16],
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "container": container, "password_used": bool(password_used),
        "files": files, "warnings": warnings, "threat_intel": ti,
        "summary": {"verdict": verdict, "level": level, "score": score,
                    "top_file": top["name"] if top else None, "file_count": len(files),
                    "techniques": sorted({x["technique"] for f in files for x in f["findings"] if x["technique"]}),
                    "disclaimer": "규칙 기반 정적 분석 결과이며 샘플을 실행하지 않았습니다. 최종 판단은 분석가가 합니다."},
    }
    result["report"] = build_report(result)
    return result


def build_report(r: Dict[str, Any]) -> str:
    s, c = r["summary"], r["container"]
    lines = ["# 파일 정적 분석 보고서", "",
             f"대상: {c['name']} ({c['size']:,} bytes, {c['type']})",
             f"SHA256: {c['sha256']}",
             f"판정: {s['verdict']} (점수 {s['score']}, 가장 위험한 파일: {s['top_file'] or '-'})",
             f"분석 시각: {r['analyzed_at']} · 소요 {r['elapsed_seconds']}초", ""]
    if r["warnings"]:
        lines += ["## 경고"] + [f"- {w}" for w in r["warnings"]] + [""]
    for f in r["files"]:
        lines += [f"## {f['name']}",
                  f"- 형식: {f['type']} · 크기 {f['size']:,} bytes · 엔트로피 {f['entropy']}",
                  f"- MD5 {f['md5']}", f"- SHA1 {f['sha1']}", f"- SHA256 {f['sha256']}",
                  f"- 판정: {f['verdict']} (점수 {f['score']})"]
        pe, elf = f.get("pe"), f.get("elf")
        if pe:
            lines += [f"- PE: {pe['machine']} {pe['bits']}bit {pe['kind']} · {pe['subsystem']} · 컴파일 {pe['compiled_at'] or '-'}",
                      f"- 서명 {'있음' if pe['signed'] else '없음'} · .NET {'예' if pe['dotnet'] else '아니오'} · ASLR {'on' if pe['aslr'] else 'off'} · DEP {'on' if pe['dep'] else 'off'} · imphash {pe['imphash'] or '-'}",
                      "- 섹션: " + ", ".join(f"{x['name']}({x['perms']}, H={x['entropy']})" for x in pe["sections"]),
                      f"- 임포트 {pe['import_count']}개: " + ", ".join(list(pe["imports"])[:15])]
        if elf:
            lines += [f"- ELF: {elf['machine']} {elf['bits']}bit {elf['kind']} · 인터프리터 {elf['interpreter'] or '없음(정적)'} · 심볼 {'제거됨' if elf['stripped'] else '있음'}",
                      "- 필요 라이브러리: " + (", ".join(elf["needed"]) or "-")]
        if f.get("parse_error"):
            lines.append(f"- {f['parse_error']}")
        if f["findings"]:
            lines.append("- 탐지 항목:")
            lines += [f"    · [{x['weight']}] {x['name']}{' (' + x['technique'] + ')' if x['technique'] else ''}: {x['evidence'][0][:150]}"
                      for x in f["findings"]]
        for k, label in (("urls", "URL"), ("ips", "IP"), ("domains", "도메인"), ("registry", "레지스트리"), ("emails", "이메일")):
            v = f["iocs"].get(k)
            if v:
                lines.append(f"- {label}: " + ", ".join(v[:10]) + (" …" if len(v) > 10 else ""))
        lines.append("")
    lines += ["## 다음 단계",
              "- 판정이 높으면 SHA256 으로 콘솔 Deep Visibility 에서 같은 해시가 다른 엔드포인트에 있는지 확인하세요 (S1QL: tgtFileSha256 = \"...\").",
              "- 추출된 URL/IP/도메인을 방화벽·프록시 로그에서 조회해 실제 통신 여부를 확인하세요.",
              "- 샘플 실행이 필요하면 격리된 샌드박스에서만 하세요. 이 도구는 샘플을 실행하지 않습니다.",
              "", "※ " + s["disclaimer"]]
    return "\n".join(lines)
