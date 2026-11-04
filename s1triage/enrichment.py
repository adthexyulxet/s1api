"""선택적 위협 인텔리전스 조회 (VirusTotal / AbuseIPDB).

API 키가 설정된 경우에만 동작하며, 조회 실패는 분석 전체를 중단시키지 않습니다.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests

from .analyzer import Iocs
from .config import Settings

log = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSE_SCORE_MALICIOUS = 75


@dataclass
class TiVerdict:
    source: str
    ioc_type: str
    value: str
    malicious: bool
    summary: str
    link: Optional[str] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


class Enricher:
    def __init__(self, settings: Settings, session: Optional[requests.Session] = None):
        self.settings = settings
        self.session = session or requests.Session()
        self._cache: Dict[tuple, Optional[TiVerdict]] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.settings.vt_api_key or self.settings.abuseipdb_api_key)

    def enrich(self, iocs: Iocs) -> List[TiVerdict]:
        if not self.enabled:
            return []
        budget = max(0, self.settings.enrich_max_lookups)
        jobs = []
        # 해시 > IP > 도메인 순으로 우선순위
        if self.settings.vt_api_key:
            jobs += [(self._vt, "file", h) for h in sorted(iocs.sha256 | iocs.sha1)]
        if self.settings.abuseipdb_api_key:
            jobs += [(self._abuseipdb, "ip", ip) for ip in sorted(iocs.ips)]
        elif self.settings.vt_api_key:
            jobs += [(self._vt, "ip", ip) for ip in sorted(iocs.ips)]
        if self.settings.vt_api_key:
            jobs += [(self._vt, "domain", d) for d in sorted(iocs.domains)]

        results: List[TiVerdict] = []
        lookups = 0
        for fn, kind, value in jobs:
            key = (fn.__name__, kind, value)
            if key not in self._cache:
                if lookups >= budget:
                    log.info("TI 조회 한도(%d) 도달, 나머지 %s 생략", budget, value)
                    continue
                lookups += 1
                try:
                    self._cache[key] = fn(kind, value)
                except requests.RequestException as exc:
                    log.warning("TI 조회 실패 %s %s: %s", kind, value, exc)
                    self._cache[key] = None
            verdict = self._cache[key]
            if verdict:
                results.append(verdict)
        return results

    # ------------------------------------------------------------ VirusTotal
    def _vt(self, kind: str, value: str) -> Optional[TiVerdict]:
        path = {"file": "files", "ip": "ip_addresses", "domain": "domains"}[kind]
        resp = self.session.get(
            f"{VT_BASE}/{path}/{value}",
            headers={"x-apikey": self.settings.vt_api_key},
            timeout=self.settings.http_timeout,
        )
        gui = {"file": "file", "ip": "ip-address", "domain": "domain"}[kind]
        link = f"https://www.virustotal.com/gui/{gui}/{value}"
        if resp.status_code == 404:
            return TiVerdict("VirusTotal", kind, value, False, "VT 데이터 없음", link)
        if resp.status_code != 200:
            log.warning("VirusTotal %s %s -> %s", kind, value, resp.status_code)
            return None
        attrs = (resp.json().get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        mal = int(stats.get("malicious", 0))
        sus = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
        return TiVerdict(
            "VirusTotal", kind, value, mal > 0,
            f"악성 {mal} / 의심 {sus} / 전체 {total}", link,
            {"stats": stats, "reputation": attrs.get("reputation")},
        )

    # ------------------------------------------------------------- AbuseIPDB
    def _abuseipdb(self, kind: str, value: str) -> Optional[TiVerdict]:
        resp = self.session.get(
            ABUSEIPDB_URL,
            headers={"Key": self.settings.abuseipdb_api_key, "Accept": "application/json"},
            params={"ipAddress": value, "maxAgeInDays": 90},
            timeout=self.settings.http_timeout,
        )
        if resp.status_code != 200:
            log.warning("AbuseIPDB %s -> %s", value, resp.status_code)
            return None
        d = resp.json().get("data") or {}
        score = int(d.get("abuseConfidenceScore", 0))
        return TiVerdict(
            "AbuseIPDB", "ip", value, score >= ABUSE_SCORE_MALICIOUS,
            f"신뢰도 점수 {score} / 신고 {d.get('totalReports', 0)}건 / {d.get('countryCode') or '-'} {d.get('isp') or ''}".strip(),
            f"https://www.abuseipdb.com/check/{value}",
            {"score": score, "usageType": d.get("usageType")},
        )
