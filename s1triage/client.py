"""SentinelOne Management API 클라이언트 (위협 조회 + Deep Visibility 쿼리)."""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import Settings

log = logging.getLogger(__name__)

S1_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
DV_EVENTS_PAGE_SIZE = 1000  # /dv/events 의 페이지당 최대 건수
RATE_LIMIT_BASE_WAIT = 15  # 429 응답에 Retry-After 가 없을 때 첫 대기(초), 이후 2배씩
RATE_LIMIT_MAX_WAIT = 120


class S1ApiError(RuntimeError):
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class DvQueryTimeout(S1ApiError):
    pass


@dataclass
class Threat:
    threat_id: str
    threat_name: str
    storyline_id: Optional[str]
    created_at: Optional[str]
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    classification: Optional[str] = None
    confidence_level: Optional[str] = None
    sha1: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_api(cls, t: Dict[str, Any]) -> "Threat":
        info = t.get("threatInfo") or {}
        agent = t.get("agentRealtimeInfo") or t.get("agentDetectionInfo") or {}
        return cls(
            threat_id=str(t.get("id")),
            threat_name=info.get("threatName") or t.get("threatName") or "Unknown Threat",
            storyline_id=info.get("storyline") or t.get("storyline"),
            created_at=t.get("createdAt") or info.get("createdAt") or t.get("updatedAt"),
            agent_id=agent.get("agentId") or t.get("agentId"),
            agent_name=agent.get("agentComputerName") or t.get("agentComputerName"),
            classification=info.get("classification"),
            confidence_level=info.get("confidenceLevel"),
            sha1=info.get("sha1"),
            raw=t,
        )


def parse_s1_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def build_session(settings: Settings) -> requests.Session:
    """429/5xx 에 대해 지수 백오프 재시도(Retry-After 준수)를 거는 세션."""
    session = requests.Session()
    retry = Retry(
        total=settings.http_retries,
        backoff_factor=1.0,
        status_forcelist=(500, 502, 503, 504),  # 429 는 S1Client 에서 더 길게 대기하며 처리
        allowed_methods=frozenset({"GET", "POST"}),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update(
        {
            "Authorization": f"ApiToken {settings.api_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )
    return session


class S1Client:
    def __init__(
        self,
        settings: Settings,
        session: Optional[requests.Session] = None,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self.settings = settings
        self.base = settings.api_url
        self.session = session or build_session(settings)
        self._sleep = sleep
        self._now = now
        self._clock = time.monotonic
        self._last_dv_init: Optional[float] = None

    # ------------------------------------------------------------------ HTTP
    @staticmethod
    def _retry_after(resp: Any, attempt: int) -> float:
        headers = getattr(resp, "headers", None) or {}
        try:
            value = float(headers.get("Retry-After", ""))
            if value > 0:
                return min(value, RATE_LIMIT_MAX_WAIT)
        except (TypeError, ValueError):
            pass
        return min(RATE_LIMIT_BASE_WAIT * (2 ** attempt), RATE_LIMIT_MAX_WAIT)

    def _request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        url = f"{self.base}{path}"
        kwargs.setdefault("timeout", self.settings.http_timeout)
        attempt = 0
        while True:
            try:
                resp = self.session.request(method, url, **kwargs)
            except requests.RequestException as exc:
                raise S1ApiError(f"{method} {path} 요청 실패: {exc}") from exc
            if resp.status_code == 429 and attempt < self.settings.rate_limit_retries:
                wait = self._retry_after(resp, attempt)
                log.warning("%s %s -> 429 요청 과다, %.0f초 후 재시도 (%d/%d)",
                            method, path, wait, attempt + 1, self.settings.rate_limit_retries)
                self._sleep(wait)
                attempt += 1
                continue
            break
        if resp.status_code != 200:
            text = resp.text or ""
            if "<html" in text.lower():  # nginx 에러 페이지 등은 태그를 지우고 요약
                text = " ".join(re.sub(r"<[^>]+>", " ", text).split())
            raise S1ApiError(f"{method} {path} -> {resp.status_code}: {text[:300]}", resp.status_code)
        try:
            return resp.json()
        except ValueError as exc:
            raise S1ApiError(f"{method} {path} 응답이 JSON 이 아닙니다.") from exc

    # --------------------------------------------------------------- Threats
    def get_unresolved_threats(self, limit: Optional[int] = None) -> List[Threat]:
        """미해결 위협을 최신순으로 최대 limit 개 가져옵니다."""
        limit = limit or self.settings.threat_fetch_limit
        params = {
            "limit": min(limit, 1000),
            "resolved": "false",
            "sortBy": "createdAt",
            "sortOrder": "desc",
        }
        data = self._request("GET", "/threats", params=params)
        return [Threat.from_api(t) for t in data.get("data") or []]

    def get_threat(self, threat_id: str) -> Optional[Threat]:
        data = self._request("GET", "/threats", params={"ids": threat_id})
        items = data.get("data") or []
        return Threat.from_api(items[0]) if items else None

    # -------------------------------------------------------- Deep Visibility
    def dv_time_window(self, created_at: Optional[str]) -> tuple[datetime, datetime]:
        """위협 생성 시각 - lookback ~ 현재 시각. 생성 시각을 모르면 현재 기준."""
        now = self._now()
        anchor = parse_s1_time(created_at) or now
        if anchor > now:
            anchor = now
        return anchor - timedelta(hours=self.settings.dv_lookback_hours), now

    def build_storyline_query(self, storyline_id: str) -> str:
        safe = str(storyline_id).replace("\\", "\\\\").replace('"', '\\"')
        return self.settings.dv_query_template.format(storyline_id=safe)

    def _throttle_dv(self) -> None:
        """DV 쿼리는 레이트리밋이 엄격해서 연속 생성 사이에 최소 간격을 둡니다."""
        if self._last_dv_init is not None:
            gap = self.settings.dv_min_interval - (self._clock() - self._last_dv_init)
            if gap > 0:
                self._sleep(gap)
        self._last_dv_init = self._clock()

    def init_dv_query(self, query: str, from_date: datetime, to_date: datetime) -> str:
        self._throttle_dv()
        payload = {
            "query": query,
            "fromDate": from_date.strftime(S1_TIME_FORMAT),
            "toDate": to_date.strftime(S1_TIME_FORMAT),
            "limit": min(self.settings.dv_max_events, 20000),
        }
        data = self._request("POST", "/dv/init-query", json=payload)
        query_id = (data.get("data") or {}).get("queryId")
        if not query_id:
            raise S1ApiError(f"DV init-query 응답에 queryId 가 없습니다: {data}")
        return query_id

    def wait_dv_query(self, query_id: str, on_progress: Optional[Callable[[int], None]] = None) -> None:
        """쿼리가 끝날 때까지 상태를 폴링합니다. 실패/시간초과 시 예외."""
        poll = max(1, self.settings.dv_poll_seconds)
        attempts = max(1, self.settings.dv_timeout_seconds // poll)
        for _ in range(attempts):
            self._sleep(poll)
            try:
                data = self._request("GET", "/dv/query-status", params={"queryId": query_id})
            except S1ApiError as exc:
                log.warning("DV 쿼리 상태 조회 실패 (재시도): %s", exc)
                continue
            status = data.get("data") or {}
            state = str(status.get("responseState") or "").upper()
            progress = status.get("progressStatus", status.get("progressPercentage", 0))
            if on_progress:
                on_progress(progress)
            if state in {"FAILED", "FAILED_CLIENT", "TIMED_OUT", "QUERY_CANCELLED", "QUERY_EXPIRED"}:
                raise S1ApiError(f"DV 쿼리 실패 (state={state}): {status.get('responseError') or ''}")
            if status.get("isFinished") or state == "FINISHED":
                return
        raise DvQueryTimeout(f"DV 쿼리가 {self.settings.dv_timeout_seconds}초 안에 끝나지 않았습니다.")

    def iter_dv_events(self, query_id: str) -> Iterator[Dict[str, Any]]:
        """nextCursor 를 따라가며 모든 DV 이벤트를 가져옵니다 (dv_max_events 상한)."""
        cursor: Optional[str] = None
        fetched = 0
        while fetched < self.settings.dv_max_events:
            params: Dict[str, Any] = {
                "queryId": query_id,
                "limit": min(DV_EVENTS_PAGE_SIZE, self.settings.dv_max_events - fetched),
            }
            if cursor:
                params["cursor"] = cursor
            data = self._request("GET", "/dv/events", params=params)
            page = data.get("data") or []
            for event in page:
                yield event
            fetched += len(page)
            cursor = (data.get("pagination") or {}).get("nextCursor")
            if not cursor or not page:
                break

    def get_storyline_events(
        self,
        storyline_id: str,
        created_at: Optional[str] = None,
        on_progress: Optional[Callable[[int], None]] = None,
    ) -> List[Dict[str, Any]]:
        from_date, to_date = self.dv_time_window(created_at)
        query = self.build_storyline_query(storyline_id)
        query_id = self.init_dv_query(query, from_date, to_date)
        log.info("DV 쿼리 시작 queryId=%s query=%s", query_id, query)
        self.wait_dv_query(query_id, on_progress=on_progress)
        return list(self.iter_dv_events(query_id))
