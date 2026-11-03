"""환경변수(.env 포함)에서 설정을 읽어옵니다.

토큰/URL 같은 비밀값은 코드에 하드코딩하지 않고 반드시 환경변수로 주입합니다.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional


class ConfigError(ValueError):
    """필수 설정이 없거나 값이 잘못된 경우."""


def load_dotenv(path: str | os.PathLike = ".env", environ: Optional[dict] = None) -> None:
    """의존성 없이 간단한 KEY=VALUE 형식의 .env 파일을 읽습니다.

    이미 설정된 환경변수는 덮어쓰지 않습니다.
    """
    env = os.environ if environ is None else environ
    p = Path(path)
    if not p.is_file():
        return
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        env.setdefault(key, value)


def _int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = env.get(key, "")
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{key} 값은 정수여야 합니다: {raw!r}") from exc


@dataclass(frozen=True)
class Settings:
    api_url: str
    api_token: str
    poll_interval: int = 30
    threat_fetch_limit: int = 20
    state_file: str = "state/seen_threats.json"
    dv_lookback_hours: int = 24
    dv_query_template: str = 'storyline = "{storyline_id}"'
    dv_poll_seconds: int = 3
    dv_timeout_seconds: int = 90
    dv_max_events: int = 5000
    http_timeout: int = 30
    http_retries: int = 3
    rate_limit_retries: int = 4
    dv_min_interval: int = 10
    vt_api_key: str = ""
    abuseipdb_api_key: str = ""
    enrich_max_lookups: int = 10
    report_dir: str = ""
    report_raw_events: bool = False

    def __repr__(self) -> str:  # 토큰이 로그에 찍히지 않도록 마스킹
        return (
            f"Settings(api_url={self.api_url!r}, api_token='***', "
            f"poll_interval={self.poll_interval}, vt={'on' if self.vt_api_key else 'off'}, "
            f"abuseipdb={'on' if self.abuseipdb_api_key else 'off'})"
        )

    __str__ = __repr__

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        env = os.environ if env is None else env
        api_url = (env.get("S1_API_URL") or "").strip().rstrip("/")
        api_token = (env.get("S1_API_TOKEN") or "").strip()
        if not api_url:
            raise ConfigError("S1_API_URL 환경변수가 필요합니다. (.env.example 참고)")
        if not api_token:
            raise ConfigError("S1_API_TOKEN 환경변수가 필요합니다. (.env.example 참고)")
        if not api_url.startswith("https://"):
            raise ConfigError("S1_API_URL 은 https:// 로 시작해야 합니다.")

        template = env.get("S1_DV_QUERY_TEMPLATE") or cls.dv_query_template
        if "{storyline_id}" not in template:
            raise ConfigError("S1_DV_QUERY_TEMPLATE 에 {storyline_id} 자리표시자가 있어야 합니다.")

        return cls(
            api_url=api_url,
            api_token=api_token,
            poll_interval=_int(env, "S1_POLL_INTERVAL", cls.poll_interval),
            threat_fetch_limit=_int(env, "S1_THREAT_FETCH_LIMIT", cls.threat_fetch_limit),
            state_file=env.get("S1_STATE_FILE") or cls.state_file,
            dv_lookback_hours=_int(env, "S1_DV_LOOKBACK_HOURS", cls.dv_lookback_hours),
            dv_query_template=template,
            dv_poll_seconds=_int(env, "S1_DV_POLL_SECONDS", cls.dv_poll_seconds),
            dv_timeout_seconds=_int(env, "S1_DV_TIMEOUT_SECONDS", cls.dv_timeout_seconds),
            dv_max_events=_int(env, "S1_DV_MAX_EVENTS", cls.dv_max_events),
            http_timeout=_int(env, "S1_HTTP_TIMEOUT", cls.http_timeout),
            http_retries=_int(env, "S1_HTTP_RETRIES", cls.http_retries),
            rate_limit_retries=_int(env, "S1_RATE_LIMIT_RETRIES", cls.rate_limit_retries),
            dv_min_interval=_int(env, "S1_DV_MIN_INTERVAL", cls.dv_min_interval),
            vt_api_key=(env.get("VT_API_KEY") or "").strip(),
            abuseipdb_api_key=(env.get("ABUSEIPDB_API_KEY") or "").strip(),
            enrich_max_lookups=_int(env, "ENRICH_MAX_LOOKUPS", cls.enrich_max_lookups),
            report_dir=(env.get("REPORT_DIR") or "").strip(),
            report_raw_events=(env.get("REPORT_RAW_EVENTS") or "").strip().lower() in {"1", "true", "yes", "on"},
        )
