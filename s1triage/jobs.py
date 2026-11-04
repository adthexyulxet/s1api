"""웹 화면에서 요청한 정밀 분석을 백그라운드로 실행하고 결과를 저장합니다."""

from __future__ import annotations

import dataclasses
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .client import S1ApiError, S1Client
from .config import Settings
from .enrichment import Enricher
from .narrative import build_outputs
from .state import SeenThreats

log = logging.getLogger(__name__)

MIN_TIMEOUT, MAX_TIMEOUT = 30, 1800
MAX_JOBS_KEPT = 50


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclasses.dataclass
class Job:
    id: str
    threat_id: str
    options: Dict[str, Any]
    status: str = "queued"  # queued / running / done / error
    logs: List[str] = dataclasses.field(default_factory=list)
    error: Optional[str] = None
    created_at: str = dataclasses.field(default_factory=_now)
    finished_at: Optional[str] = None

    def log(self, line: str) -> None:
        for part in str(line).splitlines():
            if part.strip():
                self.logs.append(part)
        del self.logs[:-400]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


def analysis_path(report_dir: str, threat_id: str) -> Path:
    return Path(report_dir) / f"analysis_{threat_id}.json"


def save_analysis(report_dir: str, report: Dict[str, Any], options: Dict[str, Any]) -> Dict[str, Any]:
    data = {
        "analyzed_at": _now(),
        "options": options,
        "report": report,
        **build_outputs(report),
    }
    path = analysis_path(report_dir, str((report.get("threat") or {}).get("id")))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return data


class JobManager:
    """정밀 분석 요청을 받아 하나씩 순서대로 실행합니다 (DV 레이트리밋 보호)."""

    def __init__(self, report_dir: str, settings: Optional[Settings] = None, client_factory=S1Client):
        self.report_dir = report_dir
        self.settings = settings
        self.client_factory = client_factory
        self.jobs: Dict[str, Job] = {}
        self._run_lock = threading.Lock()
        self._lock = threading.Lock()

    @property
    def can_query(self) -> bool:
        return self.settings is not None

    def submit(self, threat_id: str, refresh: bool = True, use_ti: bool = True, timeout: int = 300) -> Job:
        timeout = max(MIN_TIMEOUT, min(MAX_TIMEOUT, int(timeout)))
        if refresh and not self.can_query:
            raise ValueError("토큰 없이 실행 중이라 DV 를 새로 조회할 수 없습니다. 저장된 결과로 분석하세요.")
        if not refresh and not (Path(self.report_dir) / f"threat_{threat_id}.json").is_file():
            raise ValueError("이 위협의 저장된 리포트가 없습니다. 'DV 새로 조회'를 켜고 실행하세요.")
        job = Job(uuid.uuid4().hex[:12], threat_id, {"refresh": refresh, "use_ti": use_ti, "timeout": timeout})
        with self._lock:
            self.jobs[job.id] = job
            for old in list(self.jobs)[:-MAX_JOBS_KEPT]:
                self.jobs.pop(old, None)
        threading.Thread(target=self._run, args=(job,), name=f"analysis-{job.id}", daemon=True).start()
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return self.jobs.get(job_id)

    def _run(self, job: Job) -> None:
        if self._run_lock.locked():
            job.log("[*] 다른 분석이 진행 중이라 대기합니다...")
        with self._run_lock:
            job.status = "running"
            started = time.monotonic()
            try:
                report = self._fresh_report(job) if job.options["refresh"] else self._saved_report(job)
                job.log("[*] 판정·해설서·콘솔 Notes 초안 생성 중...")
                save_analysis(self.report_dir, report, job.options)
                job.log(f"[+] 정밀 분석 완료 ({time.monotonic() - started:.0f}초)")
                job.status = "done"
            except (S1ApiError, ValueError, OSError) as exc:
                job.error = str(exc)
                job.log(f"[-] 실패: {exc}")
                job.status = "error"
            except Exception as exc:  # 예기치 못한 오류도 화면에 보여줌
                log.exception("정밀 분석 실패")
                job.error = f"예기치 못한 오류: {exc}"
                job.status = "error"
            finally:
                job.finished_at = _now()

    def _saved_report(self, job: Job) -> Dict[str, Any]:
        job.log("[*] 저장된 리포트로 분석합니다 (DV 재조회 없음).")
        path = Path(self.report_dir) / f"threat_{job.threat_id}.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def _fresh_report(self, job: Job) -> Dict[str, Any]:
        from .monitor import TriagePipeline  # 순환 import 방지

        opts = job.options
        settings = dataclasses.replace(
            self.settings,
            report_dir=self.report_dir,
            dv_timeout_seconds=opts["timeout"],
        )
        if not opts["use_ti"]:
            settings = dataclasses.replace(settings, vt_api_key="", abuseipdb_api_key="")
        elif not (settings.vt_api_key or settings.abuseipdb_api_key):
            job.log("[!] VT_API_KEY / ABUSEIPDB_API_KEY 가 없어 온라인 위협인텔 조회는 건너뜁니다.")
        client = self.client_factory(settings)
        pipeline = TriagePipeline(settings, client=client, enricher=Enricher(settings),
                                  seen=SeenThreats(""), out=job.log)
        job.log(f"[*] 위협 조회: {job.threat_id}")
        threat = client.get_threat(job.threat_id)
        if not threat:
            raise ValueError(f"위협을 찾을 수 없습니다: {job.threat_id} (Threat ID 를 확인하세요)")
        report = pipeline.triage(threat)
        return report.to_dict()
