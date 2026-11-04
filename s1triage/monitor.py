"""위협 폴링 -> DV 조회 -> 분석 -> TI 조회 -> 리포트 파이프라인."""

from __future__ import annotations

import argparse
import dataclasses
import os
import logging
import sys
import time
from typing import Callable, List, Optional

from .analyzer import analyze_events
from .client import S1ApiError, S1Client, Threat
from .config import ConfigError, Settings, load_dotenv
from .enrichment import Enricher
from .report import TriageReport, format_report
from .state import SeenThreats

log = logging.getLogger("s1triage")


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


class TriagePipeline:
    def __init__(
        self,
        settings: Settings,
        client: Optional[S1Client] = None,
        enricher: Optional[Enricher] = None,
        seen: Optional[SeenThreats] = None,
        out: Callable[[str], None] = print,
    ):
        self.settings = settings
        self.client = client or S1Client(settings)
        self.enricher = enricher or Enricher(settings)
        self.seen = seen if seen is not None else SeenThreats(settings.state_file)
        self.out = out
        self.status = {"started_at": None, "last_poll_at": None, "last_error": None,
                       "polls": 0, "analyzed": 0}

    def triage(self, threat: Threat) -> TriageReport:
        out = self.out
        out("\n[!] 새로운 위협 감지됨!")
        out(f"    - Threat ID: {threat.threat_id} | Name: {threat.threat_name}")
        out(f"    - Target Storyline ID: {threat.storyline_id}")
        out(f"    - Threat Created At: {threat.created_at}")

        if not threat.storyline_id:
            report = TriageReport(threat, None, error="Storyline ID 가 없어 DV 조회를 건너뜁니다.")
        else:
            try:
                events = self.client.get_storyline_events(
                    threat.storyline_id,
                    threat.created_at,
                    on_progress=lambda p: out(f"    - Query Progress: {p}%"),
                )
                out(f"    [*] 연관 DV 이벤트 수집 완료: {len(events)}개")
                analysis = analyze_events(events)
                ti = self.enricher.enrich(analysis.iocs) if self.enricher.enabled else []
                report = TriageReport(threat, analysis, ti)
                if self.settings.report_raw_events:
                    report.raw_events = events
            except S1ApiError as exc:
                report = TriageReport(threat, None, error=str(exc))

        out(format_report(report))
        if self.settings.report_dir:
            path = report.save(self.settings.report_dir)
            out(f"    [+] JSON 리포트 저장: {path}")
        return report

    def poll_once(self) -> List[TriageReport]:
        """미해결 위협 목록 중 아직 처리하지 않은 것들을 오래된 순으로 분석합니다."""
        threats = self.client.get_unresolved_threats()
        new = [t for t in threats if t.threat_id not in self.seen]
        reports = []
        for threat in reversed(new):  # API 는 최신순 -> 오래된 것부터 처리
            reports.append(self.triage(threat))
            # DV 조회가 실패한 위협은 다음 폴링에서 재시도하도록 기록하지 않음
            if reports[-1].error is None or not threat.storyline_id:
                self.seen.add(threat.threat_id)
        return reports

    def mark_backlog_seen(self) -> int:
        count = 0
        for t in self.client.get_unresolved_threats():
            if t.threat_id not in self.seen:
                self.seen.add(t.threat_id)
                count += 1
        return count

    def run_forever(self, sleep: Callable[[float], None] = time.sleep) -> None:
        self.out("[*] SentinelOne 실시간 위협 모니터링 및 DV 분석 데몬 시작... (종료: Ctrl + C)\n")
        self.status["started_at"] = _now_iso()
        while True:
            try:
                reports = self.poll_once()
                self.status["last_error"] = None
                self.status["analyzed"] += len(reports)
                if reports:
                    self.out("\n[+] 다음 신규 위협 대기 중...\n" + "=" * 65)
            except S1ApiError as exc:
                log.error("위협 목록 조회 실패: %s", exc)
                self.status["last_error"] = str(exc)
            self.status["polls"] += 1
            self.status["last_poll_at"] = _now_iso()
            sleep(self.settings.poll_interval)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="s1triage", description="SentinelOne DV 기반 위협 자동 트리아지")
    parser.add_argument("--env-file", default=".env", help=".env 파일 경로 (기본: .env)")
    parser.add_argument("--once", action="store_true", help="한 번만 폴링하고 종료")
    parser.add_argument("--threat-id", help="특정 위협 ID 하나만 분석하고 종료")
    parser.add_argument("--skip-backlog", action="store_true", help="시작 시점의 기존 미해결 위협은 분석하지 않고 건너뜀")
    parser.add_argument("--web", action="store_true", help="모니터링을 실행하면서 웹 화면도 함께 띄움")
    parser.add_argument("--web-only", action="store_true", help="모니터링 없이 저장된 리포트만 웹 화면으로 보기 (토큰 불필요)")
    parser.add_argument("--port", type=int, default=None, help="웹 화면 포트 (기본: WEB_PORT 또는 8080)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    load_dotenv(args.env_file)
    if args.web_only:
        from .web import serve

        try:
            serve(os.environ.get("REPORT_DIR") or "reports", port=args.port)
        except KeyboardInterrupt:
            print("\n[*] 웹 화면을 종료했습니다.")
        except OSError as exc:
            print(f"[-] 웹 서버를 시작하지 못했습니다 (포트가 사용 중이면 --port 로 바꾸세요): {exc}", file=sys.stderr)
            return 1
        return 0
    try:
        settings = Settings.from_env()
    except ConfigError as exc:
        print(f"[설정 오류] {exc}", file=sys.stderr)
        return 2

    pipeline = TriagePipeline(settings)
    try:
        if args.threat_id:
            threat = pipeline.client.get_threat(args.threat_id)
            if not threat:
                print(f"[-] 위협을 찾을 수 없습니다: {args.threat_id}", file=sys.stderr)
                return 1
            pipeline.triage(threat)
            return 0
        if args.skip_backlog:
            n = pipeline.mark_backlog_seen()
            print(f"[*] 기존 미해결 위협 {n}건을 건너뜁니다.")
        if args.once:
            pipeline.poll_once()
            return 0
        if args.web:
            import threading

            from .web import serve

            if not settings.report_dir:  # 웹 화면은 저장된 JSON 리포트를 읽으므로 저장을 켬
                pipeline.settings = settings = dataclasses.replace(settings, report_dir="reports")
            threading.Thread(target=pipeline.run_forever, name="monitor", daemon=True).start()
            serve(settings.report_dir, port=args.port, status=pipeline.status)
            return 0
        pipeline.run_forever()
    except KeyboardInterrupt:
        print("\n[*] 사용자에 의해 모니터링 프로그램이 종료되었습니다.")
    except S1ApiError as exc:
        print(f"[-] API 오류: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"[-] 웹 서버를 시작하지 못했습니다 (포트가 사용 중이면 --port 로 바꾸세요): {exc}", file=sys.stderr)
        return 1
    return 0
