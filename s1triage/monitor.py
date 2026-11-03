"""위협 폴링 -> DV 조회 -> 분석 -> TI 조회 -> 리포트 파이프라인."""

from __future__ import annotations

import argparse
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
        while True:
            try:
                if self.poll_once():
                    self.out("\n[+] 다음 신규 위협 대기 중...\n" + "=" * 65)
            except S1ApiError as exc:
                log.error("위협 목록 조회 실패: %s", exc)
            sleep(self.settings.poll_interval)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="s1triage", description="SentinelOne DV 기반 위협 자동 트리아지")
    parser.add_argument("--env-file", default=".env", help=".env 파일 경로 (기본: .env)")
    parser.add_argument("--once", action="store_true", help="한 번만 폴링하고 종료")
    parser.add_argument("--threat-id", help="특정 위협 ID 하나만 분석하고 종료")
    parser.add_argument("--skip-backlog", action="store_true", help="시작 시점의 기존 미해결 위협은 분석하지 않고 건너뜀")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    load_dotenv(args.env_file)
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
        pipeline.run_forever()
    except KeyboardInterrupt:
        print("\n[*] 사용자에 의해 모니터링 프로그램이 종료되었습니다.")
    except S1ApiError as exc:
        print(f"[-] API 오류: {exc}", file=sys.stderr)
        return 1
    return 0
