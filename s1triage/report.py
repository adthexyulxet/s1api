"""트리아지 결과 구조화 + 위험도 산정 + 출력."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .analyzer import AnalysisResult
from .client import Threat
from .enrichment import TiVerdict


@dataclass
class TriageReport:
    threat: Threat
    analysis: Optional[AnalysisResult]
    ti: List[TiVerdict] = field(default_factory=list)
    error: Optional[str] = None
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def score(self) -> int:
        s = 0
        if self.analysis:
            s += min(10, sum(f.weight for f in self.analysis.findings))
        s += 5 * sum(1 for v in self.ti if v.malicious)
        if (self.threat.confidence_level or "").lower() == "malicious":
            s += 3
        return s

    @property
    def level(self) -> str:
        if self.score >= 10:
            return "HIGH"
        if self.score >= 4:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> Dict[str, Any]:
        t = self.threat
        return {
            "generated_at": self.generated_at,
            "risk": {"score": self.score, "level": self.level},
            "threat": {
                "id": t.threat_id,
                "name": t.threat_name,
                "storyline_id": t.storyline_id,
                "created_at": t.created_at,
                "agent_id": t.agent_id,
                "agent_name": t.agent_name,
                "classification": t.classification,
                "confidence_level": t.confidence_level,
                "sha1": t.sha1,
            },
            "dv": None if not self.analysis else {
                "event_count": self.analysis.event_count,
                "event_types": self.analysis.event_types,
                "findings": [f.to_dict() for f in self.analysis.findings],
                "iocs": self.analysis.iocs.to_dict(),
            },
            "threat_intel": [v.to_dict() for v in self.ti],
            "error": self.error,
        }

    def save(self, directory: str) -> Path:
        out = Path(directory)
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"threat_{self.threat.threat_id}.json"
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return path


def _short(text: Optional[str], n: int = 160) -> str:
    if not text:
        return "-"
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 3] + "..."


def format_report(r: TriageReport) -> str:
    t = r.threat
    lines = [
        "    ---------------- [Analysis Report] ----------------",
        f"    위험도: {r.level} (점수 {r.score})",
        f"    위협: {t.threat_name} | ID {t.threat_id} | 분류 {t.classification or '-'} / {t.confidence_level or '-'}",
        f"    엔드포인트: {t.agent_name or '-'} ({t.agent_id or '-'})",
        f"    Storyline: {t.storyline_id or '-'} | 생성: {t.created_at or '-'}",
    ]
    if r.error:
        lines.append(f"    [-] 오류: {r.error}")
    a = r.analysis
    if a is not None:
        types = ", ".join(f"{k} {v}" for k, v in sorted(a.event_types.items(), key=lambda kv: -kv[1])[:6])
        lines.append(f"    DV 이벤트: {a.event_count}개 ({types or '-'})")
        if a.findings:
            lines.append(f"    의심 행위 {len(a.findings)}건:")
            for f in a.findings[:20]:
                lines.append(f"      - [{f.technique}] {f.category}")
                lines.append(f"        프로세스: {f.process or '-'} (부모: {f.parent or '-'})")
                lines.append(f"        명령어: {_short(f.cmdline)}")
                lines.append(f"        SHA1: {f.sha1 or '-'}")
            if len(a.findings) > 20:
                lines.append(f"      ... 외 {len(a.findings) - 20}건 (JSON 리포트 참고)")
        elif a.event_count:
            lines.append("    - 수집된 이벤트는 있으나 지정된 의심 패턴과 일치하는 항목이 없습니다.")
        else:
            lines.append("    - 조회 범위에서 이 Storyline 의 DV 이벤트를 찾지 못했습니다. (인덱싱 지연이면 나중에 --threat-id 로 다시 조회해 보세요)")
        i = a.iocs
        lines.append(
            f"    IOC: 외부 IP {len(i.ips)} / 도메인 {len(i.domains)} / SHA1 {len(i.sha1)} / SHA256 {len(i.sha256)}"
        )
        for label, values in (("IP", i.ips), ("도메인", i.domains)):
            if values:
                shown = sorted(values)[:10]
                more = f" 외 {len(values) - 10}개" if len(values) > 10 else ""
                lines.append(f"      {label}: {', '.join(shown)}{more}")
    if r.ti:
        lines.append("    위협 인텔리전스:")
        for v in r.ti:
            mark = "!!" if v.malicious else "  "
            lines.append(f"     {mark} {v.source} {v.ioc_type} {v.value}: {v.summary}")
    lines.append("    ---------------------------------------------------")
    return "\n".join(lines)
