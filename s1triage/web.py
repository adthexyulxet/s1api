"""저장된 JSON 리포트를 브라우저로 보여주는 로컬 웹 화면 (표준 라이브러리만 사용).

기본으로 127.0.0.1 에만 열리므로 같은 PC 에서만 접속할 수 있습니다.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from .ai_verdict import ai_available
from .client import S1ApiError

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"
SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class ReportStore:
    """report_dir 의 threat_<ID>.json 파일을 읽습니다 (수정 시각 기준 캐시)."""

    def __init__(self, report_dir: str):
        self.dir = Path(report_dir)
        self._cache: Dict[Path, Tuple[float, Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def _load(self, path: Path) -> Optional[Dict[str, Any]]:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        with self._lock:
            cached = self._cache.get(path)
            if cached and cached[0] == mtime:
                return cached[1]
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            log.warning("리포트를 읽지 못했습니다 %s: %s", path, exc)
            return None
        with self._lock:
            self._cache[path] = (mtime, data)
        return data

    def list(self) -> List[Dict[str, Any]]:
        if not self.dir.is_dir():
            return []
        items = []
        for path in self.dir.glob("threat_*.json"):
            data = self._load(path)
            if data:
                items.append(summarize(data))
        items.sort(key=lambda r: r.get("created_at") or "", reverse=True)
        return items

    def get(self, threat_id: str) -> Optional[Dict[str, Any]]:
        if not SAFE_ID.match(threat_id):
            return None
        return self._load(self.dir / f"threat_{threat_id}.json")

    def list_analyses(self, limit: int = 30) -> List[Dict[str, Any]]:
        if not self.dir.is_dir():
            return []
        items = []
        for path in self.dir.glob("analysis_*.json"):
            data = self._load(path)
            if not data:
                continue
            t = (data.get("report") or {}).get("threat") or {}
            c = data.get("conclusion") or {}
            ai = data.get("ai_verdict") or {}
            items.append({"id": t.get("id"), "name": t.get("name"), "agent_name": t.get("agent_name"),
                          "verdict": c.get("verdict"), "risk": c.get("risk") or {},
                          "ai_verdict": None if ai.get("error") else ai.get("verdict"),
                          "analyzed_at": data.get("analyzed_at")})
        items.sort(key=lambda r: r.get("analyzed_at") or "", reverse=True)
        return items[:limit]

    def get_analysis(self, threat_id: str) -> Optional[Dict[str, Any]]:
        if not SAFE_ID.match(threat_id):
            return None
        return self._load(self.dir / f"analysis_{threat_id}.json")

    def list_samples(self, limit: int = 30) -> List[Dict[str, Any]]:
        if not self.dir.is_dir():
            return []
        items = []
        for path in self.dir.glob("sample_*.json"):
            data = self._load(path)
            if data:
                c, s = data.get("container") or {}, data.get("summary") or {}
                items.append({"id": data.get("id"), "name": c.get("name"), "type": c.get("type"),
                              "file_count": s.get("file_count"), "verdict": s.get("verdict"),
                              "score": s.get("score"), "analyzed_at": data.get("analyzed_at")})
        items.sort(key=lambda r: r.get("analyzed_at") or "", reverse=True)
        return items[:limit]

    def get_sample(self, sample_id: str) -> Optional[Dict[str, Any]]:
        if not SAFE_ID.match(sample_id):
            return None
        return self._load(self.dir / f"sample_{sample_id}.json")


def summarize(data: Dict[str, Any]) -> Dict[str, Any]:
    t = data.get("threat") or {}
    dv = data.get("dv") or {}
    behavior = dv.get("behavior") or {}
    return {
        "id": t.get("id"),
        "name": t.get("name"),
        "created_at": t.get("created_at"),
        "agent_name": t.get("agent_name"),
        "classification": t.get("classification"),
        "confidence_level": t.get("confidence_level"),
        "risk": data.get("risk") or {},
        "event_count": dv.get("event_count"),
        "highlights": [h.get("name") for h in behavior.get("highlights") or []],
        "malicious_ti": sum(1 for v in data.get("threat_intel") or [] if v.get("malicious")),
        "error": data.get("error"),
        "generated_at": data.get("generated_at"),
    }


def threat_row(t, store: "ReportStore") -> Dict[str, Any]:
    analysis = store.get_analysis(str(t.threat_id)) or {}
    ai = analysis.get("ai_verdict") or {}
    return {
        "id": t.threat_id, "name": t.threat_name, "created_at": t.created_at,
        "agent_name": t.agent_name, "agent_id": t.agent_id, "os": t.os_name,
        "classification": t.classification, "confidence_level": t.confidence_level,
        "incident_status": t.incident_status, "analyst_verdict": t.analyst_verdict,
        "mitigation_status": t.mitigation_status, "file_path": t.file_path,
        "storyline_id": t.storyline_id, "sha1": t.sha1,
        "has_report": (store.dir / f"threat_{t.threat_id}.json").is_file() if SAFE_ID.match(str(t.threat_id)) else False,
        "analysis": None if not analysis else {
            "verdict": (analysis.get("conclusion") or {}).get("verdict"),
            "risk": (analysis.get("conclusion") or {}).get("risk"),
            "ai_verdict": None if ai.get("error") else ai.get("verdict"),
            "analyzed_at": analysis.get("analyzed_at"),
        },
    }


def saved_threat_rows(store: "ReportStore") -> List[Dict[str, Any]]:
    """콘솔에 연결하지 않을 때: 저장된 리포트로 목록을 만듭니다."""
    from .client import Threat

    rows = []
    for path in sorted(store.dir.glob("threat_*.json")) if store.dir.is_dir() else []:
        data = store._load(path)
        if not data:
            continue
        t = data.get("threat") or {}
        threat = Threat(threat_id=str(t.get("id")), threat_name=t.get("name") or "-", storyline_id=t.get("storyline_id"),
                        created_at=t.get("created_at"), agent_id=t.get("agent_id"), agent_name=t.get("agent_name"),
                        classification=t.get("classification"), confidence_level=t.get("confidence_level"), sha1=t.get("sha1"))
        rows.append(threat_row(threat, store))
    rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    return rows


def make_handler(store: ReportStore, status: Optional[Dict[str, Any]], jobs=None):
    settings = getattr(jobs, "settings", None)
    index_html = (STATIC_DIR / "index.html").read_bytes()
    client_holder: Dict[str, Any] = {}

    def console_client():
        if not (jobs and jobs.settings):
            return None
        if "client" not in client_holder:
            client_holder["client"] = jobs.client_factory(jobs.settings)
        return client_holder["client"]

    class Handler(BaseHTTPRequestHandler):
        server_version = "s1triage"

        def log_message(self, fmt, *args):  # 콘솔을 어지럽히지 않도록 debug 로만
            log.debug("web: " + fmt, *args)

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj: Any, code: int = 200) -> None:
            self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

        def do_GET(self):
            path = unquote(urlparse(self.path).path)
            if path in ("/", "/index.html"):
                return self._send(200, index_html, "text/html; charset=utf-8")
            if path == "/api/reports":
                return self._json(store.list())
            if path.startswith("/api/reports/"):
                report = store.get(path[len("/api/reports/"):])
                if report is None:
                    return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return self._json(report)
            if path == "/api/status":
                return self._json({"monitoring": status is not None, **(status or {}),
                                   "can_query": bool(jobs and jobs.can_query),
                                   "ai_available": ai_available(),
                                   "report_dir": str(store.dir.resolve())})
            if path == "/api/threats":
                q = parse_qs(urlparse(self.path).query)
                client = console_client()
                if client is None:
                    return self._json({"source": "saved", "items": saved_threat_rows(store),
                                       "next_cursor": None, "total": None})
                try:
                    limit = int((q.get("limit") or ["50"])[0])
                except ValueError:
                    limit = 50
                try:
                    threats, cursor, total = client.list_threats(
                        limit=limit, cursor=(q.get("cursor") or [None])[0],
                        unresolved_only=(q.get("status") or ["all"])[0] == "unresolved")
                except S1ApiError as exc:
                    return self._json({"error": f"콘솔 조회 실패: {exc}"}, HTTPStatus.BAD_GATEWAY)
                return self._json({"source": "console", "items": [threat_row(t, store) for t in threats],
                                   "next_cursor": cursor, "total": total})
            if path == "/api/analyses":
                return self._json(store.list_analyses())
            if path.startswith("/api/analyses/"):
                data = store.get_analysis(path[len("/api/analyses/"):])
                if data is None:
                    return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return self._json(data)
            if path == "/api/samples":
                return self._json({"default_password": os.environ.get("SAMPLE_ZIP_PASSWORD") or "infected",
                                   "can_ti": bool(settings and settings.vt_api_key),
                                   "items": store.list_samples()})
            if path.startswith("/api/samples/"):
                data = store.get_sample(path[len("/api/samples/"):])
                if data is None:
                    return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return self._json(data)
            if path.startswith("/api/jobs/") and jobs:
                job = jobs.get(path[len("/api/jobs/"):])
                if job is None:
                    return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return self._json(job.to_dict())
            return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def _same_origin(self) -> bool:
            # 다른 웹사이트가 브라우저를 통해 로컬 서버에 분석을 요청하는 것(CSRF)을 막습니다.
            if self.headers.get("X-S1Triage") != "1":
                return False
            origin = self.headers.get("Origin")
            host = self.headers.get("Host", "")
            return origin is None or origin in (f"http://{host}", f"https://{host}")

        def _sample(self):
            from .enrichment import Enricher
            from .sample import MAX_UPLOAD, SampleError, analyze_upload

            if not self._same_origin():
                return self._json({"error": "forbidden"}, HTTPStatus.FORBIDDEN)
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_UPLOAD:
                self.close_connection = True
                return self._json({"error": f"업로드 최대 크기는 {MAX_UPLOAD // 1024 // 1024}MB 입니다."},
                                  HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            data = self.rfile.read(length) if length > 0 else b""
            query = parse_qs(urlparse(self.path).query)
            name = Path(unquote(self.headers.get("X-Filename") or "upload.bin")).name[:200] or "upload.bin"
            password = unquote(self.headers.get("X-Zip-Password") or "")
            use_ti = (query.get("use_ti") or ["0"])[0] == "1"
            try:
                timeout = int((query.get("timeout") or ["300"])[0])
            except ValueError:
                timeout = 300
            enricher = Enricher(settings) if use_ti and settings and settings.vt_api_key else None
            try:
                result = analyze_upload(data, name, password, time_limit=max(10, min(timeout, 1800)), enricher=enricher)
            except SampleError as exc:
                return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            store.dir.mkdir(parents=True, exist_ok=True)
            (store.dir / f"sample_{result['id']}.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            return self._json(result)

        def do_POST(self):
            path = urlparse(self.path).path
            if path == "/api/sample":
                return self._sample()
            if path != "/api/analyze" or not jobs:
                return self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            if not self._same_origin():
                return self._json({"error": "forbidden"}, HTTPStatus.FORBIDDEN)
            try:
                length = min(int(self.headers.get("Content-Length") or 0), 10_000)
                body = json.loads(self.rfile.read(length) or b"{}")
                threat_id = str(body.get("threat_id") or "").strip()
                if not SAFE_ID.match(threat_id):
                    raise ValueError("Threat ID 를 확인하세요 (숫자/영문만 가능).")
                job = jobs.submit(threat_id, refresh=bool(body.get("refresh", True)),
                                  use_ti=bool(body.get("use_ti", True)), timeout=int(body.get("timeout") or 300),
                                  use_ai=bool(body.get("use_ai", False)))
            except (ValueError, TypeError) as exc:
                return self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return self._json(job.to_dict(), HTTPStatus.ACCEPTED)

    return Handler


def build_server(report_dir: str, host: str = "127.0.0.1", port: int = 8080,
                 status: Optional[Dict[str, Any]] = None, settings=None, client_factory=None) -> ThreadingHTTPServer:
    from .jobs import JobManager

    jobs = JobManager(report_dir, settings, **({"client_factory": client_factory} if client_factory else {}))
    return ThreadingHTTPServer((host, port), make_handler(ReportStore(report_dir), status, jobs))


def serve(report_dir: str, host: Optional[str] = None, port: Optional[int] = None,
          status: Optional[Dict[str, Any]] = None, open_browser: bool = True, settings=None) -> None:
    host = host or os.environ.get("WEB_HOST") or "127.0.0.1"
    port = port or int(os.environ.get("WEB_PORT") or 8080)
    server = build_server(report_dir, host, port, status, settings)
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '') else host}:{port}/"
    print(f"[*] 웹 화면: {url}  (리포트 폴더: {Path(report_dir).resolve()}, 종료: Ctrl + C)")
    if host not in ("127.0.0.1", "localhost"):
        print("[!] WEB_HOST 가 127.0.0.1 이 아니라서 다른 PC 에서도 접속할 수 있습니다. 인증이 없으니 주의하세요.")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # 브라우저를 못 열어도 서버는 계속
            pass
    try:
        server.serve_forever()
    finally:
        server.server_close()
