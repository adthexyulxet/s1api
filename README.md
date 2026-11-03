# s1api: SentinelOne Deep Visibility 자동 트리아지

SentinelOne 콘솔에서 미해결 위협(Threat)이 새로 생기면 해당 위협의 **Storyline ID** 로 Deep Visibility(DV) 이벤트를 자동 조회하고, LOLBin/의심 명령줄 탐지, IOC(IP·도메인·해시) 추출, 선택적 위협 인텔리전스(VirusTotal / AbuseIPDB) 조회까지 수행한 뒤 위험도와 함께 리포트를 출력하는 Python 데몬입니다.

```
[ SentinelOne 콘솔 ]
      │  GET /threats (미해결, 최신순, 주기적 폴링)
      ▼
[ 신규 위협 선별 ]  ← state/seen_threats.json 으로 중복 분석 방지
      │  POST /dv/init-query  (storyline = "<ID>")
      │  GET  /dv/query-status (완료까지 대기)
      │  GET  /dv/events       (nextCursor 페이지네이션)
      ▼
[ 분석 ]  LOLBin·명령줄 패턴(MITRE ATT&CK), IOC 추출
      ▼
[ Enrichment ]  VirusTotal / AbuseIPDB (API 키가 있을 때만)
      ▼
[ 리포트 ]  콘솔 출력 + reports/threat_<ID>.json
```

## 빠른 시작

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# .env 에 S1_API_URL, S1_API_TOKEN 입력

python -m s1triage                 # 데몬 모드 (기본 30초 주기)
python -m s1triage --once          # 한 번만 폴링
python -m s1triage --skip-backlog  # 기존 미해결 위협은 건너뛰고 이후 신규만 분석
python -m s1triage --threat-id 1234567890   # 특정 위협 1건만 분석
```

> ⚠️ API 토큰은 절대 코드나 Git 에 넣지 마세요. `.env` 는 `.gitignore` 에 포함되어 있습니다. 토큰이 채팅·코드 등에 노출된 적이 있다면 콘솔에서 재발급(rotate)하는 것을 권장합니다.

### 필요한 API 권한
서비스 유저(Viewer 이상)에 다음 권한이 필요합니다: Threats 조회, Deep Visibility 쿼리.

## 설정 (환경변수)

| 변수 | 기본값 | 설명 |
|---|---|---|
| `S1_API_URL` | (필수) | 예: `https://<console>.sentinelone.net/web/api/v2.1` |
| `S1_API_TOKEN` | (필수) | SentinelOne API 토큰 |
| `S1_POLL_INTERVAL` | 30 | 위협 폴링 주기(초) |
| `S1_THREAT_FETCH_LIMIT` | 20 | 폴링당 가져올 미해결 위협 수 |
| `S1_STATE_FILE` | `state/seen_threats.json` | 처리한 위협 ID 저장 위치 |
| `S1_DV_LOOKBACK_HOURS` | 24 | DV 조회 범위: 위협 생성 시각 − N시간 ~ 현재 |
| `S1_DV_QUERY_TEMPLATE` | `storyline = "{storyline_id}"` | S1QL 템플릿 |
| `S1_DV_POLL_SECONDS` / `S1_DV_TIMEOUT_SECONDS` | 3 / 90 | 쿼리 상태 확인 간격 / 최대 대기 |
| `S1_DV_MAX_EVENTS` | 5000 | 위협당 수집할 최대 이벤트 수 |
| `S1_HTTP_TIMEOUT` / `S1_HTTP_RETRIES` | 30 / 3 | HTTP 타임아웃, 5xx 재시도 횟수 |
| `S1_RATE_LIMIT_RETRIES` | 4 | 429 응답 시 재시도 횟수 (Retry-After 준수, 없으면 15→30→60→120초 대기) |
| `S1_DV_MIN_INTERVAL` | 10 | DV 쿼리 연속 생성 시 최소 간격(초) |
| `VT_API_KEY` | (선택) | VirusTotal v3 키: 해시·IP·도메인 조회 |
| `ABUSEIPDB_API_KEY` | (선택) | AbuseIPDB 키: IP 평판 조회 |
| `ENRICH_MAX_LOOKUPS` | 10 | 위협 1건당 TI 조회 상한 (무료 쿼터 보호) |
| `REPORT_DIR` | (비움) | JSON 리포트 저장 디렉터리 |

## 프로토타입 대비 변경 사항

- **비밀값 분리**: URL/토큰을 `.env`(환경변수)로 이동, `Settings` 의 repr 에서 토큰 마스킹.
- **중복 방지 개선**: 최신 1건만 보던 방식 → 최신 N건을 가져와 아직 처리하지 않은 위협을 오래된 순으로 모두 분석. 처리 이력은 파일에 저장되어 재시작해도 유지됩니다. DV 조회가 실패한 위협은 다음 폴링에서 재시도합니다.
- **DV 결과 페이지네이션**: `/dv/events` 의 `nextCursor` 를 따라 전체 결과를 수집(상한 `S1_DV_MAX_EVENTS`). 기존에는 첫 페이지만 가져왔습니다.
- **조회 범위**: "현재 − 24시간" 고정 → "위협 생성 시각 − 24시간 ~ 현재". 오래된 위협도 빠짐없이 조회합니다.
- **쿼리 상태**: `isFinished` 외에 `responseState`(FINISHED/FAILED 등)도 확인해 실패 시 즉시 중단.
- **재시도/레이트리밋**: 5xx 지수 백오프 재시도, 429 는 더 길게 대기 후 재시도, DV 쿼리 사이 최소 간격, 모든 요청에 타임아웃.
- **LOLBin 오탐 수정**: 부분 문자열 매칭(`"nc" in name`) 때문에 `sync.exe`, `vncviewer.exe`, `cmdagent.exe` 등이 탐지되던 문제를, 경로·확장자를 제거한 프로세스 이름 **정확 일치**로 수정. 탐지 목록 확장 및 MITRE ATT&CK 기법 ID·가중치 부여.
- **명령줄 패턴 탐지**: 인코딩된 PowerShell, `IEX + DownloadString`, `certutil -urlcache`, `vssadmin delete shadows`, 숨김 창 실행.
- **IOC 추출**: 공인 IP(사설·예약 대역 제외), 도메인(DNS·URL·명령줄 내 URL), SHA1/SHA256/MD5.
- **위험도 점수**: 탐지 가중치 + TI 악성 판정 + 콘솔 신뢰도로 LOW / MEDIUM / HIGH 산정.

## 프로젝트 구조

```
s1triage/
  config.py      환경변수/.env 로딩
  client.py      SentinelOne API (threats, dv/init-query, query-status, events)
  analyzer.py    LOLBin·명령줄 탐지, IOC 추출
  enrichment.py  VirusTotal / AbuseIPDB
  state.py       처리한 위협 ID 저장
  report.py      위험도 산정, 콘솔/JSON 리포트
  monitor.py     파이프라인 + CLI
tests/           가짜 HTTP 응답 기반 단위 테스트
```

## 테스트

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

테스트는 실제 SentinelOne 에 접속하지 않고 가짜 응답으로 동작합니다.

## 참고 / 다음 단계

- DV 이벤트 필드명은 콘솔 버전에 따라 다를 수 있어 `analyzer.py` 에서 여러 후보 키(`tgtProcName`, `processName`, `srcProcName` 등)를 순서대로 확인합니다. 실제 응답에서 다른 키가 보이면 해당 목록에 추가하세요.
- 확장 아이디어: Slack/Teams/Jira 알림, Webhook 수신 모드, HIGH 등급 시 에이전트 네트워크 격리(`POST /agents/actions/disconnect`) 자동화(오탐 위험이 있으므로 승인 단계 권장).
