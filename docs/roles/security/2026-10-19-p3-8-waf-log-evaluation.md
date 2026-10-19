# P3-8 WAF 차단 로그 및 Web L7 탐지 룰 평가

- 작성일: 2026-10-19 KST
- 담당 직무: 보안 (`@gkacksdnjs22-stack`)
- GitHub Issue: [#194 WAF 차단 로그 및 Web L7 탐지 룰 평가](https://github.com/mmmphyun/aleph-project/issues/194)
- Notion Task: [P3-8 작업 카드](https://notion.so/3f704d37c22580a0b6f8f4cab2fa2492)
- 브랜치: `feat/security-p3-8-waf-log-evaluation`
- 선행 작업: [P3-6 PR #186](https://github.com/mmmphyun/aleph-project/pull/186), [P3-7 PR #192](https://github.com/mmmphyun/aleph-project/pull/192), [입력 계약 PR #188](https://github.com/mmmphyun/aleph-project/pull/188), [IAM 핫픽스 PR #190](https://github.com/mmmphyun/aleph-project/pull/190)
- 기준 main: `7f6760a`
- 상태: **원본 수신 후 부분 평가. 분리 작업 공간의 필수 게이트 통과. 인코딩 공격 실측 등 추가 증거가 남아 초안 PR로 검토한다.**

## 1. 현재 판정과 평가 범위

수신한 WAF 22건과 Nginx 58건을 분석한 결과, 알려진 공격자 `3.26.171.60`의 디렉터리 스캔 입력에서 기존 룰의 `WEB_DIRECTORY_SCANNING` 판정을 재현했다. WAF 원본에서도 같은 출발지의 `CloudShield-Block-IP` 규칙에 의한 BLOCK 3건을 확인했다. 원본 수신 이후의 판정은 선행 보고서의 전달값과 구분한다.

첫 공격 GET부터 Lambda 종료까지는 **9.526059초**, 최초 HTTP 403 관측까지는 **26.324311초**다. 제어 처리 종료와 실제 HTTP 차단 응답의 관측은 별도 지표이며, 전체 HTTP 경로의 10초 SLA 성공으로 보고하지 않는다.

평가 대상은 한 알려진 공격 실행과 보존된 주변 로그다. 정상 외부 IP의 차단 후 HTTP 200, 실환경 인코딩 공격, Lambda 원본은 추가 자료가 필요하다. 탐지·플랫폼·인프라 구현이나 정책은 변경하지 않았다.

## 2. 원본과 증거의 출처

| 수신 원본 | SHA-256 | 확인 범위 |
| --- | --- | --- |
| `waf-raw.json` | `24697b453609a3c717e6dad6531d120bf9fe6230ccbf81b88a2ca35af52cf297` | 30,647바이트, FilterLogEvents 형태, 22건 파싱 성공 |
| `nginx-raw.json` | `15a2c14405e2a7a2c2df61375e61874badeba73046f4005f82c4834d9ab502b1` | 15,106바이트, 58건 모두 기존 Nginx 파서로 파싱 성공 |

분석용 보존물은 [manifest.json](evidence/p3-8-2026-10-16/manifest.json), [WAF 공격자 20건 선택 필드](evidence/p3-8-2026-10-16/waf-selected-events.json), [Nginx 공격자 16건](evidence/p3-8-2026-10-16/nginx-attacker-events.json)다. 선택 JSON은 필요한 이벤트·필드와 원본 좌표를 보존한 발췌이며 원본 API 응답 전체의 복사본이 아니다. WAF 헤더·쿠키·토큰은 포함하지 않는다.

| 근거 | 출처와 사용 범위 |
| --- | --- |
| 수신 WAF·Nginx 원본 | 보안 평가에서 직접 읽고 집계·룰 재생한 입력 |
| [운영 Slack 메시지](https://skt-aleph.slack.com/archives/C0BU9AE6970/p1792138192192929) | 실제 운영 카드 직접 관찰. 메시지 시각·사건 ID·출발지·조치 문구 확인 |
| [P3-6 HTTP 403 재실측](../network/2026-10-16-p3-6-waf-403-retest.md) | 네트워크 담당의 PCAP 분석. Lambda 구간·IPSet 갱신은 클라우드 A 전달값 |
| [P3-7 수집 및 알림](../cloud-b/2026-10-16-p3-7-nginx-waf-measurement.md) | 수집 설정과 기존 전달 결과. 당시 원본 및 운영 Slack 원문 미확보라는 한계는 해당 문서 작성 시점의 상태 |

WAF 파일에는 `nextToken`이 없고 `searchedLogStreams=[]`다. Nginx 파일에는 앞·뒤 방향 토큰이 있지만 조회 매개변수와 연속 페이지 이력이 없다. 반환 토큰의 존재만으로 조회 종료를 판정할 수 없으며, 입력 토큰과 반환 토큰의 비교가 필요하다. 따라서 두 파일을 전체 로그 그룹의 완전한 추출로 단정하지 않는다. [AWS GetLogEvents 명세](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_GetLogEvents.html)

## 3. WAF 매칭 JSON과 필드 분석

전체 WAF 이벤트 범위는 2026-10-16 **17:07:42.549~17:10:29.117 KST**다. ALLOW 19건은 `Default_Action`, BLOCK 3건은 `CloudShield-Block-IP`다. `eventId`·요청 ID 누락과 중복, 동일 메시지 중복, JSON 파싱 실패는 각각 0건이며 외부 CloudWatch 시각과 내부 WAF 시각은 22건 모두 일치한다.

| 구분 | 건수와 내용 | 평가에서의 취급 |
| --- | --- | --- |
| 알려진 성공 실행 | `3.26.171.60` 20건, GET 15·HEAD 5, ALLOW 17·BLOCK 3 | 17:09:42.765~17:10:29.117 KST |
| 실행 이전 외부 요청 | `45.198.224.124`의 17:07:42.549 GET `/`, `77.83.39.94`의 17:08:48.270 GET `/.git/index` | 각각 ALLOW. 정답 라벨 없는 별도 요청이며 정상 대조군으로 집계하지 않음 |

최초 BLOCK은 원본 `events[19].message`다. 아래는 필요한 필드만 선택한 발췌다.

```json
{
  "timestamp": 1792138209112,
  "action": "BLOCK",
  "terminatingRuleId": "CloudShield-Block-IP",
  "responseCodeSent": null,
  "httpSourceName": "ALB",
  "httpRequest": {
    "clientIp": "3.26.171.60",
    "httpMethod": "HEAD",
    "uri": "/",
    "requestId": "1-6ad1dbe1-2b9ff3d56d88a2492bbb1005"
  }
}
```

| 필드 | 원본 값 또는 해석 |
| --- | --- |
| `webaclId` | `arn:aws:wafv2:ap-southeast-2:885755545044:regional/webacl/CloudShield-WebACL/8ffb0c27-ad7f-4fec-9c27-e0bd7ff2a751` |
| `httpSourceId` | `885755545044-app/CloudShield-ALB-dev/de4a0a31bdd3e235`. `httpSourceName=ALB`와 함께 해당 ALB 연계 요청임을 나타냄 |
| `action`·`terminatingRuleId` | WAF의 종결 동작과 규칙. 경로 탐지 시그니처 자체의 판정 근거와 구분 |
| `httpRequest.requestId` | ALB가 생성한 trace ID. Nginx 원문에는 공통 요청 ID가 없어 직접 키 조인 불가 |
| `responseCodeSent` | 22건 모두 `null`. 사용자 정의 응답 코드 필드이므로 이 파일에서 HTTP 200·403 값을 읽을 수 없음 |
| `terminatingRuleMatchDetails` | 전부 빈 배열. 이 필드는 SQLi·XSS 매칭 상세에 사용되므로 비어 있다는 이유로 IP 규칙 미매칭을 뜻하지 않음 |

필드 의미는 [AWS WAF 로그 필드 정의](https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html)를 따른다. WebACL 이름은 원본의 **`CloudShield-WebACL`**을 우선하며 P3-7 문서의 `CloudShield-WebACL-Dev`와 명칭이 다르다. WAF 로그와 Slack 카드가 IPSet 차단 경과를 뒷받침하지만 현재 IPSet 주소를 `GetIPSet`으로 조회한 결과는 아니다.

## 4. 실제 Nginx 입력의 룰 재생

Nginx 58건의 범위는 **17:05:04~17:14:47 KST**다. 알려진 공격자 입력은 17:09:42~17:10:02의 16건으로, HEAD 200 두 건과 GET 401 한 건·404 열세 건이다. 내부 `ELB-HealthChecker`는 `10.42.1.29`와 `10.42.0.90`에서 각각 20건이며, 나머지 외부 두 건은 정답 라벨이 없다.

WAF의 공격자 20건과 Nginx의 16건은 `/health` 로깅 제외 1건과 WAF에서 차단된 사후 HEAD 3건을 구분하면 **20−1−3=16**으로 대응한다. 남은 WAF ALLOW 16건과 Nginx 공격자 16건은 `(출발지 IP, 메서드, URI, UTC 초 단위 시각)`의 고유 튜플이 모두 일치했다. Nginx에는 WAF 요청 ID가 없으므로 이는 필드·시각의 상관대조이며 개별 요청 ID 조인이 아니다.

기존 `NginxAccessLogEvent.parse_line`과 `evaluate_web_rules`로 다음 입력을 재생했다. 각 집합을 시각순 prefix로 확장해 최초 양성 판정도 확인했다.

| 입력 집합 | 전체 입력 수 | 최초 양성 prefix의 입력 수 | 결과 |
| --- | --- | --- | --- |
| Nginx 전체 | 58 | 28 | `WEB_DIRECTORY_SCANNING` |
| 현행 실패 응답 필터 적용 | 15 | 6 | `WEB_DIRECTORY_SCANNING` |
| 알려진 공격자만 | 16 | 6 | `WEB_DIRECTORY_SCANNING` |
| 알려진 공격자의 실패 응답만 | 14 | 5 | `WEB_DIRECTORY_SCANNING` |

모든 집합에서 최초 유효 다섯 경로는 `/admin`, `/login`, `/dashboard`, `/api`, `/backup`이다. 17:09:48의 `/backup`까지 로그 시각 차이는 **6초**, 의심 경로 5개와 실패 경로 5개이며, 다섯 번째 경로 직전에는 비탐지였다. 초 단위 Nginx 시각의 차이로, PCAP의 5.775308초 간격과 정밀도가 다르다. `/backup`의 CloudWatch 수집 시각은 **17:09:50.746 KST**다.

양성 판정은 기존 매퍼에서 `HIGH`, `BLOCK_WAF`, `T1595.003`, 빈 `target_accounts`로 연결됐다. 이 매퍼 재생의 사건 ID는 검증용 합성 ID이며 운영 Slack 사건 ID와 구분한다. 순수 룰 재생은 운영 Lambda 호출·DynamoDB 배치 누적의 재현을 뜻하지 않는다.

공유한 Nginx 선택 이벤트만으로 공격 구간의 임계치 전후를 재현할 수 있다. 프로젝트 루트의 PowerShell에서 아래 명령은 파일을 읽고 기존 룰을 호출하며 AWS API를 실행하지 않는다.

```powershell
@'
import json
import sys
from pathlib import Path

sys.path.insert(0, "src")
from contracts.events import NginxAccessLogEvent
from detection.rules import evaluate_web_rules

path = Path("docs/roles/security/evidence/p3-8-2026-10-16/nginx-attacker-events.json")
rows = json.loads(path.read_text(encoding="utf-8"))["events"]
logs = [NginxAccessLogEvent.parse_line(row["message"]) for row in rows]
assert len(logs) == 16 and all(log is not None for log in logs)
assert evaluate_web_rules(logs[:5]) == (False, None)
assert evaluate_web_rules(logs[:6]) == (True, "WEB_DIRECTORY_SCANNING")
assert evaluate_web_rules(logs) == (True, "WEB_DIRECTORY_SCANNING")
print("16 real events: before threshold=False, at threshold=WEB_DIRECTORY_SCANNING")
'@ | .\.venv\Scripts\python.exe -B -
```

## 5. 운영 시간축과 수집 시각 차이

| 단계 | 2026-10-16 KST 시각 | 근거 |
| --- | --- | --- |
| 첫 공격 GET `/admin` 송신 | 17:09:42.787941 | P3-6 PCAP |
| 다섯 번째 의심 GET `/backup` 송신 | 17:09:48.563249 | P3-6 PCAP |
| `/backup` CloudWatch 수집 | 17:09:50.746 | 수신 Nginx 원본 |
| Lambda 실행 | 17:09:50.915~17:09:52.314 | 클라우드 A 전달값. RequestId `1f089011-c024-40d9-92a6-852d14833b73` |
| IPSet 갱신 완료 | 17:09:52, 초 단위 | 클라우드 A 전달값 |
| 운영 Slack 메시지 | 17:09:52.192929 | 직접 관찰한 메시지 `ts=1792138192.192929` |
| 마지막 WAF ALLOW | 17:10:02.136, HEAD `/` | 수신 WAF 원본. 같은 IP의 PCAP 응답은 17:10:02.136695 HTTP 200 |
| 첫 WAF BLOCK | 17:10:09.112, HEAD `/` | 수신 WAF 원본 |
| 최초 HTTP 403 수신 | 17:10:09.112252 | P3-6 PCAP. 후속 BLOCK은 WAF 17:10:19.119·17:10:29.117 |

운영 Slack 카드는 `INC-1792138191-7160`, 출발지 `3.26.171.60`, 타깃 `i-0605f8529598ed820`, `BLOCK_WAF`와 `CloudShield-Block-IPSet`의 `/32` 등록 완료를 표시한다. 이는 P3-7의 합성 `INC-TEST-WAF-7160` 카드와 별도로 확보한 운영 메시지다. Lambda RequestId와 공유하는 직접 키가 없으므로 IP·사건 내용·시간대로 연결하며, 메시지 시각을 사용자 수신 시각이나 현재 IPSet 조회 결과로 바꾸지 않는다.

| 구간 | 시간 | 해석 |
| --- | --- | --- |
| Lambda 런타임 | 1.399초 | 전달받은 START~END |
| 첫 GET → Lambda 종료 | **9.526059초** | 제어 처리 종료 |
| 첫 GET → 최초 관측 403 | **26.324311초** | 클라이언트의 실효 차단 응답 관측 |
| 다섯 번째 의심 GET → 최초 관측 403 | 20.549003초 | 탐지 판정 시각이 아닌 요청 시각 기준 |
| Lambda 시작 → 최초 관측 403 | 18.197252초 | Lambda 진입 이후 관측 구간 |

GET 15건의 스캔 중 403은 없었고 최초 403은 사후 HEAD 응답이다. 마지막 200과 최초 403 사이에는 프로브 공백이 있어 정확한 정책 활성화 시각·ALB 전체 전파 완료 시각을 확정하지 않는다. 이 관측 간격 전체를 순수 WAF 전파 지연으로 해석하지 않는다.

| 원본의 `ingestionTime − timestamp` | 통계 | 해석 범위 |
| --- | --- | --- |
| Nginx 공격자 16건 | 최소 1.247초, 중앙값 3.0145초, 최대 6.284초 | 로그 시각이 초 정밀도인 원시 차이 |
| Nginx 전체 58건 | 최소 1.247초, 중앙값 7.601초, 최대 7.630초 | 헬스체크 등 주변 표본 포함 |
| WAF 전체 22건 | nearest-rank p50 17.508초, p95 19.552초, 최대 22.081초 | WAF 이벤트에서 CloudWatch 적재까지의 차이 |

Nginx 원문 시각과 CloudWatch `timestamp`는 58건 모두 초 단위로 일치한다. 위 Nginx 차이는 시각 정밀도와 시계 오차를 포함하므로 순수 네트워크 수집 지연이나 3초 SLA 충족률로 단정하지 않는다. WAF 적재 차이는 정책 전파 시간이 아니다. P3-7의 1,815/1,825ms는 여전히 합성 계산기 값이며 이번 원본 통계와 구분한다.

## 6. 오탐과 미탐 평가의 분모

알려진 디렉터리 스캔 묶음 한 개는 양성으로 판정되어 **TP 1묶음**을 관찰했다. 내부 헬스체크 IP별 두 묶음은 각각 비탐지였다. 이 제한된 표본으로 일반 운영 오탐률·미탐률 0%나 전체 정확도를 주장하지 않는다.

외부 두 요청은 정답 라벨이 없어 TN·FN에 포함하지 않는다. `/.git/index`의 404 한 건은 비탐지였으며 현재 고정 민감 경로 목록 밖이라는 커버리지 관찰로 남긴다. 공격 의도를 확정하거나 운영 미탐률 분모에 넣지 않는다. WAF에서 이미 차단한 공격자 IP의 정상 경로 HEAD도 별도 정상 사용자 표본이 아니다.

두 원본의 URI에는 퍼센트 인코딩·쿼리 표본이 없으므로 실환경 인코딩 변종 정확도는 미검증이다. 첫 BLOCK 이후 정상 다른 외부 IP의 HTTP 200도 확보되지 않았다. 향후 정답 라벨과 평가 단위를 고정한 표본에서 오탐률 `FP / (FP + TN)`과 미탐률 `FN / (TP + FN)`을 계산하고 탐지 실패·입력 장애·차단 집행 실패를 구분한다.

## 7. 로컬 합성 재생과 운영 검증의 구분

원본 분석과 별도로 기존 룰·매퍼의 합성 17사례에서 기대 판정과 실제 반환값이 일치했다. 양성 6사례의 매퍼 결과도 확인했다. 기준 S는 `/admin`, `/login`, `/dashboard`, `/api`, `/private`를 0·6·7·8·10초에 입력하고 상태를 401·403·404·200·302로 지정한 묶음이다.

| 사례 | 입력 조건 | 기대와 실제 |
| --- | --- | --- |
| 1 | S 전체, 10초 경계 | `WEB_DIRECTORY_SCANNING` |
| 2~4 | S를 11초로 확대 / 4경로 / 실패 2경로 | 각각 비탐지 |
| 5~7 | IP 교대 / `/admin` 반복 / 같은 경로의 쿼리만 변경 | 각각 비탐지 |
| 8 | 헬스·robots·sitemap·정적 자원 | 비탐지 |
| 9~11 | `/../etc/passwd` 및 단일·이중 퍼센트 인코딩 | 각각 `PATH_TRAVERSAL` |
| 12 | 삼중 퍼센트 인코딩 | 비탐지. 현재 정규화 범위 밖 |
| 13 | `/.env` | `SENSITIVE_FILE_PROBING` |
| 14 | `/search?file=/.env` | 비탐지. 경로 정책의 검사 대상 밖 |
| 15~17 | S 역순 / 앞 3행 독립 호출 / 뒤 2행 독립 호출 | 디렉터리 스캔 탐지 / 비탐지 / 비탐지 |

합성 판정 일치는 운영 정확도가 아니다. 12·14번은 정책 제외 영역으로 TN으로 세지 않는다. S에는 200·302가 포함되어 실제 실패 응답 구독 필터의 재현도 아니다. 독립 호출의 비탐지나 한 묶음의 역순 입력 성공은 영속 윈도우의 배치 간 누적·지연 도착·부분 장애·포화 검증을 대신하지 않는다.

## 8. 완료 조건과 남은 검증

| 완료 조건 | 현재 상태 | 남은 증거 또는 절차 |
| --- | --- | --- |
| ALB 연계 WAF 로그 및 매칭 JSON 분석 | 수신 파일 범위 분석 완료 | 조회 범위·페이지 연속 이력은 미확보 |
| 실제 Nginx 디렉터리 스캔과 임계치 대조 | 알려진 공격 묶음 재생 확인 | 일반화 가능한 정상·공격 분모 추가 |
| 인코딩 변종의 운영 매칭 정확도 | **미완료** | 실제 단일·이중 인코딩 요청과 수집·판정 결과 |
| 운영 FP/FN 및 룰 내구성 평가 | **부분 확인** | 대표 표본과 라벨·분모, 실제 운영 장애·변종 범위 |
| 차단 후 정상 외부 IP 가용성 | **미완료** | 차단 이후 별도 정상 IP의 HTTP 200 |
| 운영 Lambda 연결 | 전달값과 원본·Slack 상관대조 | Lambda 원본과 실제 판정 시각·직접 연결 키 |
| 보안 보고서와 선택 증거 보존 | 원본 수신 결과 반영 | 검토 및 추가 자료 반영 |
| 필수 게이트와 클라우드 B 리뷰 | **게이트 통과, 초안 리뷰 단계** | 클라우드 B의 원본·수집 범위 검토 및 추가 증거 확인 |

원작업 폴더의 필수 게이트는 기존 사용자 `assets/` 때문에 역할 검사에서 차단됐다. 해당 파일과 기존 설계 문서 수정분을 보존한 채, 기준 main의 분리 작업 공간 `.codex-build/p3-8-evidence-check-20261019/`에 이번 변경만 복사해 `powershell .\scripts\check.ps1`을 실행했다. 역할 검사, Ruff 검사와 포맷 검사, **1,075 passed / 4 skipped**를 확인했으며 테스트 실행 시간은 227.13초다. 네트워크 격리 확인 테스트에서 socket 접근 경고 1건이 있었고 실패는 없었다. 마지막 문서·메타데이터 정리 후에는 역할 범위, JSON 발췌와 원본의 일치, 링크 및 원본 해시를 별도로 확인한다.

인코딩 실측과 운영 분모 등 미충족 항목이 남아 있으므로 P3-8 전체 완료 또는 Ready PR로 표시하지 않는다. 초안 PR은 현재 확보한 근거의 검토를 위한 것이며, 추가 실측은 수행하지 않았다.
