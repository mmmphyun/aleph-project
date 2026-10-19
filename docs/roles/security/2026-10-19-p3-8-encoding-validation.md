# P3-8 인코딩 실측 및 차단 후 정상 접근 대조

- 작성일: 2026-10-19 KST
- 담당: 보안 (`@gkacksdnjs22-stack`)
- 기존 평가: [WAF 차단 로그 및 Web L7 탐지 룰 평가](2026-10-19-p3-8-waf-log-evaluation.md)
- Issue: [#194](https://github.com/mmmphyun/aleph-project/issues/194), PR: [#196](https://github.com/mmmphyun/aleph-project/pull/196)
- Notion Task: [P3-8](https://notion.so/3f704d37c22580a0b6f8f4cab2fa2492)
- 범위: 네트워크·클라우드 B의 수신 원본을 읽고 기존 탐지 룰에 재생한 보안 문서 보완. 실행 코드·수집 설정·인프라 변경 없음
- 아래 절대 시각은 별도 표기가 없으면 **2026-10-19 UTC**다. KST는 UTC+09:00이다.

## 1. 판정과 근거 수준

공격자 `3.25.82.148`의 단일·이중 인코딩 원문이 PCAP과 Nginx 로그에 보존돼 있다. 각 실제 Nginx 공격 원문을 기존 `NginxAccessLogEvent.parse_line` 및 `evaluate_web_rules`에 재생하면 `PATH_TRAVERSAL`로 판정되며, 기존 매퍼는 `HIGH` / `BLOCK_WAF`로 연결한다. 로컬 재생에 사용한 식별자는 합성이며 운영 사건 ID와 구분한다.

운영 Lambda의 `PATH_TRAVERSAL` 판정·`BLOCK_WAF=True`·공격자 `/32` 등록은 클라우드 A가 사용자 채팅으로 확인했다. START/END/REPORT 및 X-Ray는 사용자가 전달한 로그 발췌를 아래에 보존했다. 판정·차단 결과 설명은 별도의 A 확인값이며, 로그 발췌에 없는 애플리케이션 로그 행을 생성하지 않는다.

클라우드 B의 Nginx·WAF 원본에서 각 사례마다 정상 공인 IP `1.245.252.171`의 `GET /` **Nginx 200 18건·WAF ALLOW 18건**, 공격자의 `CloudShield-Block-IP` **BLOCK 7건**을 직접 확인했다. 정상 관측은 마지막 공격자 403 뒤의 인접 관측이다. A가 제공한 사례별 해제 완료 시각은 정상 관측 종료보다 늦다. 이를 이번 관측 요청의 가용성 근거로 사용하며, 일반 서비스 가용성 100%나 일반 운영 오탐률 0%로 확대하지 않는다.

## 2. 수신물과 선택 증거

| 수신물 | SHA-256 | 직접 확인 범위 |
| --- | --- | --- |
| `p3-8-network-evidence-20261019-final.zip` | `7d1329e54a7a3515c26d621095db1d58aa1da307d972aec8fd0cc8f7ed63a5b9` | 157,752바이트. 최종 파일 목록 142건의 해시·용량, 세 실행의 원본 manifest 47/35/29건 및 PCAP 확인 |
| `p3-8-final-20261019.zip` | `b6cb2b327df1fe3b3233ae18b07de7505c02ac922915a07a979f2a30284acb83` | 18,167바이트. B의 history 4개와 응답 페이지 8개, 이벤트 총 147건 확인 |
| `security-handoff.md` | `a35743c16f80f41776cf60ca8b917f91be513a195beb0592e611c462d6ea5356` | 별도 인계문과 네트워크 ZIP 내부 인계문 바이트 일치 |
| 이중 사건 Slack 스크린샷 | `df6e624a0899170bd4df1025a089c151d145d121111e0ad0fe8bed70289f1339` | 사용자 제공 이미지에서 사건 ID·출발지·IPSet 등록 완료 문구 확인. 메시지 permalink·정확한 수신 시각은 미제공 |

선택 증거는 [manifest.json](evidence/p3-8-2026-10-19/manifest.json), [Nginx 선택 원문](evidence/p3-8-2026-10-19/nginx-selected-events.json), [WAF 선택 필드](evidence/p3-8-2026-10-19/waf-selected-events.json)다. 원본 ZIP은 사용자 수신 경로에 보존하고 저장소에 복사하지 않는다. WAF 헤더·쿠키·쿼리·페이지 토큰은 발췌하지 않는다. 선택 JSON에는 ZIP 내부 경로·페이지 SHA-256·이벤트 좌표를 남긴다.

PCAP은 첨부 분석 스크립트를 실행하지 않고 Ethernet/IPv4/TCP와 HTTP 시작 행을 읽어 독립 대조했다. 원문 URI·메서드·응답·프레임·시각은 CSV 및 분석 요약과 일치했다. 세 PCAP의 패킷 수는 220/160/130, HTTP 요청·응답은 22/16/13쌍이며 잘린 패킷은 0건이다. tcpdump 기록은 각 실행 정상 종료·kernel drop 0건이다.

### 클라우드 B 조회 범위와 페이지 종료

| 사례 | UTC 조회 범위 | Nginx | WAF |
| --- | --- | --- | --- |
| 단일 | 06:50:40~06:54:30 | 43건, 2페이지 | 34건, 2페이지 |
| 이중 | 07:02:20~07:06:15 | 39건, 2페이지 | 31건, 2페이지 |

각 첫 페이지의 응답 토큰은 history의 출력 토큰 및 둘째 페이지 입력 토큰과 일치한다. 둘째 페이지는 모두 이벤트 0건이며 `nextToken` 키가 없어 종료한다. 페이지 8개의 SHA-256·건수는 history와 일치하고, 147건의 eventId 누락·중복과 선언 범위 밖 이벤트는 없다. `searchedLogStreams=[]`는 폐기된 응답 필드의 동작이다. [AWS FilterLogEvents 명세](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_FilterLogEvents.html)

이는 제공된 조회의 페이지 종료 확인이다. history에 네이티브 요청 객체 전체와 `filterPattern`·스트림 제한·밀리초 경계 인자가 없어 전체 로그 그룹의 무필터 완전 추출까지 주장하지 않는다. history의 종료 경계 명명만으로 API의 엄밀한 반개구간 구현을 단정하지 않으며, 종료 경계에 걸린 이벤트는 없다.

## 3. 사례별 요청·탐지·차단 대조

| 항목 | 단일 재실측 | 이중 실측 |
| --- | --- | --- |
| 실행 ID | `20261019T065046Z-p3-8-single` | `20261019T070225Z-p3-8-double` |
| 원문 URI | `/admin/%2e%2e/config` | `/admin/%252e%252e/config` |
| PCAP 공격 송신 | 06:50:46.920718 | 07:02:26.614065 |
| 실제 Nginx 공격 원문 상태 | 06:50:46, 404 | 07:02:26, 401 |
| 공격 요청의 WAF 동작 | ALLOW | ALLOW |
| 실제 입력의 로컬 룰 재생 | `PATH_TRAVERSAL` | `PATH_TRAVERSAL` |
| A 확인 RequestId | `d294fb7d-5d49-4cd2-8415-124721308253` | `85f83dd4-a1f9-422f-a899-d25925843de0` |
| A 확인 incident_id | `INC-1792392652-2148` | `INC-1792393353-2148` |
| A 확인 운영 판정·조치 | `PATH_TRAVERSAL`, `BLOCK_WAF=True` | `PATH_TRAVERSAL`, `BLOCK_WAF=True` |
| B 원본 최초 WAF BLOCK | 06:51:10.946 | 07:02:41.639 |
| PCAP 최초 후속 HTTP 403 | 06:51:10.946494 | 07:02:41.641932 |
| 공격 송신 → 최초 관측 403 | **24.025776초** | **15.027867초** |
| 후속 WAF BLOCK / PCAP 403 | 각각 7건 | 각각 7건 |

두 사례의 공격 요청 자체는 WAF ALLOW로 Nginx까지 도달했고, 이후 `/` 요청의 WAF IP 규칙 차단과 403을 확인했다. WAF IP 규칙 BLOCK을 경로 시그니처 판정으로 대체하지 않는다. 각 Nginx 공격 원문의 한 단계 계약 디코딩과 기존 룰 정규화가 단일·이중 경로 탈출을 탐지한다.

Nginx 선택 원문과 WAF ALLOW는 `(출발지, 메서드, 원문 URI, UTC 초)`로 단일 27건·이중 24건이 일치한다. 네트워크 요청과 WAF의 공격자 이벤트도 각각 16건·13건이 같은 필드로 대응한다. Nginx에 공통 요청 ID가 없어 개별 요청 ID 조인으로 표현하지 않는다. PCAP과 WAF 시계의 미세한 차이도 순수 전파 지연으로 환산하지 않는다.

A의 이전 최초 BLOCK 전달값 06:51:20.971 / 07:02:51.667은 B 원본의 **두 번째 BLOCK**이다. A는 각각 06:51:10.946 / 07:02:41.639으로 정정했으며 B 원본과 네트워크 최초 403 관측에 대응한다. 최초 관측을 정책 활성화의 정확한 시작 시각으로 동일시하지 않는다.

### 초회 단일의 실패 보존

`20261019T064543Z-p3-8-single`은 06:45:44.147812에 같은 단일 원문을 전송해 404를 받았고, 이후 60초 관측의 `/` 요청 20건은 모두 200이었다. PCAP의 403은 0건이다. A는 RequestId `54a5e92d-0a5b-4c50-a0e3-42966cf05318`의 `PATH_TRAVERSAL` 탐지 후 `GetWebACLForResource` 권한 오류로 IPSet 등록이 끝나지 않았다고 확인했다.

네트워크 인계에 따르면 A의 IAM 조회 정책 v3 핫픽스와 초기화 완료 통보 후 단일 재실측을 수행했다. 이 최초 실패를 삭제하거나 탐지 미탐으로 재분류하지 않고, 탐지 후 차단 집행 실패로 출처와 함께 보존한다. 보안 에이전트는 해당 IAM 정책을 조회·수정하거나 재실측을 수행하지 않았다.

## 4. Lambda 로그 발췌와 A 확인값

아래 블록은 **사용자가 전달한 CloudWatch 로그 발췌**다. 보안 에이전트가 AWS에서 직접 내려받은 API 응답은 아니며 로그 그룹·조회 전체 이력은 제공되지 않았다. 로그 스트림·RequestId·사건 ID는 서로 다른 식별자다.

### 단일 재실측

Log Stream: `2026/10/19/[$LATEST]81758667a49c4078bb60cf441fcea2ec`

```text
2026-10-19T06:50:52.285Z START RequestId: d294fb7d-5d49-4cd2-8415-124721308253 Version: $LATEST
2026-10-19T06:50:53.557Z END RequestId: d294fb7d-5d49-4cd2-8415-124721308253
2026-10-19T06:50:53.557Z REPORT RequestId: d294fb7d-5d49-4cd2-8415-124721308253 Duration: 1270.90 ms Billed Duration: 1271 ms Memory Size: 256 MB Max Memory Used: 113 MB
XRAY TraceId: 1-6ad5bdcc-04914f2e37762b9a6b36d5b3 SegmentId: 4dd680ca448dacff Sampled: true
```

### 이중 실측

Log Stream: `2026/10/19/[$LATEST]848d3a9b06aa42c5b88bd67afaef27c9`

```text
2026-10-19T07:02:32.132Z INIT_START Runtime Version: python:3.12.mainlinev2.v43 Runtime Version ARN: arn:aws:lambda:ap-southeast-2::runtime:36aeb19f3326e129d9f096dea0a3c6a9ca8dce2610e62d2b2060747602d863ae
2026-10-19T07:02:33.021Z START RequestId: 85f83dd4-a1f9-422f-a899-d25925843de0 Version: $LATEST
2026-10-19T07:02:34.561Z END RequestId: 85f83dd4-a1f9-422f-a899-d25925843de0
2026-10-19T07:02:34.561Z REPORT RequestId: 85f83dd4-a1f9-422f-a899-d25925843de0 Duration: 1539.05 ms Billed Duration: 2426 ms Memory Size: 256 MB Max Memory Used: 113 MB Init Duration: 886.29 ms
XRAY TraceId: 1-6ad5c087-50dde8ee5702b1d11f8efafd SegmentId: 153f9e37aa03f135 Sampled: true
```

START~END 시각 차이는 단일 1.272초·이중 1.540초이고 REPORT Duration은 각각 1270.90ms·1539.05ms다. 시각 차이와 REPORT 지표를 구분한다. 공격 송신부터 END까지는 6.636282초·7.946935초지만 실제 최초 403은 24.025776초·15.027867초다. 두 사례를 전체 HTTP 경로의 10초 실효 차단 성공으로 보고하지 않는다.

`PATH_TRAVERSAL`, 위 incident_id 두 개 및 `BLOCK_WAF=True`·`3.25.82.148/32` 등록 완료는 위 런타임 블록과 별도로 A가 확인한 내용이다. 이중 사건은 사용자 제공 Slack 스크린샷의 `INC-1792393353-2148`, 출발지, `HIGH`, `BLOCK_WAF`, IPSet `/32` 등록 완료 문구와도 대응한다. Slack 표시를 독립적인 현재 IPSet 조회로 취급하지 않는다.

## 5. 정상 외부 IP와 사례별 복구 순서

| 항목 | 단일 | 이중 |
| --- | --- | --- |
| 정상 출발지 | `1.245.252.171` | `1.245.252.171` |
| B Nginx `GET /` 200 | 18건, 06:52:14~06:54:21 | 18건, 07:03:56~07:06:03 |
| B WAF ALLOW | 18건, 06:52:14.729~06:54:21.896 | 18건, 07:03:56.345~07:06:03.582 |
| A 전달 클라이언트 200 관측 | 18건, 06:52:14.547~06:54:21.729 | 18건, 07:03:56.105~07:06:03.349 |
| A 확인 IPSet 해당 `/32` 해제 완료 | 06:57:13 | 07:07:24 |
| A 확인 WEB# 윈도우 삭제·잔류 0건 | 06:57:19 | 07:07:31 |
| A 확인 ALB `GET /` 200 복구 | 06:57:23 | 07:07:36 |

정상 Nginx·WAF 원본은 보안에서 직접 읽었고, 정상 클라이언트 응답 시각과 IPSet·DynamoDB 복구 시각은 A의 전달 확인이다. 소스별 시계·시각 정밀도가 다르므로 서브밀리초 인과관계로 해석하지 않는다. B의 마지막 정상 WAF 이벤트와 A의 해당 IP 해제 완료 사이에는 단일 171.104초·이중 80.418초 간격이 있어, 제공된 A 확인 기록상 해제는 정상 관측 종료 이후다. 단일 윈도우 초기화·복구는 이중 요청 송신 전이다.

네트워크의 마지막 공격자 403은 단일 06:52:10.972481·이중 07:03:41.670011이다. A가 전달한 첫 정상 클라이언트 200은 그보다 각각 3.574519초·14.434989초 뒤다. 겹치는 두 클라이언트 PCAP 구간이나 정상 관측 종료 때까지의 지속 공격 프로브를 확보했다고 기술하지 않는다. 정상 200의 Lambda 비탐지 로그는 요구하지 않으며, 정상 원문의 기존 룰 재생은 각 18건 묶음에서 비탐지였다.

## 6. 재현과 남는 한계

프로젝트 루트 PowerShell에서 선택 원문으로 공격 판정과 정상 묶음 비탐지를 재현한다. AWS 호출이나 파일 쓰기는 없다.

```powershell
@'
import json
import sys
from pathlib import Path

sys.path.insert(0, "src")
from contracts.events import NginxAccessLogEvent
from detection.rules import evaluate_web_rules

path = Path("docs/roles/security/evidence/p3-8-2026-10-19/nginx-selected-events.json")
cases = json.loads(path.read_text(encoding="utf-8"))["cases"]
for name in ("single", "double"):
    events = [NginxAccessLogEvent.parse_line(row["message"]) for row in cases[name]["events"]]
    assert all(event is not None for event in events)
    attack = [event for event in events if event.source_ip == "3.25.82.148" and "%" in event.raw_message]
    normal = [event for event in events if event.source_ip == "1.245.252.171"]
    assert len(attack) == 1 and len(normal) == 18
    assert evaluate_web_rules(attack) == (True, "PATH_TRAVERSAL")
    assert evaluate_web_rules(normal) == (False, None)
    print(name, "PATH_TRAVERSAL; normal 18/18 non-threat")
'@ | .\.venv\Scripts\python.exe -B -
```

이번 두 경로의 결과를 삼중 인코딩·쿼리 공격·임의의 인코딩 변종으로 일반화하지 않는다. 관측한 정상 외부 요청의 HTTP 200은 사례별 18건이며 일반 운영 가용성 100%나 오탐률 0%의 분모로 확대하지 않는다. 10월 16일 원본의 조회 이력 부족은 해당 데이터의 한계로 유지한다.

## 7. 검증 및 리뷰 상태

원본 ZIP CRC·SHA-256, B 응답 8페이지 해시·토큰 연결·종료, 선택 이벤트와 원본의 필드 일치, 두 인코딩 실제 입력의 룰 재생·정상 18건 묶음 비탐지 및 기존 매퍼 연결을 확인했다. 네트워크 PCAP·CSV·요약의 요청·응답·시각 대조도 수행했다.

사용자 변경을 보존한 같은 PR HEAD의 로컬 복제본 `.codex-build/p3-8-final-check-20261019/`에 이번 문서·JSON만 복사해 `powershell .\scripts\check.ps1`을 실행했다. **R&R 검사, Ruff 검사·포맷 검사 및 1,075 passed / 4 skipped**로 종료 코드 0을 확인했다. pytest 실행 시간은 244.82초이며, 소켓 차단 확인 테스트의 `getaddrinfo` 경고 1건은 실패가 아니다. 게이트 로그는 `.codex-build/p3-8-final-check-20261019-gate.log`에 보존했다.

독립 검토에서 계수·시각·출처·링크와 두 재현 명령을 확인했고 P1 지적은 없었다. 쿼리 공격도 검증한 것으로 읽힐 수 있는 문장은 경로 인코딩·차단 후 정상 접근으로 한정했다. 검증 기록을 반영한 최종 문서에 대해서는 JSON·발췌·링크·역할 범위·Git 공백 검사를 확인했다. 기존 설계 문서 수정과 `assets/`는 커밋에서 제외한다.

리뷰 요청의 두 실측을 보완한 결과이며, 기존 PR #196에서 클라우드 B의 재검토를 요청한다. 새 이슈·PR 생성, AWS 직접 연결, 공격 요청·리소스 변경은 수행하지 않는다.
