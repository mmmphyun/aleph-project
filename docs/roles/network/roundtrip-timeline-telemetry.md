# 공격·차단·복구 왕복 관측 요약

- Notion Task: https://notion.so/40504d37c22581f89cd1f9cdba5025c7
- Issue: https://github.com/mmmphyun/aleph-project/issues/219
- 기반 main: `c1d1490` (2026-10-27)
- 범위: `network/roundtrip_timeline.py`, `tests/unit/test_network.py`, 이 문서

## 목적과 재사용

`roundtrip_timeline.py`는 **이미 보존한 파일만** 읽는 오프라인 CLI다. 공격·탐침·SSH·캡처·AWS 복구를 실행하지 않는다. 실행별 연결 manifest로 기존 자료와 선택한 사건을 묶어 요약 JSON 하나를 생성한다. 저장된 파일로 다시 계산할 수 있으며 프로세스 메모리를 다음 실행의 상태 저장소로 사용하지 않는다.

| 자산 | 재사용 관계 |
| --- | --- |
| `demo_attack_runner.py` | 기존 `events.jsonl`과 512행·행당 4KiB 제한. 기록 순번·원래 사건 시각·단조 경과 시간을 구별 |
| `ec2_hydra_measurement.py` | 비공개 SSH manifest의 baseline/probes/호출 경계와 PCAP 파생 CSV 규격. 기존 1MiB 청크 해시 패턴 계승 |
| `web_dir_scan.sh` | curl 모드의 요청별 시작/확인 시각·HTTP 상태·종료 코드. 실제 패킷 송신 시각으로 승격하지 않음 |
| `sg_connection_timeline.py` | 기존 Decimal epoch 검증·제한된 파일 읽기 재사용. 합성 echo의 SG 교체 사건을 공격·복구 사건으로 바꾸지 않음 |
| `waf_packet_timeline.py` | TCP CSV 검증·스트림/방향/플래그 분석을 직접 호출. SSH exporter의 flags 열만 기존 열로 투영 |

새 패킷 디코더·DB·큐·공통 사건 모델을 만들지 않는다. `src/contracts/` 및 A/B/보안 코드는 변경하지 않는다. 실제 IncidentReport의 `incident_id`를 연결할 수 있지만 요약은 탐지 보고서를 대신하지 않는다. 사건 ID 생성·침해사고 매핑을 다시 구현하지 않는다.

## 입력 연결 manifest

CLI는 입력 manifest와 **존재하지 않는** 출력 경로를 받는다. 경로는 로컬 파일이며 입력의 상대 증거 경로는 manifest 디렉터리를 기준으로 해석한다. 입력·출력은 Git 밖 비공개 실행 디렉터리에 보존한다. CLI 인자로 원시 로그·자격증명을 전달하지 않는다.

```powershell
uv run python network/roundtrip_timeline.py C:\PrivateEvidence\RUN\input.private.json C:\PrivateEvidence\RUN\summary.private.json
```

Linux에서도 같은 Python CLI를 사용할 수 있다. 실행에 Hydra/curl/tcpdump/TShark/AWS 자격증명이 필요하지 않다. 하드 링크를 지원하는 로컬 파일시스템이 필요하며 미지원 저장소에서는 실패한다.

manifest 필드:

| 필드 | 규격 |
| --- | --- |
| `schema_version` | `cloudshield-roundtrip-input-v1` |
| `run_id`, `target_key` | 실행과 비공개 대상의 공유용 식별자. 1..100자의 영숫자 및 `_.:/-` |
| `scenario` | `ssh` 또는 `web`. `all` 러너 결과는 선택한 시나리오별로 따로 요약 |
| `incident_id` | 실제 사건 ID 또는 `null`. run_id로 대체하거나 자동 생성하지 않음 |
| `clocks` | 시계 ID별 `{ "max_error_seconds": null }` 또는 측정한 최대 절대 오차 `"0"`..`"5"`초. 미측정은 반드시 null |
| `measurement_limits` | `probe_interval_seconds`, `probe_timeout_seconds`: 양수 십진 문자열 또는 미측정 null |
| `evidence` | 아래 규격의 증거 1..32개 |
| `source_ip`, `target_ips` | TCP 공격 스트림 선택 시 필요한 비공개 IPv4/타깃 IPv4 배열. 요약에는 출력하지 않음 |
| `target_origin` | Web 스캐너 입력에 기록된 정확한 origin. 요약에는 출력하지 않음 |

증거 항목은 `evidence_id`, `format`, `path`, `sha256`, `clock_id`, `run_id`, `scenario`, `target_key`를 가진다. 모든 실행·대상·시나리오 값은 manifest와 같아야 한다. 예상 SHA-256은 기존 보존 manifest 또는 별도 검증한 값으로 채운다. 분석 시 실제 바이트와 다시 대조한다. 같은 파일의 이중 등록·ID 중복·JSON 중복 키·비유한 수치는 거부한다.

| `format` | 입력 / 추가 필드 |
| --- | --- |
| `runner_events` | 기존 JSONL. start의 실제 run_id 검증. `late_probe`는 후보로 집계하지 않음 |
| `ssh_manifest` | `cloudshield-p3-3-private-evidence-v1`. `source_run_id`는 실제 하위 실행 ID. 상위 러너의 완료 기록이 있으면 하위 ID·manifest 해시 대조 |
| `web_scan` | 기존 curl key=value 요약. `target_origin`과 대조. gobuster는 요청별 시각이 없어 지원하지 않음 |
| `tcp_csv` | 기존 TCP 필드 CSV 또는 SSH exporter CSV. `start_epoch`, `end_epoch`, 선택적 `attack_streams` 필요 |
| `observations` | 아래 표준 sidecar. 수동 선별/서버 전달/추가 복구 탐침을 출처와 함께 연결 |
| `opaque` | PCAP·A/B 보존 원문 등. 바이트 해시만 검증하며 내용을 추정하지 않음 |

SSH `attack_streams` 예:

```json
[{"stream":7,"source":"192.0.2.1:40001","destination":"192.0.2.2:22"}]
```

이는 **사용자가 별도 식별한 공격 연결**이다. 캡처의 첫 SYN을 무조건 공격으로 선택하지 않는다. baseline·독립 탐침·Hydra 스트림을 먼저 대조해야 한다. 재전송을 포함한 지정 스트림의 가장 이른 송신 SYN만 선택한다. TCP CSV에서 HTTP 요청을 알 수 없으므로 Web의 `attack_streams` 지정은 거부하며 별도 HTTP 관측을 제공해야 한다. 원본 PCAP과 CSV 관계는 `opaque` PCAP 해시와 선별 좌표를 함께 보존한다. CSV가 해당 PCAP에서 파생됐는지는 해시만으로 독립 인증할 수 없다.

## 추가 관측 sidecar

sidecar는 `run_id`, `scenario`, `target_key`, `events`를 갖는다. 사건마다 다음 필드를 제공한다.

| 필드 | 의미 |
| --- | --- |
| `event_id`, `kind` | sidecar 내부 고유 ID와 아래 사건 종류 |
| `time` | 원본 UTC ISO 8601 또는 문자열 epoch 초. 소수 최대 9자리 |
| `resolution_seconds` | 생략하면 원본 자릿수 기준. `"1"`..`"0.000000001"` 중 하나 또는 불명 null. 원본보다 세밀하게 선언할 수 없음 |
| `source_kind` | `tcp_probe`, `http_probe`, `pcap_tcp`, `pcap_http`, `http_request`, `cloud_a`, `cloud_b`, `operator`, `runner` |
| `backing_evidence_id`, `locator` | 함께 해시한 다른 원본 증거 ID와 frame/행/eventId/API 기록 좌표. 자기 자신만 참조할 수 없음 |
| `outcome`, `connection_kind` | 탐침에 필수. outcome은 connected/timeout/refused/network_error/rst/fin/http, 연결 종류는 new/established |
| `http_status` | HTTP 탐침의 정수 응답 코드. 동일 루트 정상 탐침 200을 baseline·회복에 사용 |
| `incident_id` | 서버 원본에 있을 때만 실제 사건 ID. manifest의 incident_id와 다르면 거부 |

사건 종류는 `baseline`, `attack_invoked`, `first_attack`, `probe`, `recovery_requested`, `recovery_started`, `recovery_api_completed`, `configuration_verified`, `recovery_attested`, `observation_ended`, `waf_block`이다.

`first_attack`에는 실제 패킷/요청 로그 관측을 제공한다. Web `pcap_tcp` SYN은 첫 HTTP 요청으로 인정하지 않는다. 기존 web-scan의 curl 호출 직전 기록은 `attack_invoked`로만 수입한다. A 복구 요청·시작·API 완료·구성 확인은 `cloud_a` 출처가 필요하다. 운영자 확인은 `recovery_attested`로만 기록한다. WAF BLOCK은 A/B 원본의 별도 사건이며 클라이언트 403과 등치하지 않는다.

사건 ID가 없는 B의 START/END/REPORT 시각만으로 사건 연결을 완료하지 않는다. `linked`는 제공된 서버 증거의 사건 ID·실행 연결이 일치한다는 뜻이다. 해시·출처 선언이 AWS의 독립된 진위 인증이라는 뜻은 아니다. 원본의 선별·마스킹 이력도 별도로 보존해야 한다.

## 합성 예제 만들기

다음은 **실측이 아닌 테스트용 합성 자료**다. 빈 비공개 디렉터리에서 실행하면 세 파일을 독점 생성한다. 어떠한 통신도 수행하지 않는다. `raw.txt`는 실제 PCAP이 아니다.

```python
import hashlib
import json
from pathlib import Path

root = Path(".")  # Git 밖의 새 합성 실행 폴더에서 실행
binding = {"run_id": "synthetic-run", "scenario": "ssh", "target_key": "test-target"}
events = []
for key, kind, stamp, outcome in [
    ("baseline", "baseline", "100.000000001", "connected"),
    ("attack", "first_attack", "101.000000001", None),
    ("block", "probe", "103.000000002", "timeout"),
    ("recovered", "probe", "105.000000004", "connected"),
]:
    row = {
        "event_id": key,
        "kind": kind,
        "time": stamp,
        "source_kind": "pcap_tcp" if kind == "first_attack" else "tcp_probe",
        "backing_evidence_id": "raw",
        "locator": "synthetic/" + key,
    }
    if outcome:
        row.update(outcome=outcome, connection_kind="new")
    events.append(row)
sources = [
    ("raw", "opaque", b"SYNTHETIC ONLY"),
    ("obs", "observations", json.dumps({**binding, "events": events}).encode()),
]
evidence = []
for name, form, raw in sources:
    path = root / (name + ".txt")
    with path.open("xb") as handle:
        handle.write(raw)
    evidence.append(
        {
            **binding,
            "evidence_id": name,
            "format": form,
            "path": path.name,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "clock_id": "client",
        }
    )
manifest = {
    **binding,
    "schema_version": "cloudshield-roundtrip-input-v1",
    "incident_id": None,
    "clocks": {"client": {"max_error_seconds": None}},
    "measurement_limits": {"probe_interval_seconds": "1", "probe_timeout_seconds": "0.8"},
    "evidence": evidence,
}
with (root / "input.private.json").open("x", encoding="utf-8") as handle:
    json.dump(manifest, handle)
```

이후 CLI에 `input.private.json`과 새 `summary.private.json` 경로를 지정한다.

## 요약 필드와 계산

출력 버전은 `cloudshield-roundtrip-summary-v1`이다. 시각·지연·해상도·오차는 십진 **문자열**이며 누락은 null이다. 사건은 `timeline`에 원시 시각·UTC·epoch·해상도·시계·출처·좌표와 함께 보존한다. 역순 입력 여부와 동일 이벤트 중복 수는 `integrity`에 기록한다. 동일 ID·다른 내용은 오류다. 같은 시각의 정상과 차단 후보는 순서를 결정할 수 없어 거부한다.

| 필드 | 의미 |
| --- | --- |
| `observations` | 호출·첫 실제 공격·baseline·마지막 정상·첫 차단 후보·복구 제어·첫 정상 회복의 선택 사건 또는 null |
| `durations.block_observation` | 실제 첫 공격 → 첫 차단 후보 |
| `durations.block_hold_observation` | 첫 차단 후보 → 첫 정상 통신 회복. Notion의 T2−T1 |
| `durations.recovery_processing_observation` | A의 복구 실행 시작 → 첫 정상 통신 회복. 시작 증거 없으면 null |
| 각 지연의 `basis` | 동일 시계 wall time 또는 장비 간 wall time. 단조 경과 시간과 혼합하지 않음 |
| `correlation.status` | incident_id 미확보 unlinked / ID만 선언 unverified / 일치하는 서버 증거 linked |
| `stage_status` | 후보·회복 미관측, 미확인 사유, 중단, 파일 종료 관측, 구성 증거 유무. 멱등성·SLA·정책 원인은 별도 미평가 |
| `evidence` | 증거 ID·형식·실제 SHA-256·바이트 수·하위 실행 ID·연결 선언 방식. 원본 파일 경로·IP는 복사하지 않음 |
| `input_manifest_sha256` | 이번 계산에 사용한 연결 manifest의 원본 바이트 해시 |

합성 예제의 주요 출력:

```json
{
  "incident_id": null,
  "correlation": {"status": "unlinked", "basis": null},
  "durations": {
    "block_observation": {"seconds": "2.000000001", "reason": null},
    "block_hold_observation": {"seconds": "2.000000002", "reason": null},
    "recovery_processing_observation": {"seconds": null, "reason": "endpoint_not_observed"}
  }
}
```

위 출력은 일부 필드만 발췌했다. 관측이 중단됐거나 first_attack/차단/회복이 없어도 유효한 미완료 요약을 만들 수 있다. 예를 들어 회복 미관측이면 `stage_status.recovery=not_observed`, `recovery_reason=normal_after_block_not_observed`, 유지 구간의 seconds=null이다. 미완료 요약 생성의 CLI 종료 코드는 0이며 파이프라인 성공을 뜻하지 않는다.

회복 미관측 출력의 발췌 예:

```json
{
  "stage_status": {
    "block": "candidate_observed",
    "recovery": "not_observed",
    "recovery_reason": "normal_after_block_not_observed"
  },
  "durations": {
    "block_hold_observation": {"seconds": null, "reason": "endpoint_not_observed"}
  }
}
```

손상 JSON, 잘못된 시각/해상도, 실행·대상·사건 혼합, 음수 구간, 해시 불일치, 파일 상한·I/O 실패는 종료 코드 2와 다음 진단으로 종료한다. 원문·경로·주소·내부 예외는 콘솔에 재출력하지 않는다.

```text
요약 실패: 입력 연결·시각·해시·상한·새 출력 경로를 확인하세요
```

## 정확도·판정·보존 한계

- **첫 관측은 정책 적용 순간이 아니다.** SSH timeout 확인의 ended_at과 무응답 SYN 송신 시각을 구분한다. 정상 연결 정리 FIN/RST, refused, network error를 SG 차단으로 합치지 않는다. 기존 Established 연결은 신규 연결의 차단/회복 표본으로 쓰지 않는다.
- HTTP 403은 후보이며 WAF 원본 BLOCK·규칙·request ID 대조가 필요하다. timeout/5xx를 WAF 차단으로 표시하지 않는다. Web 스캔 후보 경로의 200/404를 루트 정상 탐침 회복으로 사용하지 않는다.
- A의 API 완료/구성 조회와 실제 통신 회복은 별도 사건이다. 통신 회복으로 구성 원복·복구 멱등성을 증명하지 않는다. API 완료보다 먼저 통신이 회복될 수 있어 이 둘의 순서를 강제하지 않는다.
- 원본 초 단위 시각에 밀리초를 추가하지 않는다. 기존 러너는 observed_at을 밀리초 형식으로 정규화하므로 원래 해상도는 null로 남기고, 탐침 details/SSH manifest/Web 원문이 있으면 해당 원본 해상도를 사용한다. 원본의 소수 자릿수는 NTP 정확도 보장이 아니다.
- 장비 간 시계 오차는 미측정 시 null이다. 선언된 두 최대 절대 오차의 합을 보수적인 차이 오차 한계로 표기한다. 같은 시계라도 안정성·step 보장은 없으며 이 값은 탐침 간격/timeout/시각 양자화까지 포함한 전체 정확도가 아니다.
- 각 탐침의 `process_elapsed_ms`와 러너의 `runner_process_elapsed_ms`는 해당 프로세스의 단조 시계 경과 값이다. 서버 wall time과 빼지 않는다. 구간 계산은 명시된 사건 epoch 차다.
- 첫 공격 기준 지연과 서버 탐지 조건 충족 이후 지연은 별도 지표다. 이번 모듈·합성 테스트로 10초 SLA를 선언하지 않는다.
- 메타데이터 파일 각 1MiB, 일반 관측 최대 10,000건(전체도 10,000건), 러너 512행·행당 4KiB, 증거 최대 32개·각 1GiB, 최종 요약 최대 8MiB. SHA-256은 1MiB 청크로 계산한다. 실행별 새 파일을 쓰며 무한 append하지 않는다.
- 입력 증거는 변경하지 않는다. 완성한 JSON을 같은 디렉터리 임시 파일에 flush/fsync한 뒤 덮어쓰기 없는 hard link로 게시한다. 쓰기 실패의 임시 파일만 제거한다. 기존 출력은 보존한다. 이는 프로세스 오류의 부분 JSON 노출 방지이며 전원 장애까지의 디렉터리 내구성 보장은 아니다.
- DB/강한 일관성 읽기/TTL/메시지 큐/DLQ는 로컬 유한 후처리에 비적용이다. 함수는 예외를 전파하고 CLI는 오류 종료한다. 자동 재공격·재시도·업로드는 없다.
- 실측 원본·실제 IP·민감 로그·자격증명은 Git에 추가하지 않는다. 공개 예제는 합성/마스킹하고 출처 변환 이력을 밝힌다. 해시 일치는 파일 식별이며 증거 출처의 독립 인증을 대신하지 않는다.

## A/B 연계와 P5-4 잔여 검증

A에서 필요한 자료: 실제 incident_id, run_id 연결 근거, 대상/출발지/시나리오, 복구 요청·실행 시작·API 완료·구성 재조회 각각의 원본 시각·해상도·시계 ID·요청 ID·보존 해시. 새 `apply_rollback` 반환 성공값만으로 시작/완료 시각을 만들어 넣지 않는다.

B에서 필요한 자료: 사건 연결 로그·eventId·원래 timestamp와 ingestionTime의 구별, WAF 요청/BLOCK 원본 좌표, Slack 원본 ts와 게시 구간. P4-2 공개 로그는 선택·마스킹된 증거이며 원본 `source_sha256`와 체크아웃 파일의 해시를 혼동하지 않는다. Incident ID 없는 Lambda 런타임 로그는 시간대만으로 직접 연결하지 않는다.

공통으로 필요한 합의: run_id↔incident_id 전달 경로, 원본 증거 보관·마스킹·수집 경로, 시계 오차 측정값, 탐침 위치·간격·timeout, A/B가 출력할 sidecar 규격. CloudWatch 업로드·Grafana datasource/패널 구현은 이번 범위에 없다. 타 직무에 자동 메시지를 보내지 않는다.

P5-4에서는 별도 승인 후 실제 SSH/Web 공격 첫 패킷/요청, 정상→차단 후보→회복 탐침, Web 별도 PCAP, WAF BLOCK 원본, A 복구 제어 기록·구성 원복·재실행 멱등성, 각 장비 시계 상태를 같은 실행별로 확보해야 한다. 현재 합성 검증을 실인프라 왕복 성공으로 표시하지 않는다.

## 품질 검증

`tests/unit/test_network.py`에서 외부 소켓 차단 상태로 기존 러너 실제 Reporter 출력·SSH/Web 결과·TCP CSV와 합성 sidecar를 검증한다. 정상뿐 아니라 미완료·시간 역전·중복 충돌·해상도 모순·출처 혼합·오류 판정·해시/용량·부분 저장 실패를 검출한다. 공통 mock 데이터·검증 게이트·의존성은 변경하지 않는다.

필수 게이트: 저장소 루트에서 `powershell .\scripts\check.ps1`. 2026-10-27 검증 결과:

- 원 작업 폴더 `C:\Aleph`: 새 합성 테스트 **71개 통과**, Ruff lint/format 통과. pytest 캐시 쓰기 경고가 있었다. 필수 게이트는 R&R 통과 후 기존 `.pytest_cache` ACL로 테스트 파일 경로 순회에서 중단됐다. 캐시 ACL·게이트·검증 제약을 변경하지 않았다.
- 분리 검증 폴더: `C:\Users\User\.codex\worktrees\network-roundtrip-validation\Aleph`. 기준 커밋 `c1d149050f2b4df9ee9176d91faeb7721b6efd5e`에 이 작업의 소스·테스트·문서 세 파일만 적용했다. 사용자 미추적 문서와 비공개 증거는 복사하지 않았다.
- 환경: Windows PowerShell, Python **3.12.14**, `uv sync --all-extras --locked`, Ruff **0.16.4**, pytest **8.4.2**, `AGENT_ROLE=network`. 역할 파일 없는 분리 환경의 정상 역할 식별값이며 가드 우회가 아니다.
- 같은 `powershell .\scripts\check.ps1`을 우회 옵션 없이 실행해 **종료 코드 0**. R&R·테스트 경로·Ruff lint·160개 파일 format 통과. pytest **1387 passed / 4 skipped / 1 warning, 183.17초**.
- skip 4건은 기존 Terraform mock 도구/provider 조건에 따른 네트워크 2건·WAF 2건이다. warning은 기존 `test_network_socket_is_blocked_by_default`가 DNS 소켓 차단을 확인하며 발생했다. skip을 통과 건수로 포함하거나 실인프라 검증으로 확대하지 않는다.
- 검증한 소스 SHA-256: `43bd20ad1d9a5096d7a242a70d5f1458dead865f7937c1ad3c0983f000ab2fc4`. 테스트 SHA-256: `b1b8a7db1a6375d1a9302fac36d7647c1209c824b4b27eb5fb39035e13e51103`. 원 작업 폴더와 검증 폴더의 바이트 일치를 대조했다.
- 전체 게이트 로그는 저장소 밖 `%TEMP%\cloudshield-roundtrip-check-final.log`에 보존했다. 문서의 합성 생성 예제와 CLI도 임시 디렉터리에서 그대로 실행해 정밀 지연·미확보 처리 결과를 확인했다. 최종 문서의 결과 기록·예제 보강은 코드/테스트를 바꾸지 않는다.
- 원격 CI 결과는 PR에서 별도 확인한다. 실제 공격·탐침·캡처·SSH·AWS 변경·P5-4 실측은 수행하지 않았다. 별도 요청 전 머지하지 않는다.
