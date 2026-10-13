# [P3-3] Kali/Hydra 공격 및 L4 패킷 단절 실측 준비·보류 보고서

- Notion Task: https://notion.so/3f704d37c2258094a489f4242ec8f2db
- GitHub Issue: https://github.com/mmmphyun/aleph-project/issues/171
- 준비 일자: 2026-10-13 KST
- 실제 실험 일자: 미정
- 현재 판정: **실측 미수행 / 10초 충족 여부 판정 불가**

## 1. 범위와 현재 결론

승인 대상은 `TARGET_EC2_PUBLIC_IP:22` 한 곳이며 테스트 전용 계정의 합성 인증 실패 5회만
허용한다. 계정 열거, 비밀번호 스프레이, 포트 스캔, 다른 서비스 접근은 범위 밖이다.

이번 준비에서는 Kali WSL과 제한 실행 도구를 구성하고 로컬 mock 회귀 테스트만 수행했다.
실제 타깃 TCP 연결, Hydra 인증 시도, 패킷 캡처, AWS 조회 및 격리·복구는 수행하지 않았다.
따라서 준비 성공을 인증 실패 재현이나 10초 관통 파이프라인 성공으로 해석할 수 없다.

실측을 보류한 근거는 다음과 같다.

- 테스트 전용 계정이 없으며 임의로 `root`, `admin`, `ubuntu` 계정을 선택할 수 없다.
- 사용자 인계 기준 CloudWatch → Lambda → SG 교체 → Slack 파이프라인이 아직 연결되지 않았다.
- 저장소 기본 Baseline SG의 SSH ingress는 VPC 내부 CIDR만 허용한다. 배포 환경에서 외부 Kali
  출발 IP를 허용한 별도 증거가 없다.
- 격리 뒤 Baseline SG를 복구할 담당자·승인된 절차가 없다.
- 인증 가능한 계정·키가 없어 공격 전 기존 SSH 세션을 만들고 유지할 수 없다.

## 2. 배포 기준과 실행 환경

| 항목 | 확인 결과 |
| --- | --- |
| 마스킹 대상 | `TARGET_EC2_PUBLIC_IP:22` |
| 저장소 기준 | P3-2 PR #170, merge commit `6ded30d` |
| 실제 배포 버전 | 독립 확인 불가; 저장소 병합과 런타임 배포를 동일시하지 않음 |
| 공격 환경 | Kali GNU/Linux Rolling 2026.2, WSL2 |
| 커널 | `6.18.33.2-microsoft-standard-WSL2` |
| 경로 | Kali `eth0` → WSL NAT → Windows 물리 이더넷 → 인터넷 |
| VPN | 활성 기본 경로에서 확인되지 않음 |
| Hydra | 9.7 |
| tcpdump | 4.99.6 |
| TShark | 4.6.6 |
| Wireshark GUI | 미실행 |
| 시계 | Kali `NTPSynchronized=yes`; Windows `w32tm`은 권한 부족으로 독립 확인 실패 |

Kali 내부 주소와 서버가 관측할 공인 출발 주소는 WSL NAT 때문에 다르다. 현재 공인 출발 주소는
값을 공유하지 않고 Git 밖 비공개 파일로만 기록했다. 실제 실험 직전 주소가 바뀔 수 있으므로 다시
관측하고 SG 허용 증거와 대조해야 한다.

## 3. 실행 도구의 안전 계약

`network/ec2_hydra_measurement.sh`의 기본 동작은 무트래픽 `plan`이다. 실제 실행은 다음 조건을
모두 만족해야 한다.

1. `run --execute`를 함께 지정한다.
2. 대상은 환경변수로만 전달된 정규화 공개 IPv4이며 출력에는 `TARGET_EC2_PUBLIC_IP`만 남긴다.
3. 계정은 `cloudshield_test` 또는 `cloudshield_test_<식별자>` 형식만 허용한다.
4. 파이프라인 준비, 출발 IP 허용, 복구 준비 확인값이 모두 `yes`여야 한다.
5. Git 밖의 소유자 전용 0700 증거 디렉터리를 사용한다.
6. 한 증거 루트에 원자적 실행 마커를 만들며 재실행은 0회로 제한한다.
7. 캡처 준비와 공격 전 TCP 22 기준선이 확인된 뒤에만 Hydra를 시작한다.

Hydra 인자는 합성 오답 5개, 동시성 1, 응답 제한 3초, 연결 간 대기 1초, 전체 30초로 고정한다.
예상치 못한 인증 성공을 발견하면 해당 Hydra 프로세스 그룹만 중단한다. 캡처는 단일 `eth0`,
IPv4/TCP 22, 최대 45초·2,000패킷이며 신규 연결 탐침은 1초 간격 30회이다. 원본 Hydra 출력,
PCAP, TShark CSV와 manifest는 공유 저장소에 넣지 않는다.

실행 예시는 실제 주소나 계정을 포함하지 않는다.

```bash
bash network/ec2_hydra_measurement.sh plan

# 필수 준비 확인과 비공개 환경변수 설정 후에만 허용
bash network/ec2_hydra_measurement.sh run --execute \
  --interface eth0 \
  --evidence-root /var/lib/cloudshield-evidence/p3-3
```

## 4. 정상 기준선과 실험 절차

실제 실행이 허용되면 다음 순서를 변경하지 않는다.

1. 실제 출발 공인 IP와 `eth0` 기본 경로, 장비별 UTC 시각을 기록한다.
2. Cloud A/B로부터 배포 커밋, 구독 필터, 자동 대응, 대상 매핑, 복구 준비를 확인한다.
3. 클라이언트 캡처 준비 메시지를 확인한다. 서버 캡처는 담당자가 별도로 준비한다.
4. 신규 TCP 22 연결 1회를 정상 기준선으로 확인한다.
5. 가능하면 별도 운영자가 인증된 기존 SSH 세션 하나를 유지한다.
6. 합성 오답 5개를 동시성 1로 한 번만 실행한다.
7. 신규 TCP 연결 탐침과 캡처를 유지하고 서버 로그·Lambda·SG·Slack 증거를 대조한다.
8. 원본 증거의 크기·SHA-256·종료 코드·드롭 통계를 기록한 뒤 담당자가 복구한다.

테스트 계정이나 키가 없는 현재 상태에서는 5번의 기존 세션을 만들 수 없다. TCP 기준선만으로
인증 세션 지속 여부를 대신 증명하지 않는다.

## 5. 사건 타임라인과 10초 판정식

| 사건 | UTC 시각 | 증거 | 현재 상태 |
| --- | --- | --- | --- |
| 공격 시작 | 미발생 | Hydra private log | 미수행 |
| 최초 인증 실패 | 미발생 | 서버 auth log | 미수행 |
| 5번째 실패·임계값 충족 | 미발생 | 서버 이벤트 시각 | 미수행 |
| Lambda 탐지 | 미발생 | Lambda 로그 | 파이프라인 미연결 |
| SG 교체 API 완료 | 미발생 | AWS API/CloudTrail 또는 담당자 증거 | 미수행 |
| 실제 부착 SG 확인 | 미발생 | EC2 describe 결과 | 미수행 |
| 마지막 신규 연결 성공 | 미발생 | 탐침·PCAP | 미수행 |
| 최초 신규 연결 실패 | 미발생 | 탐침·PCAP | 미수행 |
| Slack 도착 | 미발생 | Slack 카드 시각 | 파이프라인 미연결 |

사전에 정의한 계산식은 다음과 같다.

- 최초 공격 기준 지연: `SG 부착 확인 − 공격 시작`
- 탐지 임계값 기준 대응 지연: `SG 부착 확인 − 5번째 서버 인증 실패 이벤트 시각`
- 전체 관통 지연: `max(SG 부착 확인, Slack 도착) − 공격 시작`
- 주기 탐침의 차단 시각: `[마지막 성공 시각, 최초 실패 시각]`의 구간

현재는 모든 시작·끝 증거가 없어 세 계산 모두 **판정 불가**다. 향후에도 SG API 성공만으로 패킷
차단이나 Slack 전파를 대신 증명하지 않는다.

## 6. 패킷 및 연결 분석 표

실제 PCAP이 생성되지 않았으므로 프레임을 합성하지 않는다.

| 프레임 | UTC/상대 시각 | 방향 | TCP stream / 4-tuple | 플래그 | Seq / Ack | 관측 의미 |
| ---: | --- | --- | --- | --- | --- | --- |
| N/A | 미관측 | 미관측 | 미관측 | SYN/SYN-ACK/ACK/FIN/RST 미관측 | 미관측 | 실제 타깃 PCAP 없음 |

| 지표 | 계획 상한 | 실제값 | 구분 |
| --- | ---: | ---: | --- |
| 합성 후보 | 5 | 0 | 실행 보류 |
| 서버 인증 실패 | 5 | 0 | 서버 로그 없음 |
| Hydra 동시성 | 1 | 0 | 실행 보류 |
| 기준선 연결 | 1 | 0 | 실행 보류 |
| 신규 연결 탐침 | 30 | 0 | 실행 보류 |
| 패킷 | 2,000 | 0 | PCAP 없음 |
| 재실행 | 0 | 0 | 계약 준수 |

## 7. 증거와 로컬 검증

| 증거 식별자 | 위치·해시 | 공개 여부 |
| --- | --- | --- |
| `P3-3-SOURCE-IP-OBS-01` | `/var/lib/cloudshield-evidence/p3-3/source-public-ip.private`, SHA-256 `ed6d175fc1f2a3f536404d0bfef7634b60d076eae63c83c30bb86d8f3dd1b755` | 비공개 원본, mode 600 |
| 증거 루트 | `/var/lib/cloudshield-evidence/p3-3`, mode 700 | Git 밖 Kali ext4 |
| Python 러너 | SHA-256 `78cbcb9edb549e014f971a66d339634a049e2cb438a34b48119325a7cdc4878c` | 공유 소스 |
| Shell 진입점 | SHA-256 `adf96c67bb8ae596f3ddb2c4ca157e83d0c2c2600c0cd493a5a7d03b7a99a39c` | 공유 소스 |
| 기존 캡처 스크립트 | SHA-256 `01e2e693d5426699aab921b163b3a379fd8257357afc0d15aa68f155179499e7` | 재사용 소스 |
| 네트워크 테스트 | SHA-256 `6beaa1cf980f1ce0a359cae0579f4ddb1c7ea09131bcae0d56b3761655f1f0a3` | 공유 소스 |

신규 mock 단위 테스트 40개가 통과했다. 공개 대상 검증, 전용 계정 규약, 준비 플래그 선검사,
Hydra 고정 argv, 합성 후보 5개, 단일 실행 마커, 종료 코드 비신뢰 분류, TCP 22 단일 탐침,
기본 plan의 무부작용을 검증했다. 이 결과는 실제 EC2·AWS·Slack 실측이 아니다.

작업 트리의 기존 `.pytest_cache`는 샌드박스 ACL 때문에 `check.ps1` 경로 순회가 거부됐다.
검사 기준을 완화하지 않고 `.codex-build/p3-3-check`에 로컬 Git 복제본을 만들고 위 해시의 변경
소스를 복사한 뒤 `pyproject.toml`의 기존 `dev` extra를 설치했다. 해당 Windows/Python 3.14.7
환경에서 `powershell .\scripts\check.ps1`을 우회 플래그 없이 실행한 결과 R&R, 테스트 경로,
Ruff lint, 126개 파일 format 검사와 pytest가 모두 통과했다. pytest 결과는
`964 passed, 4 skipped, 1 warning`이며 경고는 기존 소켓 차단 smoke 테스트의 DNS 호출 차단이다.

## 8. 대체 원인, 중단 및 복구

### 기존 SSH 세션 유지 판단

AWS 공식 연결 추적 문서에 따르면 SG 규칙을 바꿔도 **추적 중인 TCP 연결은 즉시 끊기지 않고**
연결 추적 만료까지 허용될 수 있다. 반대로 양방향 `0.0.0.0/0` 허용처럼 추적되지 않은 흐름은
허용 규칙 변경 시 즉시 끊길 수 있다. 따라서 “격리 SG 부착 = 기존 SSH 세션 단절”로 단정할 수 없다.

- 이번 실험의 관측 목표는 기존 세션 생존 여부와 무관하게 **격리 뒤 신규 TCP/22 연결이 10초 안에
  실패하는지**로 고정한다.
- 복구용 기존 세션은 `/32` 출발지처럼 추적되는 조건에서 사전에 만들고 keepalive를 사용하되,
  보장된 복구 채널로 간주하지 않는다. Session Manager 또는 콘솔 접근을 별도 복구 채널로 준비한다.
- 기존 연결까지 즉시 강제 단절해야 한다면 SG만으로는 부족할 수 있다. NACL은 기존 연결도 끊을 수
  있지만 서브넷 전체 영향이 있으므로 이번 네트워크 역할 실험 범위 밖의 별도 승인 사항이다.

근거: [Amazon EC2 security group connection tracking](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html)

신규 연결 무응답이 관측되더라도 다음 원인을 구분해야 한다.

- Baseline SG에 출발 공인 IP가 허용되지 않음
- sshd 비밀번호 인증 비활성화 또는 전용 계정 미존재
- 호스트 방화벽, 라우팅, WSL NAT/VPN 변경
- tcpdump 권한·인터페이스 오류 또는 캡처 드롭
- CloudWatch 지연, 구독 필터·Lambda 연결 실패
- SG 교체가 아닌 sshd 제한·Hydra 도구 오류

예상치 못한 인증 성공, 캡처 미준비, 기준선 실패, 대상 불일치, 서비스 이상, 복구 준비 상실 시
즉시 중단하고 비공개 증거를 보존한다. 이번에는 SG가 변경되지 않아 복구 작업도 발생하지 않았다.
향후 복구는 Cloud A가 기존 Baseline SG 식별자를 사전 기록하고 승인된 방법으로 재부착한 뒤,
Cloud B가 SSH·수집·Slack 상태를 확인해야 한다. 네트워크 담당 도구는 SG 변경이나 복구를 수행하지 않는다.

## 9. 후속 협업 조건

- Cloud B: `cloudshield_test` 전용 계정, 비밀번호 인증 실패 로그 형식, 서버측 캡처와
  CloudWatch/Slack 관측 경로 제공
- Cloud A: 외부 Kali 공인 출발 IP의 TCP 22 허용 증거, 배포 커밋·대상 매핑·자동 대응 활성화,
  이전 300초 실패 윈도우 상태, Baseline SG 복구 담당자와 절차 제공
- 보안: 배포된 임계값이 동일 계정 5회/300초 정책과 일치하는지 확인
- 네트워크: 실험 직전 공인 출발 IP 재관측, 캡처 준비, 단일 실행 및 원본 증거 보존

위 조건이 충족되기 전에는 Draft 상태를 유지하며 P3-3 완료나 10초 SLA 달성을 선언하지 않는다.
