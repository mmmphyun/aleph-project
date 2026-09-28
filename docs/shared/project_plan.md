# CloudShield 프로젝트 계획서

> **프로젝트 명**: CloudShield (클라우드 하이브리드 위협 탐지·자동 대응 및 SecOps 파이프라인)  
> **팀 구성**: 4인 (네트워크, 클라우드 B, 보안, 클라우드 A)  
> **개발 기간**: 2026.09.04 ~ 2026.11.04 (총 9주)  
> **현재 시점**: 2026.09.28 (4주차 완료 / 잔여 5주)  
> **상태**: Phase 2 시나리오 1(SSH) 파이프라인 결합 완료 $\rightarrow$ 시나리오 2(Web) 착수 단계  
> **핵심 가치**: "10초 관통 이벤트 구동 다중 계층 복합 차단 파이프라인"

---

## 01. 기획과 보안 목표

### 1.1 보호 대상 및 해결하고자 하는 문제
* **보호 대상**: AWS 퍼블릭 서브넷에 노출된 핵심 워크로드(EC2 인스턴스, 웹 서비스) 및 IAM 자격증명 자산.
* **클라우드 보안 관제의 주요 병목**:
  1. **수동 관제에 따른 대응 지연 (MTTD/MTTR)**: 보안 경보 발생 후 담당자가 콘솔에 접속해 IP를 차단하기까지 수 분에서 수 시간이 소요됨.
  2. **단일 계층 차단의 한계**: L4 Security Group이나 방화벽만 차단하면 이미 탈취된 세션 토큰과 웹 애플리케이션 계층(L7) 공격을 막지 못해 내부 횡적이동(Lateral Movement)으로 이어짐.
  3. **관제 대시보드 매몰**: 웹 UI 개발에 리소스가 편중되어 실제 인프라 침해 위협을 차단하는 코어 로직 검증이 부실해지는 문제.

### 1.2 핵심 솔루션 및 목표
* **단일 10초 관통 데모 파이프라인**:
  * 공격 발생 즉시 관제 인력의 수동 개입 없이 **10초 이내에 중앙 수집 $\rightarrow$ 위협 탐지 $\rightarrow$ L4/L7 복합 차단 $\rightarrow$ Slack 알림 전파**를 완결하는 자동화된 SecOps 파이프라인 구축.
* **정량적 핵심 성능 지표 (KPI)**:
  * **전체 파이프라인 관통 시간**: 공격 로그 생성 시점부터 차단 완료 및 알림 전파까지 $\le 10$초.
  * **차단 멱등성 및 계층별 독립 격리 보장**: Boto3 API 호출 간 레이스 컨디션을 방지하고, L4 SG 및 L7 WAF 차단을 계층별 독립 Boto3 호출로 집행해 부분 실패 시에도 기성공 조치를 안전하게 유지.
    * **오탐 방지 임계치 윈도우**: 5분(300초) 슬라이딩 윈도우 내 실패 횟수를 기반으로 상태를 판정해 단일 오인 트래픽 차단 방지 (`DETECTION_WINDOW_SECONDS = 300`).

### 1.3 핵심 위협 시나리오
1. **시나리오 1: SSH 무차별 대입 공격 (Hydra Brute-Force)**
   * 타깃 EC2 포트 22를 향한 대량의 인증 실패 유발 $\rightarrow$ 임계치 초과 시 L4 격리 Security Group 교체 및 인스턴스 네트워크 차단.
2. **시나리오 2: 웹 디렉토리 브루트포스 및 포트 스캐닝 (Nmap / Dirb)**
   * 웹 애플리케이션 엔드포인트 비정상 탐색 및 스캔 $\rightarrow$ 시그니처 매칭 즉시 L7 AWS WAF IPSet에 공격자 IP 동적 등록 및 HTTP 403 차단.
*(참고: IAM 자격증명 세션 무효화는 CloudTrail의 5~15분 수집 지연으로 인해 10초 실시간 경로에서 전략적으로 배제함 - 03.4절 참조)*

---

## 02. 서비스와 보안 설계

### 2.1 전체 시스템 아키텍처

```text
[공격자]
       │
       ▼ (Hydra / Nmap 모의 공격)
[타깃 워크로드 (EC2)]
       │ (로그 발생: /var/log/auth.log, /var/log/nginx/access.log)
       ▼
[CloudWatch Agent] (중앙 집중 수집 및 CW Logs 전송, Buffer Interval 최적화)
       │
       ▼ (CW Logs Subscription Filter)
[Lambda Orchestrator] (초경량 서버리스 오케스트레이터)
       ├─► [탐지 엔진 (Rule & Incident Mapper)] (ReDoS 방어 정규식 + 결정론적 ATT&CK 매퍼)
       ├─► [DynamoDB 상태 윈도우] (TTL 기반 5분(300초) 슬라이딩 윈도우 / 중복 차단 방지 원자적 상태 갱신)
       ├─► [복합 차단 엔진]
       │     ├─ L4: EC2 Security Group 격리 (인바운드 전면 차단)
       │     └─ L7: AWS WAFv2 IPSet 동적 등록 (웹 트래픽 차단)
       └─► [Slack Reporter] (Block Kit 기반 구조화된 침해사고 대응 카드 상황 전파)
```

### 2.2 공통 인터페이스 계약
* **설계 원칙**: 직무 간 데이터 결합도를 낮추고 런타임 타입 오류를 원천 차단하기 위해 Pydantic 기반의 엄격한 불변 데이터 모델 채택.
* **핵심 계약 모델 (`src/contracts/incident.py`)**:
  * `IncidentReport`: 보안 분석 엔진이 생성하고 차단 및 Slack 리포터 모듈이 소비하는 단일 표준 침해사고 보고서 규격.
    ```python
    # src/contracts/incident.py 핵심 필드 (실제 코드와 1:1 일치)
    class IncidentReport(BaseModel):
        incident_id: str
        attack_type: str  # 예: "SSH Brute Force", "SSH Password Spraying"
        mitre_id: str  # 예: "T1110.001", "T1110.003"
        risk_level: Literal["HIGH", "MEDIUM", "LOW"]
        source_ip: str  # IPv4 주소
        target_identifier: str  # EC2 Instance ID (i-...)
        target_accounts: tuple[str, ...]
        summary_ko: str
        action_required: Literal[
            "BLOCK_WAF",
            "QUARANTINE_EC2",
            "REVOKE_IAM_SESSION",
            "BLOCK_AND_QUARANTINE",
            "BLOCK_IP_ONLY",
            "ALERT_ONLY",
            "NONE",
        ]
        recommendations: tuple[str, ...]
    ```
  * `IncidentReport`는 테크 리드의 승인 없이 변경할 수 없는 보호 계약으로 관리됨.

### 2.3 다중 계층 복합 차단 및 복구 엔진
* **탐지 vs 차단 단계별 판정 기준**:
  * **1단계 위협 탐지**: 5분(300초) 슬라이딩 윈도우 내 단일 계정 실패 $\ge 5$회 시 `SSH Brute Force`(`risk_level = "HIGH"`, `BLOCK_AND_QUARANTINE`), 고유 계정 $\ge 2$개 도달 시 `SSH Password Spraying`(`risk_level = "MEDIUM"`, `BLOCK_IP_ONLY`)으로 판정하여 `IncidentReport` 생성.
  * **2단계 계층별 독립 차단 집행**: Lambda 오케스트레이터가 보고서의 **`action_required`** 값에 따라 대상별 Boto3 차단 API를 계층별 독립 Boto3 호출로 분기 실행함:
    * `action_required == "BLOCK_AND_QUARANTINE"`: SSH 무차별 대입 탐지 시 L4 EC2 격리와 L7 WAF IPSet 차단을 동시 실행.
    * `action_required in ("BLOCK_IP_ONLY", "BLOCK_WAF")`: 패스워드 스프레잉(`BLOCK_IP_ONLY`) 및 Web 스캔(`BLOCK_WAF`) 탐지 시 L7 WAF IPSet 차단 실행.
    * `action_required == "ALERT_ONLY"` 또는 `"NONE"`: 인프라 차단 API를 호출하지 않고 Slack 상황 전파만 수행.
* **계층별 차단 실행 동작**:
  * **L4 격리 (Security Group)**:
    * 인스턴스에 적용된 기존 SG를 제거하고 인바운드가 완전히 차단된 `sg-quarantine`으로 교체.
    * Boto3 `modify_instance_attribute` 호출 시 멱등성 보장.
  * **L7 웹 차단 (AWS WAFv2 IPSet)**:
    * 차단 대상 IP를 WAFv2 IPSet에 추가 (`update_ip_set`).
    * CloudFront 및 ALB 연동 웹 트래픽 드롭 (HTTP 403 차단).
* **오탐 발생 시 긴급 복구 절차**:
  * **L4 SG 격리 해제**: 관리자 확인 또는 오탐 판정 시, 대상 인스턴스의 Security Group을 원본 운영 SG(`sg-production`)로 원복(`modify_instance_attribute`).
  * **L7 WAF 차단 해제**: WAFv2 IPSet의 IP 주소 목록에서 오탐 차단된 `/32` 엔트리를 제거(`update_ip_set`)하여 정상 트래픽 유입 재개.

---

## 03. 개발과 협업 계획

### 3.1 4대 직무별 R&R 및 포트폴리오 경계

| 담당 직무 | 고유 도메인 영역 (면접 핵심 무기) | 산출물 및 관리 경로 |
| :--- | :--- | :--- |
| **네트워크** | • 모의 공격 시나리오 구현 (Hydra, Nmap 스크립트)<br>• 패킷 캡처 및 TCP 플래그/핸드셰이크 분석 보고서 | `network/`<br>`tests/unit/test_network.py`<br>`docs/roles/network/` |
| **클라우드 B** | • EC2 CloudWatch Agent 중앙 수집 구성<br>• Slack Block Kit 리포터 및 Nginx 로깅 포맷 정의 | `src/collector/`<br>`src/reporter/`<br>`tests/unit/test_collector.py`<br>`tests/unit/test_reporter.py`<br>`docs/roles/cloud-b/` |
| **보안** | • ReDoS 방어형 시그니처 탐지 정규식 룰<br>• MITRE ATT&CK 기반 결정론적 Incident Mapper | `src/detection/`<br>`tests/unit/test_rules.py`<br>`tests/unit/test_incident_mapper.py`<br>`docs/roles/security/` |
| **클라우드 A (PL)** | • 공통 계약(Contracts) 및 Lambda 오케스트레이터<br>• DynamoDB 윈도우 카운터, Boto3 복합 차단 엔진<br>• Terraform IaC 및 moto 가상 AWS 테스트베드 하네스 | `src/contracts/`<br>`src/remediation/`<br>`infra/`<br>`tests/conftest.py`<br>`docs/roles/cloud-a/` |

### 3.2 협업 거버넌스 및 코드 품질 파이프라인
* **WIP 1개 제한 및 PR Stacking 원천 금지**: 열린 PR이 있는 상태에서 신규 티켓 착수 금지.
* **1:1 상호 짝꿍 코드 리뷰 체계**:
  * `네트워크` $\leftrightarrow$ `보안`: 모의 공격 로그와 탐지 정규식 매칭 일치성 검증.
  * `보안` $\leftrightarrow$ `클라우드 B`: 정규식 포맷과 CloudWatch/Nginx 실제 수집 로그 포맷 일치성 검증.
  * `클라우드 B` $\leftrightarrow$ `네트워크`: 타깃 EC2 포트 및 Nginx 설정의 모의 공격 트래픽 수용성 검증.
  * `클라우드 A`: 전역 아키텍처 불변 계약 및 파이프라인 거버넌스 관리.
* **단일 로컬 검증 게이트 (`check.ps1`)**:
  * 모든 커밋/PR 전 `powershell .\scripts\check.ps1`을 실행하여 4중 검증(테스트 경로, Ruff Linter, Ruff Formatter, Pytest 100%) 강제.

### 3.3 9주간 개발 마일스톤 및 진행 현황

총 9주(2026.09.04 ~ 2026.11.04) 일정 중 4주차를 마친 시점(2026.09.28)이며, 기완료된 커밋과 잔여 계획을 단계별로 관리함:

```text
[전체 9주 타임라인 요약]
Phase 1 (W1~W2: 09.04 ~ 09.10) : 개발 하네스 & 가상 테스트베드 구축 [완료]
Phase 2 (W2~W4: 09.11 ~ 09.28) : 도메인 코어 로직 & 시나리오 1(SSH) 결합 [완료]
-------------------------------- [현재 시점: 2026.09.28 (잔여 5주)] --------------------------------
Phase 2.5 (W5~W6: 09.29 ~ 10.12) : 시나리오 2(Web Scan/WAF) 도메인 로직 구현
Phase 3   (W7~W8: 10.13 ~ 10.26) : Terraform IaC 인프라 프로비저닝 & AWS 배포
Phase 4   (W9   : 10.27 ~ 11.04) : 실기기 10초 관통 E2E 실측 & 데모/최종 발표
```

#### 1) 기완료 마일스톤 (2026.09.04 ~ 2026.09.28)
* **Phase 1: 개발 하네스 및 가상 테스트베드 구축 (09.04 ~ 09.10) [완료]**:
  * Pydantic V2 불변 데이터 계약(`src/contracts/`) 확정 및 Drift Guard 구축.
  * Moto 기반 AWS 격리 테스트베드(EC2, WAF, DynamoDB) 구축.
  * GitHub Actions 무인증 OIDC CI, PR 제목 린터, R&R 스코프 가드, 노션 동기화 배관 구축.
* **Phase 2: 도메인 코어 로직 및 시나리오 1 파이프라인 결합 (09.11 ~ 09.28) [완료]**:
  * **네트워크**: SSH 단일 모의 연결, tcpdump L4 캡처, SYN-ACK 타임라인 분석, Docker 격리 Hydra 공격 시뮬레이션 완료.
  * **보안**: SSH 무차별 대입 1차 시그니처 룰(`rules.py`), MITRE T1110.001 결정론적 IncidentReport 매퍼(`incident_mapper.py`), 오탐 방어 단위 테스트 완료.
  * **클라우드 B**: 타깃 EC2 리눅스/Nginx 초기화, CloudWatch Agent 수집 설정(`amazon-cloudwatch-agent.json`), Slack Block Kit 전파 모듈(`slack_notifier.py`) 완료.
  * **클라우드 A**: L4 Quarantine SG 교체 엔진, L7 WAF IPSet 차단 엔진, DynamoDB 2-버킷 타임스탬프 슬라이딩 윈도우(`auth_window.py`), 오케스트레이터-Slack 파이프라인 결합(PR #80) 완료.

#### 2) 잔여 마일스톤 (2026.09.29 ~ 2026.11.04)
* **Phase 2.5: 시나리오 2(Web Directory Scan & Spraying) 확장 (09.29 ~ 10.12, 2주)**:
  * **보안**: Nmap/Gobuster 웹 디렉토리 스캔 및 패스워드 스프레잉 시그니처 룰 추가, Nginx access.log 4xx/5xx 연속 발생 매핑.
  * **클라우드 B**: Nginx 로그 수집 경로 CW Agent 추가, 웹 공격용 CloudWatch 구독 필터 연계.
  * **네트워크**: Web 대상 Gobuster/Nmap 모의 공격 스크립트 작성 및 HTTP 트래픽 패킷 분석 보고서.
  * **클라우드 A**: 시나리오 2 WAF 차단 연계 오케스트레이터 파이프라인 결합.
* **Phase 3: Terraform IaC 인프라 프로비저닝 및 AWS 실제 배포 (10.13 ~ 10.26, 2주)**:
  * VPC, EC2 타깃 인스턴스, WAFv2 WebACL, DynamoDB, Lambda 오케스트레이터 프로비저닝 Terraform 모듈 작성 (`infra/terraform/`).
  * Trivy 기반 IaC 정적 보안 취약점 점검 100% 통과.
  * 실제 AWS 계정 환경에 인프라 배포 및 CloudWatch Agent 실기기 연동.
* **Phase 4: 실기기 10초 관통 E2E 실측 및 최종 발표 준비 (10.27 ~ 11.04, 1주)**:
  * 실제 AWS 인프라 환경에서 Hydra/Nmap 모의 공격 발사 $\rightarrow$ 공격 인입부터 Slack 알림 및 SG/WAF 차단 완료까지 타임스탬프 델타 실측 (목표: 10초 이내).
  * 10초 관통 데모 영상 녹화 및 터미널-Slack-AWS 콘솔 3분할 시연 준비.
  * 발표 자료(HTML 슬라이드) 최종 확정 및 프로젝트 결과 보고서 완료.

### 3.4 기술적 난제 및 아키텍처 트레이드오프
1. **CloudTrail 수집 지연과 IAM 세션 실시간 차단 배제 (핵심 결정)**:
   * *문제*: CloudTrail의 CloudWatch Logs 전달 지연(5~15분)으로 인해 10초 실시간 SLA를 물리적으로 충족할 수 없음.
   * *아키텍처 결정*: 10초 실시간 Critical Path에는 CW Agent 기반의 L4 SG / L7 WAF 차단만 배치하고, IAM 세션 무효화는 비동기 사후 파이프라인(Future Work)으로 분리하여 파이프라인 정체성을 수호함.
2. **CloudWatch Logs 전달 지연**:
   * *문제*: CloudWatch 기본 전송 주기로 인한 SLA 초과 위험.
   * *대응*: EC2 인스턴스 CloudWatch Agent 수집 경로를 최적화하고, CloudWatch Subscription Filter를 Lambda에 직접 연결하여 로그 인입 즉시 비동기 스트림 처리.
3. **차단 API 중복 실행 및 레이스 컨디션**:
   * *문제*: 대량 공격 트래픽 유입 시 Lambda 다중 호출로 인한 중복 카운트 및 Boto3 API 경합.
   * *대응*: DynamoDB 시간 버킷(`epoch // 300`) 기반의 조건식 없는 원자적 연산(`ADD`, `list_append`)을 적용해 동시성 충돌을 원천 배제하고, 차단 엔진은 Boto3 호출 멱등성 및 WAF LockToken 낙관적 락 재시도로 일관성을 보장.
4. **정규식 백트래킹(ReDoS) 취약점**:
   * *문제*: 악의적인 페이로드 분석 시 정규식 엔진의 CPU 고갈 및 지연 발생.
   * *대응*: 중첩 수량자(`(a+)+`)를 원천 배제한 선형 시간 정규식만 채택하고 정적 분석 Linter로 사전 차단.

---

## 04. 검증 계획과 완료 기준

### 4.1 시나리오별 검증 매트릭스

| 공격 시나리오 | 발생 도구 및 페이로드 | 탐지 및 차단 조건 | 기대 차단 동작 | 최종 알림 검증 |
| :--- | :--- | :--- | :--- | :--- |
| **SSH Brute-Force** | Hydra (`-l root -P passlist.txt`) | 5분(300초) 내 인증 실패 $\ge 5$회 (심각도 HIGH) | EC2 SG `sg-quarantine` 격리 및 L7 WAF IPSet 동시 차단 (신규 세션 차단, 기존 연결은 세션 유지 후 만료) | Slack 채널에 공격자 IP, 침해사고 요약, L4/L7 복합 차단 집행 현황 전송 |
| **Port Scan / Dirb** | Nmap / Gobuster | Nginx 404/403 응답 빈도 임계치 초과 (심각도 HIGH) | AWS WAFv2 IPSet에 해당 IP 등록 (HTTP 403 차단) | Slack 채널에 공격자 IP, 공격 유형(rule_name), L7 WAF 차단 성공 전송 |

### 4.2 완료 기준
* [ ] **코드 품질 게이트**: `powershell .\scripts\check.ps1` 무경고 100% 통과 (Ruff, Pytest).
* [ ] **단위 테스트 가상화**: `moto` 기반 가상 AWS 환경에서 Boto3 차단 엔진 단위 테스트 100% 통과.
* [ ] **10초 SLA 관통 증빙**: 모의 공격 시작 시점부터 Slack 알림 수신 및 실제 인프라 차단 완료까지의 타임스탬프 델타가 10초 미만임을 로그로 증빙.
* [ ] **자동 대응 파이프라인 검증**: 차단 과정에서 사람의 수동 콘솔 조작이 개입되지 않음을 증빙.
* [ ] **오탐 복구 검증**: 격리된 SG 및 차단된 WAF IPSet에 대해 차단 해제 Boto3 스크립트 실행 시 정상 통신이 원복되어 복구됨을 단위/통합 테스트로 검증.
