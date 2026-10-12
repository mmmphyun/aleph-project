# P3-1B baseline SG 외부 Egress 정책

- 기준일: 2026-10-12 KST
- Notion Task: https://notion.so/3f704d37c225803ba79ee04e420fedaf
- Issue: https://github.com/mmmphyun/aleph-project/issues/167
- 기준 main: `faec5a71c4a86db5a494c8f7784079dc144c4bfc`
- 브랜치: `feat/network-baseline-egress-policy`
- `.agent-role=network`, 사용자 P3-1B 사전 RFC 승인 “진행해” 확인
- 수정 범위: `infra/terraform/modules/quarantine_sg/**`, `tests/unit/test_network.py`, `docs/roles/network/**`

## 정책과 P3-2 인터페이스

baseline SG는 정상 통신의 명시적 입력을 소비하며 격리 SG는 양방향 빈 규칙이다.
P3-1A의 정규 IPv4 egress `/0` 입력 허용 위에 P3-1B의 서비스 정책을 별도 산출물로 제공한다.
`infra/terraform/modules/quarantine_sg/policies/external_bootstrap/main.tf`는 AWS 리소스 없이
`egress` map만 출력한다. SG `main.tf`, `variables.tf`, `outputs.tf`는 변경하지 않는다.

| 정책 키 | CIDR | 프로토콜 | from_port | to_port | 서비스 용도 |
| --- | --- | --- | --- | --- | --- |
| `package_http` | `0.0.0.0/0` | tcp | 80 | 80 | HTTP 패키지 저장소 |
| `agent_logs_https` | `0.0.0.0/0` | tcp | 443 | 443 | HTTPS Agent 다운로드·CloudWatch Logs |

정확한 HCL 정책과 루트 결합 예시는 [모듈 README](../../../infra/terraform/modules/quarantine_sg/README.md)에 있다.
정책 원본의 규칙 map은 아래와 같다. 테스트 입력은 이 설명용 복사본을 사용하지 않는다.

```hcl
egress = {
  package_http = {
    cidr        = "0.0.0.0/0"
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    description = "HTTP package repositories"
  }
  agent_logs_https = {
    cidr        = "0.0.0.0/0"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    description = "HTTPS agent download and CloudWatch Logs"
  }
}
```

P3-2는 별도 `baseline_external_policy` 모듈을 선언하고
`traffic = { ingress = var.quarantine_traffic.ingress, egress = module.baseline_external_policy.egress }`로 연결한다.
SG 자체 출력은 입력에 사용하지 않아 순환이 없다. 정책 선택·입력 전에는 자동 개방이 없으며
일반 빈 `traffic.egress` 입력은 계속 빈 규칙이다. 일반 TCP/UDP·포트 인터페이스는 유지한다.
정책과 기존 map의 자동 병합을 구현하지 않아 키 덮어쓰기가 없다. 별도 병합은 키 충돌 거부와
최종 map의 중복·60개 상한 검증이 필요하다.

현재 루트 `quarantine_traffic.egress.all-vpc`는 `10.42.0.0/16` TCP 1~65535이다.
루트 소유자는 P3-2에서 이 넓은 규칙을 교체·정리하고 정책을 활성화해야 한다.
루트 활성화, 프로비저닝과 실제 통신 검증은 클라우드 A/B 및 관련 담당자의 후속 범위다.
`0.0.0.0/0`은 모든 IPv4 목적지를 허용하므로 목적지까지 최소화한 정책으로 표현하지 않는다.
80~443 범위, 전체 프로토콜, 추가 DNS/IPv6/ICMP/SG 참조 규칙은 정의하지 않았다.

## 서비스 의존성과 제한

`init_target_server.sh`의 `apt-get update/install`은 배포 AMI의 APT 저장소 구성을 사용한다.
HTTP 저장소는 TCP 80, HTTPS 저장소는 TCP 443이 필요하며 실제 URL은 코드에서 정하지 않는다.
`infra/terraform/modules/ec2/user_data.sh.tftpl`의 HTTPS S3 Agent 다운로드 URL은 TCP 443 근거다.
마지막 localhost `/health` 호출은 외부 TCP 80과 무관하다. CloudWatch Agent는 기존
`src/collector/amazon-cloudwatch-agent.json`의 auth.log·nginx/access.log 수집을 재사용한다.
클라우드 B 배포 문서 및 EC2 수집 IAM 정책을 읽기 전용 확인했다.

VPC는 `enable_dns_support/hostnames=true`, public subnet 자동 공인 IP는 false이며
private route table은 NAT 경로 없이 비어 있다. SG 2개 규칙만으로 인터넷 성공을 주장하지 않는다.
실제 DNS/AMI 저장소, public IP+IGW 또는 NAT 경로, NACL/OS 방화벽, TLS, 리전·로그 그룹 및
instance profile 권한을 별도 확인한다. EC2 IAM의 로그 스트림 생성·전송·조회 권한이 필요하다.
[AWS SG 문서](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)에 따라
AmazonProvidedDNS는 SG 필터 대상이 아니다. 사용자 DNS의 추가 송신 필요성은 협업으로 결정한다.
[Logs Interface Endpoint](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch-logs-and-interface-VPC.html)는
Logs의 사설 경로를 제공하지만 APT 저장소·S3 다운로드까지 대체하지 않는다.

## 검증과 완료 범위

신규 HCL 테스트는 정책 모듈을 먼저 평가하고 `run.external_policy.egress`를 실제 SG 입력으로
소비한다. 정확히 두 IPv4 TCP 단일 포트, IPv6/prefix-list/SG 참조/self 부재, 승인된 ingress
유지와 빈 ingress 유지 및 격리 SG 빈 양방향 규칙을 검증한다. 기존 SG 39개·VPC 14개를 보존하며
SG 42개를 pytest 기대 개수로 지정한다. ingress `/0`, 비정규 prefix/CIDR, 포트·프로토콜·설명,
중복·60개 상한 검증은 유지한다. 격리 엔진의 빈 규칙과 SG ID/ARN/이름 계약을 변경하지 않는다.

정적 Terraform 정책이므로 신규 런타임 상태·DB 항목·일관성·지연/역순 이벤트 처리는 없다.
정책은 2개 규칙이고 기존 방향별 60개 상한을 유지하며 입력 검증/mock 오류를 그대로 전파한다.
검증 CLI Terraform 1.16.5, AWS provider 5.100.0, 기존 버전 제약과 Trivy 전체 심각도 기준을 재사용한다.
검사별 실제 결과는 다음과 같다. 원본 캐시·보안 정책·ACL을 변경하지 않았다.

| 검사 | 종료 상태와 실제 결과 |
| --- | --- |
| 원본 `powershell .\scripts\check.ps1` | exit 1; R&R 통과 후 기존 `.pytest_cache` 열거 권한 오류 |
| 동일 SHA-256 Windows 체크아웃 첫 전체 게이트 | exit 1; 919 passed / 1 failed / 0 skipped / 2 warnings; 기존 Lambda 패키지 subprocess의 cp949/UTF-8 디코딩 불일치 |
| 동일 Windows 체크아웃 `PYTHONUTF8=1` 전체 게이트 | exit 0; R&R·경로·Ruff lint/format·pytest 모두 통과; **920 passed / 0 failed / 0 skipped / 1 warning**, 175.61초 |
| Windows VPC/SG/WAF backend=false init | 각 exit 0; 기존 로컬 provider 재사용; WAF tracked lock은 readonly |
| Windows SG fmt/validate/AWS mock | 각각 exit 0; **42 passed / 0 failed / 0 errored / 0 skipped** |
| Linux VPC fmt/validate/AWS mock | 각각 exit 0; **14 passed / 0 failed / 0 errored / 0 skipped** |
| Linux SG fmt/validate/AWS mock | 각각 exit 0; **42 passed / 0 failed / 0 errored / 0 skipped** |
| Linux pytest Terraform 연계 | exit 0; **2 passed / 0 failed / 0 skipped**, 408 deselected, 16.88초 |
| Linux WAF readonly init / validate | exit 0 / exit 1; 추적 lock에 Linux 설치 provider checksum이 없어 validate 실패; lock 수정 없음 |
| Linux 동일 소스 전체 `powershell ./scripts/check.ps1` | exit 1; **918 passed / 2 failed / 0 skipped / 1 warning**, 84.86초; WAF 정책/mock 및 런타임 차단 주소 보존 검증이 checksum 문제로 실패 |
| Trivy 0.75.0 SG 전체 심각도, `--exit-code 1` | exit 0; SG 71 successes / 0 failures 및 순수 정책 모듈 51 successes / 0 failures; 독립 SG 입력 미지정 경고 기록 |
| Trivy 실제 정책 출력 결합, 전체 심각도 | exit 0; 71 successes / 0 failures; 상대경로 동일 소스 결합으로 모듈 해석·변수 경고 없음 |

Windows: Python 3.12.14 / pytest 8.4.2 / Ruff 0.16.4 / uv 0.12.10 /
moto 5.2.3 / boto3 1.43.88 / Terraform 1.16.5 windows_amd64 / AWS provider 5.100.0.
Linux: Docker `mcr.microsoft.com/powershell:7.5-ubuntu-24.04`, image `042240d57ec9` /
Python 3.12.3 / pytest 8.4.2 / Ruff 0.16.4 / uv 0.13.0 / Terraform 1.16.5 linux_amd64 /
AWS provider 5.100.0 / PowerShell 7.5. 고정 의존성은 `uv sync --all-extras --frozen`으로 준비했다.
컨테이너에서 설치한 도구 패키지는 검증용이며 타깃 부트스트랩은 실행하지 않았다.

Windows 임시 체크아웃은 `C:/Users/User/AppData/Local/Temp/cloudshield-p3-1b-20261012`이며
추적 파일·신규 산출물·역할 파일 **216개 SHA-256**을 원본과 비교했다. Linux도 같은 manifest의
216개만 복사해 비교했다. Windows 실행 도중 생성된 비추적 VPC/SG lock을 Linux로 복사한
최초 init은 checksum 불일치로 실패했고, manifest 소스만 복사해 재검증했다. 추적 lock은 그대로다.
Trivy 최초 Windows 절대경로 결합도 exit 0이었지만 모듈 해석 오류가 있어 유효 성공으로 채택하지
않고 SHA-256 동일 상대경로 복사본에서 다시 평가했다. 실패를 skip으로 바꾸지 않았다.
게이트 첫 인코딩 실패는 환경의 `PYTHONUTF8=1`로 해결했으며 테스트·검사기·제약은 수정하지 않았다.
최종 1 warning은 기존 기본 소켓 차단 검증의 경고다.

증빙은 `C:/Users/User/AppData/Local/Temp/`에 보존한다.

- manifest: `cloudshield-p3-1b-sha256.json`, SHA-256 `edc22f8c33480bdbaa47a67813f8e2a08397204b3496ed26f4e20c591dc6669d`
- 원본/Windows 게이트: `cloudshield-p3-1b-original-check.log`, `cloudshield-p3-1b-full-check.log`, `cloudshield-p3-1b-full-check-utf8.log`
- Windows init/validate/mock: `cloudshield-p3-1b-windows-*.log`
- Linux: `cloudshield-p3-1b-linux-run.log`, `cloudshield-p3-1b-linux-evidence/`의 init/fmt/validate/mock/pytest/전체 게이트 로그
- Trivy: `cloudshield-p3-1b-trivy-module.json`, `cloudshield-p3-1b-trivy-policy.json` 및 동일 이름 `.log`
- 변경하지 않은 `scripts/check.ps1` SHA-256: `8b89383ac3366d4c4c95842e9ef24e9438ccfc21ea7a6c6d1efd51acad8c88fa`
- 변경하지 않은 WAF tracked lock SHA-256: `bb45cd135b8b96bf8af81c1a4b3f0a02e0bd441d33c10fb809628a87aaf6014c`

결과 기록 문서만 검사 후 갱신했으며 실행 소스·테스트·검사기는 변경하지 않았다.
임시 provider/state/plan/lock·자격증명은 커밋하지 않는다. 사용자 비추적 문서 3개를 보존한다.
원본 체크아웃의 캐시 권한 오류와 Linux readonly WAF lock 문제가 남아 Draft로 제출한다.
Windows 동일 소스 전수 통과와 별도로 해당 환경 문제 해결을 담당자에게 요청하며,
이번 작업에서 보안 설정·ACL·타 직무 lock을 변경하거나 예외 승인을 승계하지 않는다.

실제 AWS 조회/생성/변경/삭제, 실제 AWS plan/apply/destroy/import, 부트스트랩·Agent 다운로드·로그 전송,
SG 부착 및 10초 데모 실측을 수행하지 않는다. provider 설치나 mock 성공은 배포 성공이 아니다.

## 자동 동기화와 리뷰

`notion_sync.yml`은 Issue opened/reopened에서 진행 중, PR opened/reopened에서 검토 중,
PR merged에서 완료로 전이한다. Draft 예외가 없고 merged PR 본문의 모든 `#숫자`를 찾아
열린 Issue를 종료하므로 Refs는 완료 차단 수단이 아니다. PR 본문에는 P3-1B 전용 Issue만
완료 대상으로 연결하며 선행 PR은 숫자 해시 참조 없이 표시한다. 에이전트는 노션을 직접 변경하지 않는다.
필수 리뷰어 `gkacksdnjs22-stack`의 리뷰를 기다리며 이번 요청에서는 머지하지 않는다.

Issue 167 opened에 따른 [Notion Sync run](https://github.com/mmmphyun/aleph-project/actions/runs/38221668759)은
success이며 실행 로그에서 해당 카드 ID의 진행 중 전이 완료를 확인했다. PR 및 최신 CI 결과는
PR 본문에 확정한다. P3-1B 완료 범위는 정책·mock 검증이며 루트 적용/AWS 배포/10초 데모를 포함하지 않는다.
