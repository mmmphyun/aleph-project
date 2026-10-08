# AWS WAFv2 WebACL 및 IPSet 모듈 정책·검증 명세

- Notion Task: https://notion.so/3e904d37c22581e7a754cd950242c777
- GitHub Issue: https://github.com/mmmphyun/aleph-project/issues/152
- 구현 범위: `infra/terraform/modules/waf/`
- 검토자: 클라우드 B `@wkdtlgns99-cell`

## 1. 차단 정책과 기존 계약

이 모듈은 기존 탐지·매퍼가 생성한 `BLOCK_WAF` 사고 보고를 플랫폼 차단 엔진이
집행할 수 있도록 WAF 리소스를 제공한다. 탐지 임계치, `IncidentReport`, Lambda
오케스트레이터 및 DynamoDB 윈도우는 기존 구현을 재사용한다.

| 항목 | 정의 | 이유 및 제약 |
| --- | --- | --- |
| IPSet 이름 | `CloudShield-Block-IPSet` | 기존 `DEFAULT_WAF_IPSET_NAME`과 일치 |
| 범위 | `REGIONAL` | 기존 `DEFAULT_WAF_SCOPE`과 일치, 동일 리전의 대상에 연결 |
| 주소 버전 | `IPV4` | 기존 차단 엔진의 단일 호스트 `/32` 계약 유지 |
| 초기 주소 | 빈 목록 | 배포만으로 정상 IP를 차단하지 않음 |
| WebACL 이름 | `CloudShield-WebACL` | 동일 계정·리전의 단일 CloudShield 스택 전제 |
| 기본 동작 | `Allow` | 탐지로 확정된 출발지만 차단 |
| 규칙 | `CloudShield-Block-IP`, Priority `0`, `Block` | 생성된 IPSet ARN 직접 참조 |
| IP 판정 | WAF가 직접 관측한 출발지 IP | 임의 `X-Forwarded-For` 값을 신뢰하지 않음 |
| 설계 WCU | `1` | 전달 헤더를 사용하지 않는 IPSet 문장 1개 |
| 관측성 | WebACL·규칙 CloudWatch 메트릭 활성화 | 차단 요청 집계 지원 |
| 요청 샘플 | 비활성화 | 민감 헤더·쿼리의 별도 샘플 저장 방지 |

직접 출발지 IP를 비교하는 IPSet 문장의 WCU는 1이다. 전달 헤더의 `ANY` 위치 검사처럼
정책을 확장하면 용량 계산을 다시 해야 한다.
[AWS IPSet match WCU 설명](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statements-match.html)

`expected_rule_wcu`는 설계값이고 `web_acl_capacity`는 AWS가 생성 후 반환하는 실제
capacity다. mock 테스트의 capacity는 고정한 테스트 데이터이며 AWS 실측값이 아니다.

## 2. Terraform과 런타임의 상태 소유권

Terraform은 IPSet의 이름·범위·주소 버전·태그와 WebACL 정책을 관리한다.
생성 이후 `addresses`는 기존 Lambda 차단 엔진이 `GetIPSet`과 `LockToken` 기반
`UpdateIPSet`으로 관리한다. `lifecycle.ignore_changes = [addresses]`는 이후 Terraform
재적용에서 런타임 차단 주소가 빈 초기 목록으로 되돌아가는 것을 막는다.
[Terraform ignore_changes 명세](https://developer.hashicorp.com/terraform/language/meta-arguments/lifecycle)

이 설정은 리소스 삭제·교체를 방지하지 않는다. 리소스 교체나 기존 IPSet의 관리 편입은
플랫폼 운영자가 현재 차단 목록과 state를 확인한 뒤 수행해야 한다. Terraform 변수로
차단 주소를 주입하거나 기존 차단을 해제하는 인터페이스는 제공하지 않는다.
차단 해제는 운영 확인 후 최신 LockToken으로 해당 `/32`만 제거하는 플랫폼 절차를 따른다.

차단 목록의 자동 만료·분할·포화 대응은 이 모듈에 새로 구현하지 않는다. 기존 엔진이
영속 AWS IPSet을 사용하므로 Lambda 메모리에 공유 상태를 보관하지 않으며,
IPSet 한도 초과·잠금 충돌·API 실패의 처리는 기존 플랫폼 엔진과 관측 경계를 따른다.
기존 엔진은 오류를 로깅하고 `False`로 반환한다. 이 모듈은 그 동작을 `raise`로
변경하지 않으며 플랫폼의 재시도·DLQ 연결이 완료됐다고 가정하지 않는다.

## 3. 플랫폼 결합 인터페이스와 배포 전 확인

클라우드 A가 기존 Terraform 루트에서 다음 인터페이스를 결합한다.
아래는 연결 예시이며 이 PR에서는 루트 파일을 변경하지 않는다.

```hcl
module "waf" {
  source      = "./modules/waf"
  environment = var.environment
}

# 기존 module "lambda" 블록의 입력으로 연결
# waf_ipset_arn = module.waf.ipset_arn

# 대상 ALB가 준비된 뒤 플랫폼에서 연결
# resource "aws_wafv2_web_acl_association" "target" {
#   resource_arn = <대상 ALB ARN>
#   web_acl_arn  = module.waf.web_acl_arn
# }
```

모듈 출력은 `ipset_arn`, `ipset_id`, `ipset_name`, `scope`, `web_acl_arn`,
`web_acl_id`, `expected_rule_wcu`, `web_acl_capacity`다. 루트의 예시 IPSet ARN을
실제 `ipset_arn`으로 교체해야 Lambda IAM 대상과 생성 리소스가 일치한다.
고정 리소스 이름으로 기존 런타임을 유지하므로 같은 계정·리전에 여러 환경을 동시에
만들 때는 플랫폼의 이름 선택 인터페이스도 함께 설계해야 한다.

EC2에 WebACL을 직접 붙일 수 없으므로 실제 웹 트래픽을 검사하는 ALB 등 지원 리소스와
연결해야 한다. 해당 리소스 연결과 직접 EC2 접근에 의한 우회 방지는 플랫폼·네트워크
배포 설계에서 확인한다.
[AWS WebACL 연결 리소스 명세](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-associating-aws-resource.html)

WAF는 SSH 포트 22 트래픽을 차단하지 않는다. SSH 대응의 실제 네트워크 격리는 기존
L4 엔진의 책임이다. 전체 WAF 로그 저장소·로깅 리소스도 플랫폼에서 별도로 결합해야 하며,
CloudWatch 메트릭을 활성화한 것만으로 원문 WAF 로깅이 구성되지는 않는다.

AWS WAF 변경은 수 초에서 수 분 동안 전파될 수 있다. API 성공 시각과 실제 HTTP 403
관측 시각을 따로 기록하고, 10초 목표는 실환경 관통 시험에서 측정해야 한다.
[AWS 변경 전파와 일시적 불일치](https://docs.aws.amazon.com/us_en/waf/latest/developerguide/waf-referenced-set-managing.html)

## 4. 로컬 검증 방법 및 범위

Terraform 모듈 자체는 1.6 이상을 지원한다. mock provider 테스트는 1.7 이상이 필요하다.
[HashiCorp mock provider 명세](https://developer.hashicorp.com/terraform/language/tests/mocking)

```powershell
terraform -chdir=infra/terraform/modules/waf init -backend=false -input=false
terraform -chdir=infra/terraform/modules/waf fmt -check -recursive
terraform -chdir=infra/terraform/modules/waf validate
terraform -chdir=infra/terraform/modules/waf test
trivy config --exit-code 1 infra/terraform/modules/waf
powershell .\scripts\check.ps1
```

실행 환경은 Terraform 1.9.8, AWS provider 5.100.0, Trivy 0.75.0이다.
모듈별 provider lock 파일을 포함해 같은 선택으로 검증을 재현한다.

| 검증 | 내용 | 결과 |
| --- | --- | --- |
| Terraform validate | 실제 AWS provider 스키마 검사 | 통과 |
| Terraform mock 테스트 5개 | 빈 IPSet, 이름·범위·IPv4, Block·Allow, ARN 연결, 직접 IP 비교, 메트릭, 태그, 잘못된 환경값 | 통과 |
| pytest IaC 테스트 2개 | mock 정책 검증 실행 및 기존 `/32` 두 개의 재계획 보존 | 통과 |
| Trivy config | 모듈의 전체 severity 설정 오류 검사 | 발견 사항 0건 |

pytest 검증은 보안 소유 경로인 `tests/unit/test_incident_mapper.py`에서 실행한다.
Terraform 설치와 모듈 init이 없는 Python 전용 환경에서는 IaC 테스트 2개가 명시적으로
skip된다. WAF 변경의 검증자는 Terraform 설치 및 모듈 init 후 전체 게이트를 실행하여
이 두 테스트가 실제로 통과했는지 확인해야 한다.

재계획 테스트는 임시 로컬 state에 기존 `/32` 주소 두 개를 두고, 실제 provider로
`plan -refresh=false`를 수행해 태그 업데이트 이후에도 주소가 유지되는지 검사한다.
검증 provider는 테스트 자격증명을 사용하고 계정·메타데이터 조회를 비활성화한다.
mock 테스트의 apply도 실제 AWS를 호출하지 않는다. 실제 HTTP 차단, 전파 시간,
권한 구성 및 전체 10초 관통 성능은 이 검증으로 증명하지 않는다.
