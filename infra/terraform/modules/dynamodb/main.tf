# CloudShield DynamoDB Terraform 모듈: 배치 간 인증 실패 누적 슬라이딩 윈도우 테이블
# 소유자: 클라우드 A (플랫폼 전담)
#
# Why:
#   CloudWatch Logs Subscription Filter를 통해 비동기 인입되는 분할 배치를 무상태(Stateless)
#   Lambda 메모리만으로는 집계할 수 없으므로, DynamoDB 원자적 조건식 없는 쓰기(Atomic ADD)와
#   5분 TTL 자동 만료를 활용하여 다중 Lambda 인스턴스 간 인증 실패 횟수를 정확히 누적함.
#
# Constraints:
#   - 단일 파티션 키 target_key(S) 구조 (BF#{ip}#{user}#{bucket_id} 또는 SPRAY#{ip}#{bucket_id}).
#   - TTL 속성명은 expire_at(N) 필수 활성화 (Unix Epoch 초 단위 10분 TTL).
#   - 제로 트러스트 및 Trivy 정적 보안 기준 충족: 암호화(SSE-KMS/DEFAULT) 및 PITR 활성화.

resource "aws_dynamodb_table" "auth_window" {
  name         = var.table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "target_key"

  attribute {
    name = "target_key"
    type = "S"
  }

  ttl {
    attribute_name = "expire_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled = true
  }

  tags = merge(
    var.tags,
    {
      Name        = var.table_name
      Environment = var.environment
      Purpose     = "SlidingWindowAuthFailureCounter"
    }
  )
}
