# CloudShield S3 침해 보고서 모듈: 버킷 생성, SSE-S3 암호화, 수명주기 및 사내 IP 격리 정책
# 소유자: 클라우드 A (플랫폼 전담)
#
# Why:
#   상사 보고용 HTML 문서를 안전하게 영속화하고, 7일 후 자동 폐기하여 스토리지 누수 및 컴플라이언스
#   위험을 원천 차단함. 지정된 사내 인가 공인 IP 외에는 Presigned URL 열람 시에도
#   S3 버킷 정책(NotIpAddress Deny)을 통해 403 Forbidden 차단을 강제함.

resource "aws_s3_bucket" "reports" {
  bucket = "${var.bucket_name_prefix}-${var.environment}"

  tags = merge(
    var.tags,
    {
      Name        = "${var.bucket_name_prefix}-${var.environment}"
      Environment = var.environment
      Purpose     = "SecOpsExecutiveReports"
    }
  )
}

# 1. 서버 측 기본 암호화 (SSE-S3) 강제
resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# 2. 퍼블릭 액세스 차단 (CIS AWS Benchmark 준수)
resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 3. 7일 만료 수명주기(Lifecycle) 규칙 설정
resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "expire-reports-after-7-days"
    status = "Enabled"

    filter {}

    expiration {
      days = 7
    }
  }
}

# 4. 사내 인가 공인 IP 외 GetObject 열람 전면 차단 (Deny) 버킷 정책
data "aws_iam_policy_document" "reports_ip_restriction" {
  statement {
    sid    = "DenyExternalIpReadAccess"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = [
      "s3:GetObject"
    ]

    resources = [
      "${aws_s3_bucket.reports.arn}/*"
    ]

    condition {
      test     = "NotIpAddress"
      variable = "aws:SourceIp"
      values   = var.allowed_report_cidrs
    }
  }
}

resource "aws_s3_bucket_policy" "reports" {
  bucket = aws_s3_bucket.reports.id
  policy = data.aws_iam_policy_document.reports_ip_restriction.json

  depends_on = [
    aws_s3_bucket_public_access_block.reports
  ]
}
