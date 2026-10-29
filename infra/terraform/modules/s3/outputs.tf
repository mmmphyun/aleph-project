# CloudShield S3 모듈 출력값 정의
# 소유자: 클라우드 A (플랫폼 전담)

output "bucket_id" {
  description = "침해 보고서 S3 버킷 ID"
  value       = aws_s3_bucket.reports.id
}

output "bucket_name" {
  description = "침해 보고서 S3 버킷 이름"
  value       = aws_s3_bucket.reports.bucket
}

output "bucket_arn" {
  description = "침해 보고서 S3 버킷 ARN"
  value       = aws_s3_bucket.reports.arn
}
