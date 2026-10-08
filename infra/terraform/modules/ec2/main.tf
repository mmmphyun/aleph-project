# 클라우드 B: 네트워크 자산을 입력받아 수집 타깃만 생성한다.
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  name = "cloudshield-${var.environment}-target"
  # 기존 수집 설정을 단일 원본으로 재사용해 로그 경로 불일치를 방지한다.
  agent_config = jsondecode(file("${path.module}/../../../../src/collector/amazon-cloudwatch-agent.json"))
  log_groups   = toset([for entry in local.agent_config.logs.logs_collected.files.collect_list : entry.log_group_name])
  filters = {
    "/cloudshield/target/auth-log"         = "\"Failed password\""
    "/cloudshield/target/nginx-access-log" = "[ip, ident, user, timestamp, request, status_code = 401 || status_code = 403 || status_code = 404, ...]"
  }
  # gzip 압축으로 EC2 user-data 16KiB 제한 안에 기존 초기화 자산을 포함한다.
  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    init_script  = base64gzip(file("${path.module}/../../../../init_target_server.sh"))
    nginx_config = base64gzip(file("${path.module}/../../../../nginx.conf"))
    agent_config = base64gzip(jsonencode(local.agent_config))
  })
}

resource "aws_cloudwatch_log_group" "target" {
  for_each          = local.log_groups
  name              = each.value
  retention_in_days = var.log_retention_days
  tags              = { Environment = var.environment }
}

resource "aws_iam_role" "target" {
  name = local.name
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "ec2.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy" "logs" {
  name = "target-log-writer"
  role = aws_iam_role.target.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
      Resource = [for group in aws_cloudwatch_log_group.target : "${group.arn}:*"]
    }]
  })
}

resource "aws_iam_instance_profile" "target" {
  name = local.name
  role = aws_iam_role.target.name
}

resource "aws_lambda_permission" "logs" {
  for_each       = local.filters
  statement_id   = each.key == "/cloudshield/target/auth-log" ? "CloudShieldAuth-${var.environment}" : "CloudShieldNginx-${var.environment}"
  action         = "lambda:InvokeFunction"
  function_name  = var.lambda_function_arn
  principal      = "logs.${data.aws_region.current.name}.${data.aws_partition.current.dns_suffix}"
  source_arn     = "${aws_cloudwatch_log_group.target[each.key].arn}:*"
  source_account = data.aws_caller_identity.current.account_id
}

resource "aws_cloudwatch_log_subscription_filter" "target" {
  for_each        = local.filters
  name            = each.key == "/cloudshield/target/auth-log" ? "CloudShield-SSH-FailedPassword-Filter" : "CloudShield-Nginx-Access-Filter"
  log_group_name  = aws_cloudwatch_log_group.target[each.key].name
  filter_pattern  = each.value
  destination_arn = var.lambda_function_arn
  depends_on      = [aws_lambda_permission.logs]
}

resource "aws_instance" "target" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = var.security_group_ids
  associate_public_ip_address = var.associate_public_ip_address
  iam_instance_profile        = aws_iam_instance_profile.target.name
  user_data                   = local.user_data
  user_data_replace_on_change = true
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 16
  }
  tags       = { Name = local.name, Environment = var.environment }
  depends_on = [aws_iam_role_policy.logs, aws_cloudwatch_log_subscription_filter.target]
  lifecycle {
    precondition {
      condition     = length(local.user_data) <= 16384
      error_message = "user-data가 16KiB를 초과합니다."
    }
    precondition {
      condition     = split(":", var.lambda_function_arn)[3] == data.aws_region.current.name && split(":", var.lambda_function_arn)[4] == data.aws_caller_identity.current.account_id
      error_message = "Lambda는 타깃과 동일 리전/계정이어야 합니다."
    }
  }
}
