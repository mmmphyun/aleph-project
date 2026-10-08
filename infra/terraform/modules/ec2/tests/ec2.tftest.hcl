mock_provider "aws" {
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:ap-northeast-2:123456789012:log-group:/cloudshield/target/mock" }
  }
  mock_data "aws_region" {
    defaults = { name = "ap-northeast-2" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws", dns_suffix = "amazonaws.com" }
  }
}

variables {
  ami_id              = "ami-0123456789abcdef0"
  subnet_id           = "subnet-0123456789abcdef0"
  security_group_ids  = ["sg-0123456789abcdef0"]
  lambda_function_arn = "arn:aws:lambda:ap-northeast-2:123456789012:function:CloudShield-Threat-Orchestrator"
}

run "target_defaults" {
  command = apply
  assert {
    condition     = aws_instance.target.metadata_options[0].http_tokens == "required" && aws_instance.target.root_block_device[0].encrypted
    error_message = "IMDSv2와 디스크 암호화가 필수입니다."
  }
  assert {
    condition     = !aws_instance.target.associate_public_ip_address && aws_instance.target.user_data_replace_on_change
    error_message = "기본 사설 IP 및 설정 변경 시 교체가 필요합니다."
  }
  assert {
    condition     = length(aws_cloudwatch_log_subscription_filter.target) == 2 && length(aws_lambda_permission.logs) == 2 && alltrue([for group in aws_cloudwatch_log_group.target : group.retention_in_days == 7])
    error_message = "두 로그 경로의 구독/권한/유한 보존 기간이 필요합니다."
  }
  assert {
    condition     = toset(jsondecode(aws_iam_role_policy.logs.policy).Statement[0].Action) == toset(["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"])
    error_message = "수집 역할은 로그 쓰기 최소 권한만 허용합니다."
  }
  assert {
    condition     = length(local.user_data) <= 16384 && strcontains(local.user_data, "-a fetch-config -m ec2 -s")
    error_message = "user-data 크기 제한과 Agent 시작 명령을 확인하세요."
  }
}

run "reject_cross_region" {
  command = plan
  variables {
    lambda_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:other"
  }
  expect_failures = [aws_instance.target]
}

run "reject_cross_account" {
  command = plan
  variables {
    lambda_function_arn = "arn:aws:lambda:ap-northeast-2:999999999999:function:other"
  }
  expect_failures = [aws_instance.target]
}

run "reject_missing_security_groups" {
  command = plan
  variables {
    security_group_ids = []
  }
  expect_failures = [var.security_group_ids]
}

run "reject_unbounded_retention" {
  command = plan
  variables {
    log_retention_days = 0
  }
  expect_failures = [var.log_retention_days]
}

run "reject_arm_instance" {
  command = plan
  variables {
    instance_type = "t4g.micro"
  }
  expect_failures = [var.instance_type]
}
