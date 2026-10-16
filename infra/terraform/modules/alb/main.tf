# CloudShield ALB 모듈: L7 데이터 평면 구축 및 Target Group 포워딩
# 소유자: 클라우드 A (플랫폼 전담)
#
# Why:
#   Web L7 WAFv2 WebACL을 연결할 Application Load Balancer를 제공하고,
#   인터넷 인바운드 HTTP(80) 트래픽을 타깃 EC2 인스턴스의 Nginx 컨테이너/데몬으로 전달함.
#
# Constraints:
#   - ALB는 최소 2개의 가용영역(AZ)에 속한 서브넷에 배치되어야 함.
#   - 타깃 헬스체크는 Nginx 기본 인덱스 경로("/") 200 OK를 기준으로 판정함.

locals {
  alb_name = "CloudShield-ALB-${var.environment}"
  tg_name  = "CloudShield-TG-${var.environment}"
  resource_tags = merge(var.tags, {
    Project     = "CloudShield"
    Environment = var.environment
    ManagedBy   = "Terraform"
  })
}

# ==============================================================================
# 1. ALB 전용 보안 그룹 (인터넷 80 인바운드 허용)
# ==============================================================================
resource "aws_security_group" "alb" {
  name        = "CloudShield-ALB-SG-${var.environment}"
  description = "Security group for CloudShield Application Load Balancer"
  vpc_id      = var.vpc_id
  tags        = merge(local.resource_tags, { Name = "CloudShield-ALB-SG-${var.environment}" })

  ingress {
    description = "HTTP ingress from approved test origins"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.ingress_cidrs
  }

  egress {
    description = "Allow all outbound traffic to VPC targets"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ==============================================================================
# 2. Application Load Balancer (인터넷 경계)
# ==============================================================================
resource "aws_lb" "this" {
  name               = local.alb_name
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.subnet_ids

  enable_deletion_protection = false

  tags = merge(local.resource_tags, { Name = local.alb_name })
}

# ==============================================================================
# 3. Target Group (HTTP 80, 인스턴스 타깃)
# ==============================================================================
resource "aws_lb_target_group" "this" {
  name        = local.tg_name
  port        = var.target_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    path                = "/"
    protocol            = "HTTP"
    port                = "traffic-port"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = merge(local.resource_tags, { Name = local.tg_name })
}

# ==============================================================================
# 4. Target Group Attachment (타깃 EC2 등록)
# ==============================================================================
resource "aws_lb_target_group_attachment" "this" {
  target_group_arn = aws_lb_target_group.this.arn
  target_id        = var.target_instance_id
  port             = var.target_port
}

# ==============================================================================
# 5. HTTP Listener (포트 80 수신 및 Target Group 포워딩)
# ==============================================================================
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }

  tags = local.resource_tags
}
