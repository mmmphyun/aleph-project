# 클라우드 A 전용 모듈: Boto3 기반 다중 계층 원자적 차단 엔진(remediation.py)
# 소유자: 클라우드 A

from remediation.auth_window import AuthFailureWindow
from remediation.llm_worker import llm_analysis_handler, send_deep_analysis_slack_alert
from remediation.orchestrator import emit_threat_resolved_event, threat_orchestrator_handler
from remediation.remediation import (
    RemediationResult,
    apply_remediation,
    block_ip_wafv2,
    quarantine_ec2_instance,
)
from remediation.web_window import WebAttackWindow

__all__ = [
    "AuthFailureWindow",
    "RemediationResult",
    "WebAttackWindow",
    "apply_remediation",
    "block_ip_wafv2",
    "emit_threat_resolved_event",
    "llm_analysis_handler",
    "quarantine_ec2_instance",
    "send_deep_analysis_slack_alert",
    "threat_orchestrator_handler",
]
