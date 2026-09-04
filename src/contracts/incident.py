# CloudShield 인터페이스 데이터 계약: IncidentReport
# 소유자: 클라우드 A (전역 공통 계약 - 임의 수정 금지)
"""침해사고 분석 보고서 데이터 계약 모델.

보안 분석 엔진(rules.py / LLM)이 생성하고,
클라우드 A(차단 엔진) 및 클라우드 B(Slack 알림)가 소비하는 공통 인터페이스.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IncidentReport(BaseModel):
    """표준 침해사고 분석 보고서 모델 (Pydantic V2).

    Why:
        4개 직무(네트워크, 보안, 클라우드 A, 클라우드 B) 간 런타임 결합도를 낮추고
        AWS Boto3 조치 및 Slack 카드 렌더링 시 발생할 수 있는 데이터 누락/타입 불일치 방지.

    Constraints:
        - source_ip: 올바른 IPv4 형식이어야 함 (0~255 각 옥텟 검증).
        - target_identifier: AWS EC2 인스턴스 ID 형식 (^i-[0-9a-f]{8,17}$) 준수.
        - action_required: 사전 정의된 격리/차단 액션 유니온에 속해야 함.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_id: str = Field(
        ...,
        description="사건 고유 식별자 (예: INC-20260904-001)",
        examples=["INC-20260904-001"],
    )
    attack_type: str = Field(
        ...,
        description="공격 유형 (예: SSH Brute Force, Web L7 Spraying)",
        examples=["SSH Brute Force"],
    )
    mitre_id: str = Field(
        ...,
        description="MITRE ATT&CK 기법 ID (예: T1110.001, T1046)",
        examples=["T1110.001"],
    )
    risk_level: Literal["HIGH", "MEDIUM", "LOW"] = Field(
        ...,
        description="사고 위험도 평가 등급",
    )
    source_ip: str = Field(
        ...,
        description="공격자 출발지 공인/사설 IPv4 주소",
        examples=["198.51.100.50"],
    )
    target_identifier: str = Field(
        ...,
        description="침해 타깃 식별자 (EC2 Instance ID)",
        examples=["i-0abcd1234ef567890"],
    )
    target_accounts: tuple[str, ...] = Field(
        default_factory=tuple,
        description="공격 대상 시스템 계정 목록 (예: admin, root)",
    )
    summary_ko: str = Field(
        ...,
        description="침해 상황에 대한 한글 요약 (2~3문장 이내)",
    )
    action_required: Literal[
        "BLOCK_WAF",
        "QUARANTINE_EC2",
        "REVOKE_IAM_SESSION",
        "BLOCK_AND_QUARANTINE",
        "BLOCK_IP_ONLY",
        "ALERT_ONLY",
        "NONE",
    ] = Field(
        ...,
        description="인프라 대응 오케스트레이터 지시 액션",
    )
    recommendations: tuple[str, ...] = Field(
        default_factory=tuple,
        description="SecOps 관리자 권고 조치 항목 리스트",
    )

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, v: str) -> str:
        """IPv4 유효성 및 형식 검증.

        Why:
            정규식 중복 검사를 배제하고 파이썬 표준 라이브러리(stdlib) ipaddress를 활용하여
            0~255 옥텟 범위 및 IPv4 형식 무결성을 보장함.

        Constraints:
            단일 IPv4 주소 문자열만 허용하며 서브넷 마스크(/24 등) 및 포트 번호 포함 불가.

        Side-effects / Edge-cases:
            옥텟 범위를 벗어난 비정상 IP("999.999.999.999") 또는
            알파벳 문자열 입력 시 ValueError 발생.
        """
        try:
            ipaddress.IPv4Address(v)
        except ValueError as exc:
            raise ValueError(f"유효하지 않은 IPv4 주소: {v}") from exc
        return v

    @field_validator("target_identifier")
    @classmethod
    def validate_instance_id(cls, v: str) -> str:
        """AWS EC2 인스턴스 ID 포맷 검증.

        Side-effects / Edge-cases:
            'i-' 접두사 및 8자리 또는 17자리 16진수 문자열 규격 강제.
        """
        if not re.match(r"^i-[0-9a-f]{8,17}$", v):
            raise ValueError(f"유효하지 않은 EC2 인스턴스 ID 형식: {v}")
        return v
