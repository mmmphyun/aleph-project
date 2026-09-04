# CloudShield 인터페이스 데이터 계약: Events
# 소유자: 클라우드 A (전역 공통 계약 - 임의 수정 금지)
"""이벤트 데이터 계약 모델 및 압축/해제 유틸리티.

규격 1 (Syslog auth.log) 및 규격 2 (CloudWatch Logs Subscription Filter)를
Pydantic V2 모델로 정의하고 상호 변환 및 파싱을 지원함.
"""

from __future__ import annotations

import base64
import gzip
import json
import re

from pydantic import BaseModel, ConfigDict, Field


class SyslogAuthEvent(BaseModel):
    """리눅스 /var/log/auth.log 표준 SSH 로그인 실패 이벤트 모델 (규격 1).

    Why:
        네트워크 공격 시뮬레이션(Hydra)과 타깃 EC2 로깅 간의 일치 여부를 검증하고,
        보안 룰 엔진이 정규식으로 안전하게 필드를 추출할 수 있도록 정형화.

    포맷 예시:
        Sep 03 14:20:01 target-ec2 sshd[12341]: Failed password for
        invalid user admin from 198.51.100.50 port 49152 ssh2
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    timestamp_str: str = Field(..., description="Syslog 타임스탬프 (예: Sep 03 14:20:01)")
    hostname: str = Field(..., description="타깃 호스트명 (예: target-ec2)")
    process: str = Field(default="sshd", description="프로세스 이름")
    pid: int = Field(..., description="프로세스 PID")
    is_invalid_user: bool = Field(default=False, description="존재하지 않는 계정 여부")
    username: str = Field(..., description="접속 시도 사용자 계정 (예: admin, root)")
    source_ip: str = Field(..., description="접속 시도 출발지 IPv4")
    port: int = Field(..., description="접속 시도 출발지 포트 번호")
    protocol: str = Field(default="ssh2", description="SSH 프로토콜 버전")
    raw_message: str = Field(..., description="로그 원문 라인")

    @classmethod
    def parse_line(cls, line: str) -> SyslogAuthEvent | None:
        """단일 Syslog 원문 라인을 파싱하여 모델 인스턴스 생성.

        Edge-cases:
            - 'invalid user' 구문이 포함된 경우와 일반 사용자 실패 경우 모두 처리.
            - SSH 실패 로그가 아닌 경우 None 반환.
        """
        stripped = line.strip()
        if not stripped:
            return None

        # Syslog 표준 SSH 실패 로그 정규식 패턴
        pattern = (
            r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
            r"(?P<host>[^\s]+)\s+"
            r"(?P<proc>[^\[:]+)\[(?P<pid>\d+)\]:\s+"
            r"Failed password for (?P<invalid>invalid user )?(?P<user>[^\s]+)\s+"
            r"from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
            r"port (?P<port>\d+)\s+"
            r"(?P<proto>\S+)"
        )
        match = re.match(pattern, stripped)
        if not match:
            return None

        groups = match.groupdict()
        return cls(
            timestamp_str=groups["time"],
            hostname=groups["host"],
            process=groups["proc"],
            pid=int(groups["pid"]),
            is_invalid_user=bool(groups["invalid"]),
            username=groups["user"],
            source_ip=groups["ip"],
            port=int(groups["port"]),
            protocol=groups["proto"],
            raw_message=stripped,
        )


class CloudWatchLogEvent(BaseModel):
    """CloudWatch Logs 개별 로그 레코드 모델."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(..., description="CloudWatch 로그 이벤트 고유 ID")
    timestamp: int = Field(..., description="이벤트 발생 시각 Epoch Milliseconds")
    message: str = Field(..., description="실제 로그 원문 문자열")


class CloudWatchLogsPayload(BaseModel):
    """CloudWatch Logs Subscription Filter 수신 페이로드 (규격 2).

    Why:
        AWS CloudWatch Logs Subscription Filter가 분석 Lambda 함수로 이벤트를
        전달할 때 gzip 압축 및 Base64 인코딩된 상태로 주어지므로,
        이를 파싱/디코딩하고 역으로 테스트용 페이로드를 생성하는 표준 팩토리 제공.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    messageType: str = Field(..., description="메시지 유형 (DATA_MESSAGE 등)")
    owner: str = Field(..., description="AWS 계정 ID (12자리)")
    logGroup: str = Field(..., description="CloudWatch 로그 그룹 경로")
    logStream: str = Field(..., description="CloudWatch 로그 스트림 이름 (EC2 Instance ID 등)")
    subscriptionFilters: list[str] = Field(
        default_factory=list,
        description="매칭된 필터 이름 목록",
    )
    logEvents: list[CloudWatchLogEvent] = Field(
        default_factory=list,
        description="수집된 로그 이벤트 목록",
    )

    @classmethod
    def from_awslogs_data(cls, base64_gzip_data: str) -> CloudWatchLogsPayload:
        """Base64 디코딩 및 Gzip 압축을 해제하여 Pydantic 모델로 변환.

        Side-effects / Edge-cases:
            비정상 데이터 입력 시 ValueError 발생.
        """
        try:
            compressed = base64.b64decode(base64_gzip_data)
            decompressed = gzip.decompress(compressed)
            payload_dict = json.loads(decompressed.decode("utf-8"))
            return cls.model_validate(payload_dict)
        except Exception as exc:
            raise ValueError(f"CloudWatch Logs 데이터 디코딩/역직렬화 실패: {exc}") from exc

    def to_awslogs_data(self) -> str:
        """현재 인스턴스를 JSON 직렬화 후 Gzip 압축 및 Base64 인코딩 문자열로 반환.

        Why:
            로컬 단위 테스트 및 E2E 테스트베드에서 실제 AWS Lambda 수신 페이로드를
            모의(Mocking) 생성하기 위함.
        """
        json_bytes = self.model_dump_json().encode("utf-8")
        compressed = gzip.compress(json_bytes)
        return base64.b64encode(compressed).decode("utf-8")
