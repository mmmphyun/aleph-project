# CloudShield 인터페이스 데이터 계약: Events
# 소유자: 클라우드 A (전역 공통 계약 - 임의 수정 금지)
"""이벤트 데이터 계약 모델 및 압축/해제 유틸리티.

규격 1 (Syslog auth.log), 규격 2 (CloudWatch Logs Subscription Filter),
규격 3 (Nginx access.log)을 Pydantic V2 모델로 정의하고 상호 변환 및 파싱을 지원함.
"""

from __future__ import annotations

import base64
import gzip
import json
import re
from urllib.parse import unquote

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
        # Why: 전통적 BSD Syslog 포맷(Sep 03 14:20:01) 및
        #      최신 Linux systemd/rsyslog ISO 8601 포맷 동시 지원
        # Constraints: IPv4 옥텟 형식 및 sshd 프로세스 실패 이벤트에 한함
        # Edge-cases: 타깃 EC2 OS 버전에 따른 타임스탬프 포맷 불일치로 인한
        #             이벤트 무음 누락(Silent Drop) 방지
        pattern = (
            r"^(?P<time>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[^\s]+))\s+"
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


class NginxAccessLogEvent(BaseModel):
    """Nginx access.log 웹 접근 로그 이벤트 모델 (규격 3).

    Why:
        타깃 EC2 Nginx 웹 서버의 access.log(cloudshield_combined 포맷)를 파싱하여
        L7 웹 공격(디렉토리 스캐닝, 관리자 페이지 무차별 대입 등)에 대한
        탐지 룰 엔진 및 차단(WAF IPSet) 오케스트레이터의 공통 표준 인터페이스를 제공함.

    Constraints:
        - 불변 모델(frozen=True, extra="forbid")로 정의하여 계약 변조 방지.
        - 필수 필드 8개: source_ip, timestamp_str, method, uri, status_code,
          response_time, user_agent, raw_message.
        - 파싱 시 표준 1차 URL unquote 처리를 적용하여 인코딩 우회 공격에 대응.

    Side-effects / Edge-cases:
        - URL 퍼센트 인코딩 디코딩 시 UTF-8 오류는 errors="replace"로 안전하게 대체 처리.
        - Nginx access.log 포맷이 아니거나 비정상 요청 라인인 경우 None 반환.

    포맷 예시 (cloudshield_combined):
        198.51.100.77 - - [28/Sep/2026:11:52:38 +0000] "GET /admin HTTP/1.1"
        401 150 "-" "curl/7.81.0" 0.002 "-"
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_ip: str = Field(..., description="접속 시도 출발지 IPv4")
    timestamp_str: str = Field(..., description="Nginx 타임스탬프 (예: 28/Sep/2026:11:52:38 +0000)")
    method: str = Field(..., description="HTTP 요청 메서드 (예: GET, POST)")
    uri: str = Field(..., description="요청 URI 경로 (1차 URL unquote 처리 완료)")
    status_code: int = Field(..., description="HTTP 응답 상태 코드 (예: 200, 401, 403, 404)")
    response_time: float = Field(default=0.0, description="요청 처리 소요 시간 (초)")
    user_agent: str = Field(..., description="클라이언트 User-Agent 헤더")
    raw_message: str = Field(..., description="로그 원문 라인")

    @classmethod
    def parse_line(cls, line: str) -> NginxAccessLogEvent | None:
        """단일 Nginx access.log 원문 라인을 파싱하여 모델 인스턴스 생성.

        Why:
            CloudWatch Logs에서 디코딩된 Nginx 접근 로그 문자열로부터
            L7 탐지 룰 및 WAF 오케스트레이터가 필요로 하는 핵심 필드를 안전하게 추출함.

        Constraints:
            - 표준 1차 URL unquote 처리(urllib.parse.unquote) 지원.
            - cloudshield_combined 및 표준 Nginx Combined 로그 포맷 동시 지원.

        Side-effects / Edge-cases:
            - Nginx 로그 규격과 일치하지 않거나 빈 문자열인 경우 None 반환.
            - 비정상/불완전 퍼센트 인코딩(%ZZ 등)은 errors="replace"로 안전하게 유지.
        """
        stripped = line.strip()
        if not stripped:
            return None

        # Nginx Combined / cloudshield_combined 로그 정규식 패턴
        # Why: 표준 Combined 포맷 외에 cloudshield_combined 포맷의
        #      응답 소요 시간($request_time) 및 상위 프록시 헤더를 선택적으로 추출함
        pattern = (
            r"^(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
            r"(?P<ident>\S+)\s+"
            r"(?P<user>\S+)\s+"
            r"\[(?P<time>[^\]]+)\]\s+"
            r'"(?P<method>[A-Za-z]+)\s+(?P<uri>\S+)(?:\s+[^"]+)?"\s+'
            r"(?P<status>\d{3})"
            r"(?:\s+(?P<bytes>\S+)"
            r'(?:\s+"(?P<referer>[^"]*)")?'
            r'(?:\s+"(?P<user_agent>[^"]*)")?'
            r"(?:\s+(?P<response_time>\d+(?:\.\d+)?|-))?"
            r'(?:\s+"(?P<forwarded>[^"]*)")?)?'
        )
        match = re.match(pattern, stripped)
        if not match:
            return None

        groups = match.groupdict()
        raw_uri = groups["uri"]
        unquoted_uri = unquote(raw_uri, encoding="utf-8", errors="replace")

        resp_time_str = groups.get("response_time")
        if resp_time_str and resp_time_str != "-":
            try:
                resp_time = float(resp_time_str)
            except ValueError:
                resp_time = 0.0
        else:
            resp_time = 0.0

        ua = groups.get("user_agent")
        user_agent = ua if ua is not None else "-"

        return cls(
            source_ip=groups["ip"],
            timestamp_str=groups["time"],
            method=groups["method"].upper(),
            uri=unquoted_uri,
            status_code=int(groups["status"]),
            response_time=resp_time,
            user_agent=user_agent,
            raw_message=stripped,
        )
