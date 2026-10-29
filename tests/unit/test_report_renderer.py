# CloudShield 단위 테스트: 침해사고 긴급 대응 보고서 렌더러 및 S3 Presigned URL 발급기
# 소유자: 클라우드 A (플랫폼 전담)
"""보고서 렌더러(report_renderer.py) 및 워커 연동 단위 테스트 모듈."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from contracts.incident import IncidentReport
from remediation.llm_worker import llm_analysis_handler
from remediation.report_renderer import (
    S3_CONNECT_TIMEOUT_SECONDS,
    S3_READ_TIMEOUT_SECONDS,
    render_executive_html_report,
    upload_report_and_generate_presigned_url,
)


@pytest.fixture
def sample_incident_report() -> IncidentReport:
    """테스트용 표준 IncidentReport 객체 생성."""
    return IncidentReport(
        incident_id="INC-20261029-001",
        attack_type="SSH Brute Force",
        mitre_id="T1110.001",
        risk_level="HIGH",
        source_ip="198.51.100.50",
        target_identifier="i-0605f8529598ed820",
        target_accounts=("root", "admin", "testuser"),
        summary_ko=(
            "외부 비인가 IP에서 SSH 무차별 대입 공격이 발생하여 L4 격리 및 WAF 차단을 집행함."
        ),
        action_required="BLOCK_AND_QUARANTINE",
        recommendations=(
            "L4 네트워크 격리 유지 및 포렌식 스냅샷 생성",
            "외부 SSH 22 포트 직접 노출 차단 및 SSM 전환",
            "해당 IP 대역 NACL 차단 규칙 등록",
        ),
    )


class TestExecutiveHtmlReportRenderer:
    """상사 보고용 관공서 공문서 서식 HTML 렌더러 검증 테스트."""

    def test_render_contains_essential_components(
        self,
        sample_incident_report: IncidentReport,
    ) -> None:
        """관공서 표준 결재란, 핵심 사건 정보, 차단 내역 및 권고 조치 표출 검증."""
        raw_logs = [
            "Failed password for root from 198.51.100.50 port 44120 ssh2",
            "Failed password for invalid user admin from 198.51.100.50 port 44122 ssh2",
        ]
        html_out = render_executive_html_report(sample_incident_report, raw_logs)

        # 1. 문서 메타 및 표준 3단 결재란 검증
        assert "문서번호:" in html_out
        assert sample_incident_report.incident_id in html_out
        assert "<th>담당</th>" in html_out
        assert "<th>검토</th>" in html_out
        assert "<th>결재</th>" in html_out

        # 2. 위험도 텍스트 표기 및 불필요한 영단어 병기 배제 검증
        assert 'class="risk-high"' in html_out
        assert "높음" in html_out
        assert "(HIGH)" not in html_out
        assert "badge" not in html_out  # 화려한 배지 클래스 배제

        # 3. 4대 한글 섹션 헤더 검증 (영단어 병기 배제)
        assert "1. 사고 개요" in html_out
        assert "2. 긴급 차단 조치 내역" in html_out
        assert "3. 수집 로그 내역" in html_out
        assert "4. 향후 조치 계획" in html_out

        # 4. 차단 증빙 내역 테이블 및 P2 미측정 기본값 표기 검증
        assert "격리 보안 그룹 교체" in html_out
        assert "차단 목록(IPSet) 영구 등록" in html_out
        assert "차단 완료" in html_out
        assert "측정 정보 없음" in html_out  # processing_times 미전달 시 하드코딩 배제

        # 5. 수집 로그 대조표 검증
        assert "Failed password for root" in html_out
        assert "Failed password for invalid user admin" in html_out

        # 6. 향후 조치 계획 검증
        assert "1단계:" in html_out
        assert "L4 네트워크 격리 유지" in html_out

        # 7. A4 인쇄 미디어 쿼리 검증
        assert "@media print" in html_out
        assert "size: A4 portrait;" in html_out
        assert "page-break-inside: avoid;" in html_out

    def test_format_time_html_xss_escaping(
        self,
        sample_incident_report: IncidentReport,
    ) -> None:
        """P1 필수 검증: processing_times에 악성 XSS 문자열 인입 시 HTML 이스케이프 강제 검증."""
        # 1. processing_times를 통한 악성 스크립트 인젝션 차단 검증
        xss_payloads = {
            "network": "<script>alert('pwned')</script>",
            "waf": "1.25",  # 유효한 숫자형 문자열
        }
        html_out = render_executive_html_report(
            report=sample_incident_report,
            processing_times=xss_payloads,
        )

        assert "<script>" not in html_out
        assert (
            "&lt;script&gt;alert(&#x27;pwned&#x27;)&lt;/script&gt;" in html_out
            or "&lt;script&gt;alert('pwned')&lt;/script&gt;" in html_out
        )
        assert "1.25초" in html_out

        # 2. remediation_times 및 img 태그 XSS 차단 검증
        img_xss = {
            "waf": '<img src=x onerror=alert("xss")>',
            "network": float("nan"),
        }
        html_out_img = render_executive_html_report(
            report=sample_incident_report,
            processing_times=img_xss,
        )
        assert "<img src=x" not in html_out_img
        assert "&lt;img src=x onerror=alert(&quot;xss&quot;)&gt;" in html_out_img
        assert "측정 정보 없음" in html_out_img

    def test_render_with_separate_total_and_layer_times(
        self,
        sample_incident_report: IncidentReport,
    ) -> None:
        """P2 권장 검증: 전체 대응 시간과 계층별 실측 시간이 분리 표기되는지 검증."""
        times = {
            "network": 0.82,
            "waf": 0.45,
            "total": 5.00,
        }
        html_out = render_executive_html_report(
            sample_incident_report,
            processing_times=times,
        )

        assert '<td class="center">0.82초</td>' in html_out
        assert '<td class="center">0.45초</td>' in html_out
        assert "전체 긴급 대응 소요 시간" in html_out
        assert "5.00초" in html_out

    def test_render_with_processing_times(
        self,
        sample_incident_report: IncidentReport,
    ) -> None:
        """P2 권장 사항: 실측 처리 시간 전달 시 테이블 정상 렌더링 검증."""
        times = {
            "network": 0.82,
            "waf": 0.45,
            "auth": 0.12,
        }
        html_out = render_executive_html_report(
            sample_incident_report,
            processing_times=times,
        )

        assert "0.82초" in html_out
        assert "0.45초" in html_out
        assert "0.12초" in html_out

    def test_xss_prevention_escaping(
        self,
        sample_incident_report: IncidentReport,
    ) -> None:
        """원문 로그 또는 요약에 스크립트 태그 인입 시 HTML 엔티티 이스케이프 검증."""
        malicious_logs = [
            "<script>alert('XSS_PAYLOAD')</script>",
            "<img src=x onerror=alert(1)>",
        ]
        html_out = render_executive_html_report(sample_incident_report, malicious_logs)

        # XSS 스크립트 태그가 그대로 노출되지 않고 엔티티로 치환되었는지 검증
        assert "<script>" not in html_out
        assert "&lt;script&gt;" in html_out
        assert "&lt;/script&gt;" in html_out
        assert "&lt;img src=x onerror=alert(1)&gt;" in html_out

    def test_risk_level_color_mapping(self) -> None:
        """MEDIUM 및 LOW 위험도에 대한 텍스트 스타일 매핑 및 영단어 배제 검증."""
        med_report = IncidentReport(
            incident_id="INC-20261029-002",
            attack_type="Port Scanning",
            mitre_id="T1046",
            risk_level="MEDIUM",
            source_ip="203.0.113.10",
            target_identifier="i-0123456789abcdef0",
            target_accounts=(),
            summary_ko="비인가 포트 스캐닝 활동 탐지.",
            action_required="BLOCK_WAF",
            recommendations=(),
        )
        html_med = render_executive_html_report(med_report)
        assert 'class="risk-medium"' in html_med
        assert "보통" in html_med
        assert "(MEDIUM)" not in html_med

        low_report = IncidentReport(
            incident_id="INC-20261029-003",
            attack_type="Information Gathering",
            mitre_id="T1595",
            risk_level="LOW",
            source_ip="203.0.113.20",
            target_identifier="i-0123456789abcdef0",
            target_accounts=(),
            summary_ko="단순 정찰 시도 탐지.",
            action_required="NONE",
            recommendations=(),
        )
        html_low = render_executive_html_report(low_report)
        assert 'class="risk-low"' in html_low
        assert "낮음" in html_low
        assert "(LOW)" not in html_low


class TestS3ReportUploader:
    """Moto 가상 AWS S3 기반 보고서 업로드 및 Presigned URL 생성 검증."""

    @mock_aws
    def test_upload_report_and_generate_presigned_url_success(self) -> None:
        """가상 S3에 객체 업로드 및 Presigned URL 정상 발급 검증."""
        bucket_name = "cloudshield-secops-reports-test"
        s3 = boto3.client("s3", region_name="ap-northeast-2")
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "ap-northeast-2"},
        )

        incident_id = "INC-20261029-777"
        dummy_html = "<html><body><h1>테스트 보고서</h1></body></html>"

        url = upload_report_and_generate_presigned_url(
            report_html=dummy_html,
            incident_id=incident_id,
            bucket_name=bucket_name,
            s3_client=s3,
            expires_in=1800,
        )

        # 1. URL 반환값 검증
        assert isinstance(url, str)
        assert bucket_name in url
        assert f"reports/{incident_id}.html" in url

        # 2. S3 객체 내용 및 메타데이터 검증
        resp = s3.get_object(Bucket=bucket_name, Key=f"reports/{incident_id}.html")
        content = resp["Body"].read().decode("utf-8")
        assert content == dummy_html
        assert resp["ContentType"] == "text/html; charset=utf-8"

    def test_s3_client_timeout_config(self) -> None:
        """P1 필수 검증: 기본 S3 클라이언트 생성 시 타임아웃 상한(2초/5초, 재시도 1회) 강제 검증."""
        with patch("boto3.client") as mock_boto_client:
            mock_inst = MagicMock()
            mock_inst.generate_presigned_url.return_value = "https://s3.example.com/purl"
            mock_boto_client.return_value = mock_inst

            upload_report_and_generate_presigned_url(
                report_html="<html></html>",
                incident_id="INC-001",
                bucket_name="my-bucket",
                s3_client=None,
            )

            mock_boto_client.assert_called_once()
            service_name, kwargs = mock_boto_client.call_args
            assert service_name[0] == "s3"
            client_config = kwargs.get("config")
            assert client_config is not None
            assert client_config.connect_timeout == S3_CONNECT_TIMEOUT_SECONDS
            assert client_config.read_timeout == S3_READ_TIMEOUT_SECONDS
            assert client_config.retries["total_max_attempts"] == 1

    def test_validation_errors(self) -> None:
        """버킷명 또는 사건 ID 누락 시 ValueError 발생 검증."""
        with pytest.raises(ValueError, match="bucket_name은 비어 있을 수 없습니다"):
            upload_report_and_generate_presigned_url("<html></html>", "INC-001", "")

        with pytest.raises(ValueError, match="incident_id는 비어 있을 수 없습니다"):
            upload_report_and_generate_presigned_url("<html></html>", "", "my-bucket")


class TestLlmWorkerReportIntegration:
    """llm_worker.py 핸들러와 S3 보고서 생성 파이프라인 결합 및 장애 격리 검증."""

    @mock_aws
    def test_worker_report_generation_and_slack_integration(
        self,
        sample_incident_report: IncidentReport,
    ) -> None:
        """REPORTS_S3_BUCKET 환경변수 존재 시 HTML 렌더링, 업로드 및 report_url 전달 검증."""
        bucket_name = "cloudshield-secops-reports-dev"
        s3 = boto3.client("s3", region_name="ap-northeast-2")
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "ap-northeast-2"},
        )

        event = {
            "source": "cloudshield.security",
            "detail-type": "ThreatRemediated",
            "id": "evt-12345",
            "detail": {
                **sample_incident_report.model_dump(),
                "raw_logs": ["Sample syslog line 1", "Sample syslog line 2"],
                "processing_times": {"network": 0.77, "waf": 0.33, "auth": 0.09},
            },
        }

        with (
            patch.dict(os.environ, {"REPORTS_S3_BUCKET": bucket_name}),
            patch(
                "remediation.llm_worker.send_deep_analysis_slack_alert",
                return_value=True,
            ) as mock_send_slack,
        ):
            res = llm_analysis_handler(event, s3_client=s3)

            assert res["status"] == "accepted"
            assert res["incident_id"] == sample_incident_report.incident_id
            assert res["report_url"] is not None
            assert bucket_name in res["report_url"]

            # Slack 전송 함수에 report_url이 전달되었는지 검증
            mock_send_slack.assert_called_once()
            _, kwargs = mock_send_slack.call_args
            assert kwargs.get("report_url") == res["report_url"]

    def test_worker_s3_timeout_delay_isolation(
        self,
        sample_incident_report: IncidentReport,
    ) -> None:
        """P1 필수 검증: S3 지연/타임아웃 발생 시에도
        Lambda가 중단되지 않고 Slack 기본 알림이 발송되는지 검증."""
        event = {
            "source": "cloudshield.security",
            "detail-type": "ThreatRemediated",
            "id": "evt-12345",
            "detail": sample_incident_report.model_dump(),
        }

        mock_s3 = MagicMock()
        # S3 연결 시간 초과 모의
        mock_s3.put_object.side_effect = TimeoutError("S3 Socket Connect Timeout (exceeded 2.0s)")
        mock_bedrock = MagicMock()

        with (
            patch.dict(os.environ, {"REPORTS_S3_BUCKET": "dummy-bucket"}),
            patch(
                "remediation.llm_worker.send_deep_analysis_slack_alert",
                return_value=True,
            ) as mock_send_slack,
        ):
            res = llm_analysis_handler(event, bedrock_client=mock_bedrock, s3_client=mock_s3)

            assert res["status"] == "accepted"
            assert res["report_url"] is None  # 지연 장애 시 안전 격리
            assert res["slack_notified"] is True  # Slack 알림은 정상 발송

            mock_send_slack.assert_called_once()
            _, kwargs = mock_send_slack.call_args
            assert kwargs.get("report_url") is None

    def test_worker_s3_skipped_when_lambda_remaining_time_insufficient(
        self,
        sample_incident_report: IncidentReport,
    ) -> None:
        """P1 필수 검증: Bedrock 지연 등으로 잔여 시간이 부족(8000ms 미만)할 때
        S3 호출을 안전 생략하고 Slack 전송 예산을 확보하는지 검증."""
        event = {
            "source": "cloudshield.security",
            "detail-type": "ThreatRemediated",
            "id": "evt-12345",
            "detail": sample_incident_report.model_dump(),
        }

        mock_context = MagicMock()
        # S3 진입 시점에 잔여시간 4000ms 반환 (S3_MIN_REMAINING_BUDGET_MS=8000 미만)
        mock_context.get_remaining_time_in_millis.return_value = 4000

        mock_s3 = MagicMock()
        mock_bedrock = MagicMock()

        with (
            patch.dict(os.environ, {"REPORTS_S3_BUCKET": "cloudshield-secops-reports-dev"}),
            patch(
                "remediation.llm_worker.send_deep_analysis_slack_alert",
                return_value=True,
            ) as mock_send_slack,
        ):
            res = llm_analysis_handler(
                event=event,
                context=mock_context,
                bedrock_client=mock_bedrock,
                s3_client=mock_s3,
            )

            assert res["status"] == "accepted"
            # S3 호출이 생략되어야 함
            assert res["report_url"] is None
            mock_s3.put_object.assert_not_called()
            # Slack 알림은 잔여 시간에 맞춰 정상 호출되어야 함
            assert res["slack_notified"] is True
            mock_send_slack.assert_called_once()
            _, kwargs = mock_send_slack.call_args
            # 4000ms 잔여시간 기준: (4000 - 500) / 1000 = 3.5초 타임아웃 캡핑 검증
            assert kwargs.get("timeout") == 3.5
            assert kwargs.get("report_url") is None

    @mock_aws
    def test_worker_pipeline_timestamps_integration_with_s3_report(
        self,
        sample_incident_report: IncidentReport,
    ) -> None:
        """P2 권장 검증: 실제 생산자가 발행한 pipeline_timestamps를 소비하여
        S3 보고서 HTML에 실측 시간(0.42초)이 연동 렌더링되는지 E2E 통합 검증."""
        bucket_name = "cloudshield-secops-reports-dev"
        s3 = boto3.client("s3", region_name="ap-northeast-2")
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "ap-northeast-2"},
        )

        # 생산자(orchestrator)가 발행하는 표준 형태의 이벤트
        event = {
            "source": "cloudshield.security",
            "detail-type": "ThreatRemediated",
            "id": "evt-prod-001",
            "detail": {
                **sample_incident_report.model_dump(),
                "raw_logs": ["Sample syslog log message 1"],
                "pipeline_timestamps": {
                    "detected_epoch": 1700000000.0,
                    "remediated_epoch": 1700000000.42,
                },
            },
        }

        with (
            patch.dict(os.environ, {"REPORTS_S3_BUCKET": bucket_name}),
            patch(
                "remediation.llm_worker.send_deep_analysis_slack_alert",
                return_value=True,
            ),
        ):
            res = llm_analysis_handler(event, s3_client=s3)

            assert res["status"] == "accepted"
            assert res["report_url"] is not None

            # S3에 업로드된 HTML 본문 조회
            object_key = f"reports/{sample_incident_report.incident_id}.html"
            s3_obj = s3.get_object(Bucket=bucket_name, Key=object_key)
            html_body = s3_obj["Body"].read().decode("utf-8")

            # 실측 계산된 0.42초가 전체 긴급 대응 소요 시간에 단독 표기되었는지 검증
            assert "전체 긴급 대응 소요 시간" in html_body
            assert "0.42초" in html_body
            # 개별 계층(네트워크, 웹 방화벽)은 복제되지 않고 정직하게 '측정 정보 없음' 유지 검증
            assert "측정 정보 없음" in html_body
            assert '<td class="center">0.42초</td>' not in html_body
            assert '<th class="center">0.42초</th>' in html_body

    @mock_aws
    def test_worker_remediation_times_xss_escaping_via_handler(
        self,
        sample_incident_report: IncidentReport,
    ) -> None:
        """P1 필수: remediation_times 경로 악성 HTML 인입 시 S3 보고서 XSS 이스케이프 검증."""
        bucket_name = "cloudshield-secops-reports-dev"
        s3 = boto3.client("s3", region_name="ap-northeast-2")
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "ap-northeast-2"},
        )
        event = {
            "source": "cloudshield.security",
            "detail-type": "ThreatRemediated",
            "id": "evt-xss-001",
            "detail": {
                **sample_incident_report.model_dump(),
                "remediation_times": {"waf": "<img src=x onerror=alert(1)>"},
            },
        }
        with (
            patch.dict(os.environ, {"REPORTS_S3_BUCKET": bucket_name}),
            patch("remediation.llm_worker.send_deep_analysis_slack_alert", return_value=True),
        ):
            res = llm_analysis_handler(event, s3_client=s3)
            assert res["status"] == "accepted"
            s3_obj = s3.get_object(
                Bucket=bucket_name, Key=f"reports/{sample_incident_report.incident_id}.html"
            )
            html_body = s3_obj["Body"].read().decode("utf-8")
            assert "<img src=x" not in html_body
            assert "&lt;img src=x onerror=alert(1)&gt;" in html_body

    @pytest.mark.parametrize("remaining_ms", [0, 200, 400, 500])
    def test_worker_slack_skipped_on_boundary_remaining_times(
        self,
        sample_incident_report: IncidentReport,
        remaining_ms: int,
    ) -> None:
        """P1 필수: 0, 200, 400, 500ms 경계값에서 데드라인 버퍼(500ms) 이하이므로
        Slack 네트워크 호출을 생략하고 slack_notified=False를 반환하는지 검증."""
        event = {
            "source": "cloudshield.security",
            "detail-type": "ThreatRemediated",
            "id": f"evt-bound-{remaining_ms}",
            "detail": sample_incident_report.model_dump(),
        }

        mock_context = MagicMock()
        mock_context.get_remaining_time_in_millis.return_value = remaining_ms
        mock_s3 = MagicMock()
        mock_bedrock = MagicMock()

        with (
            patch.dict(os.environ, {"REPORTS_S3_BUCKET": "cloudshield-secops-reports-dev"}),
            patch(
                "remediation.llm_worker.send_deep_analysis_slack_alert",
                return_value=True,
            ) as mock_send_slack,
        ):
            res = llm_analysis_handler(
                event=event,
                context=mock_context,
                bedrock_client=mock_bedrock,
                s3_client=mock_s3,
            )

            assert res["status"] == "accepted"
            assert res["report_url"] is None
            mock_s3.put_object.assert_not_called()
            assert res["slack_notified"] is False
            mock_send_slack.assert_not_called()

    @pytest.mark.parametrize(
        ("remaining_ms", "expected_timeout"),
        [
            (600, 0.1),
            (1000, 0.5),
            (3000, 2.5),
            (7000, 5.0),
        ],
    )
    def test_worker_slack_timeout_clamped_to_exact_usable_budget(
        self,
        sample_incident_report: IncidentReport,
        remaining_ms: int,
        expected_timeout: float,
    ) -> None:
        """P1 필수: 버퍼 차감 후 잔여 예산이 양수인 경우, 해당 예산을 초과하지 않는
        정확한 타임아웃으로 Slack이 호출되는지 검증 (5.0초 상한 준수)."""
        event = {
            "source": "cloudshield.security",
            "detail-type": "ThreatRemediated",
            "id": f"evt-budget-{remaining_ms}",
            "detail": sample_incident_report.model_dump(),
        }

        mock_context = MagicMock()
        mock_context.get_remaining_time_in_millis.return_value = remaining_ms
        mock_s3 = MagicMock()
        mock_bedrock = MagicMock()

        with (
            patch(
                "remediation.llm_worker.send_deep_analysis_slack_alert",
                return_value=True,
            ) as mock_send_slack,
        ):
            res = llm_analysis_handler(
                event=event,
                context=mock_context,
                bedrock_client=mock_bedrock,
                s3_client=mock_s3,
            )

            assert res["status"] == "accepted"
            assert res["slack_notified"] is True
            mock_send_slack.assert_called_once()
            _, kwargs = mock_send_slack.call_args
            assert kwargs.get("timeout") == pytest.approx(expected_timeout)

    @mock_aws
    def test_worker_s3_success_then_slack_remaining_time_depleted(
        self,
        sample_incident_report: IncidentReport,
    ) -> None:
        """P1 필수: S3 진입 시 10,000ms로 성공했으나, S3 완료 후 잔여 시간이
        400ms(버퍼 500ms 이하)로 급감한 경우 Slack 호출을 안전 생략하는지 검증."""
        bucket_name = "cloudshield-secops-reports-dev"
        s3 = boto3.client("s3", region_name="ap-northeast-2")
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "ap-northeast-2"},
        )
        event = {
            "source": "cloudshield.security",
            "detail-type": "ThreatRemediated",
            "id": "evt-s3-then-depleted",
            "detail": sample_incident_report.model_dump(),
        }

        mock_context = MagicMock()
        # 1차(S3 진입 시): 10,000ms -> S3 진행
        # 2차(Slack 진입 시): 400ms -> 버퍼 500ms 이하이므로 Slack 생략
        mock_context.get_remaining_time_in_millis.side_effect = [10000, 400]

        with (
            patch.dict(os.environ, {"REPORTS_S3_BUCKET": bucket_name}),
            patch(
                "remediation.llm_worker.send_deep_analysis_slack_alert",
                return_value=True,
            ) as mock_send_slack,
        ):
            res = llm_analysis_handler(event, context=mock_context, s3_client=s3)

            assert res["status"] == "accepted"
            assert res["report_url"] is not None
            assert res["slack_notified"] is False
            mock_send_slack.assert_not_called()

    @mock_aws
    def test_worker_s3_success_then_slack_timeout_reduced(
        self,
        sample_incident_report: IncidentReport,
    ) -> None:
        """P1 필수: S3 10,000ms 성공 후 Slack 진입 시 잔여 3,500ms로 감소한 경우
        Slack 타임아웃이 3.0초((3500-500)/1000)로 동적 축소 적용되는지 검증."""
        bucket_name = "cloudshield-secops-reports-dev"
        s3 = boto3.client("s3", region_name="ap-northeast-2")
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "ap-northeast-2"},
        )
        event = {
            "source": "cloudshield.security",
            "detail-type": "ThreatRemediated",
            "id": "evt-s3-then-reduced",
            "detail": sample_incident_report.model_dump(),
        }

        mock_context = MagicMock()
        # 1차(S3 진입 시): 10,000ms -> S3 진행
        # 2차(Slack 진입 시): 3,500ms -> 가용 예산 3.0초
        mock_context.get_remaining_time_in_millis.side_effect = [10000, 3500]

        with (
            patch.dict(os.environ, {"REPORTS_S3_BUCKET": bucket_name}),
            patch(
                "remediation.llm_worker.send_deep_analysis_slack_alert",
                return_value=True,
            ) as mock_send_slack,
        ):
            res = llm_analysis_handler(event, context=mock_context, s3_client=s3)

            assert res["status"] == "accepted"
            assert res["report_url"] is not None
            assert res["slack_notified"] is True
            mock_send_slack.assert_called_once()
            _, kwargs = mock_send_slack.call_args
            assert kwargs.get("timeout") == pytest.approx(3.0)
