# CloudShield 보고서 렌더러: 침해사고 긴급 대응 결과 공문서 HTML 렌더링 및 S3 발급기
# 소유자: 클라우드 A (플랫폼 전담)
"""침해사고 긴급 대응 결과 보고서 HTML 렌더링 및 S3 Presigned URL 발급 모듈.

Why:
    사후 LLM 심층 분석 완료 후 기계적 Slack 요약에 그치지 않고,
    경영진 및 관공서 결재 규격에 부합하는 정형화된 A4 인쇄/PDF 호환 보고서를 자동 생성함.
    사내 인가 공인 IP로만 접근 가능한 격리된 S3 버킷에 안전하게 업로드하고,
    1시간 만료의 안전한 임시 열람 링크(Presigned URL)를 생성하여 관제 효율을 극대화함.

Constraints:
    - 외부 CDN 라이브러리 및 웹 폰트 의존성 없이 단일 파일 인라인 CSS로만 스타일링.
    - XSS 인젝션 방어를 위해 원문 로그 및 사용자 입력 필드는 html.escape() 필수 처리.
    - @media print 및 @page A4 세로 규격을 강제하여 브라우저 인쇄 및 PDF 저장 시 표 분할 방지.
    - S3 업로드는 바이트 스트림(put_object)으로 직접 전송하여 런타임 디스크 의존성 배제.

Side-effects / Edge-cases:
    - boto3 s3_client 미전달 시 내부에서 안전하게 기본 클라이언트를 생성하여 사용.
    - 잘못된 IncidentReport 모델 인입 시 ValueError 전파.
    - S3 통신 장애(네트워크 오류, 자격증명 만료 등) 시 호출자에게 예외를 전파하되,
      워커 레벨에서 격리할 수 있도록 설계됨.
"""

from __future__ import annotations

import html
import logging
import math
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from contracts.incident import IncidentReport

logger = logging.getLogger(__name__)

# 기본 Presigned URL 유효 기간: 1시간 (3600초)
DEFAULT_URL_EXPIRATION_SECONDS = 3600
# S3 클라이언트 타임아웃 상한: Lambda 30초 데드라인 침범 방지 (연결 2초, 읽기 5초, 재시도 1회)
S3_CONNECT_TIMEOUT_SECONDS = 2
S3_READ_TIMEOUT_SECONDS = 5


def render_executive_html_report(
    report: IncidentReport,
    raw_logs: list[str] | None = None,
    processing_times: dict[str, str | float] | None = None,
) -> str:
    """IncidentReport 데이터 및 원문 로그를 관공서 표준 공문서 HTML 양식으로 렌더링.

    Why:
        결정론적 침해 사실(사건 ID, 공격자 IP, 차단 조치)과 LLM 추론 결과(요약, 권고)를
        엄격한 A4 규격의 흑백 위주 공문서 서식으로 결합하여 신뢰성과 가독성을 보장함.

    Constraints:
        - report: 유효한 IncidentReport 인스턴스.
        - raw_logs: 수집된 원문 로그 목록 (최대 10건 권장 표기).
        - 반환값: UTF-8 인코딩 가능한 독립형 완전한 HTML 문자열.
    """
    safe_incident_id = html.escape(report.incident_id)
    safe_attack_type = html.escape(report.attack_type)
    safe_mitre_id = html.escape(report.mitre_id)
    safe_source_ip = html.escape(report.source_ip)
    safe_target_id = html.escape(report.target_identifier)
    safe_summary = html.escape(report.summary_ko)

    # 공격 시도 대상 계정 포맷팅
    if report.target_accounts:
        safe_accounts = ", ".join(html.escape(acc) for acc in report.target_accounts)
    else:
        safe_accounts = "지정 계정 없음 (단일 호스트 또는 웹 엔드포인트 전역 스캔)"

    # 위험도 등급에 따른 텍스트 색상 클래스 지정 (불필요한 영단어 병기 배제)
    risk_class = "risk-high"
    risk_label = "높음"
    if report.risk_level == "MEDIUM":
        risk_class = "risk-medium"
        risk_label = "보통"
    elif report.risk_level == "LOW":
        risk_class = "risk-low"
        risk_label = "낮음"

    # 처리 시간 포맷팅 헬퍼 (실측값 우선 적용, 미측정 시 정직한 '측정 정보 없음' 표기)
    times = processing_times or {}

    def _format_time(val: Any) -> str:
        if val is None or val == "":
            return "측정 정보 없음"
        if isinstance(val, (int, float)):
            if math.isnan(val) or math.isinf(val):
                return "측정 정보 없음"
            return f"{val:.2f}초"
        if isinstance(val, str):
            clean_str = val.strip()
            if not clean_str:
                return "측정 정보 없음"
            try:
                num = float(clean_str)
                if not (math.isnan(num) or math.isinf(num)):
                    return f"{num:.2f}초"
            except (ValueError, TypeError):
                pass
            return html.escape(clean_str)
        return html.escape(str(val))

    time_network = _format_time(times.get("network"))
    time_waf = _format_time(times.get("waf"))
    time_iam = _format_time(times.get("iam"))
    time_auth = _format_time(times.get("auth"))
    time_total = _format_time(times.get("total"))

    # 긴급 차단 조치 내역 테이블 행 생성
    remediation_rows: list[str] = []

    # 1. L4 네트워크 격리 조치
    if report.action_required in ("BLOCK_AND_QUARANTINE", "QUARANTINE_EC2"):
        remediation_rows.append(
            f"""        <tr>
          <td class="center">네트워크</td>
          <td><code>{safe_target_id}</code></td>
          <td>격리 보안 그룹 교체 (모든 외부 인입 차단)</td>
          <td class="center">차단 완료</td>
          <td class="center">{time_network}</td>
        </tr>"""
        )

    # 2. L7 웹 방화벽 조치
    if report.action_required in ("BLOCK_AND_QUARANTINE", "BLOCK_WAF", "BLOCK_IP_ONLY"):
        remediation_rows.append(
            f"""        <tr>
          <td class="center">웹 방화벽</td>
          <td><code>{safe_source_ip}/32</code></td>
          <td>차단 목록(IPSet) 영구 등록</td>
          <td class="center">차단 완료</td>
          <td class="center">{time_waf}</td>
        </tr>"""
        )

    # 3. 인증/세션 조치
    if report.action_required == "REVOKE_IAM_SESSION":
        remediation_rows.append(
            f"""        <tr>
          <td class="center">인증 권한</td>
          <td>IAM 세션 토큰</td>
          <td>발급된 임시 자격증명 및 세션 즉시 만료</td>
          <td class="center">만료 완료</td>
          <td class="center">{time_iam}</td>
        </tr>"""
        )

    # 4. 공통 상태 관리 행
    remediation_rows.append(
        f"""        <tr>
          <td class="center">상태 관리</td>
          <td>인증 상태 저장소</td>
          <td>차단 이력 영속 기록 및 중복 차단 방지 적용</td>
          <td class="center">기록 완료</td>
          <td class="center">{time_auth}</td>
        </tr>"""
    )

    remediation_tbody = "\n".join(remediation_rows)

    # 원문 수집 로그 테이블 행 생성
    log_rows: list[str] = []
    effective_logs = raw_logs if raw_logs is not None else []
    display_logs = effective_logs[:10]

    if display_logs:
        for idx, line in enumerate(display_logs):
            safe_line = html.escape(line)
            log_rows.append(
                f"""        <tr>
          <td class="center">{idx + 1}</td>
          <td class="center">{safe_source_ip}</td>
          <td><code>{safe_line}</code></td>
        </tr>"""
            )
    else:
        log_rows.append(
            """        <tr>
          <td colspan="3" class="center" style="color: #666666;">
            수집된 원문 로그 내역이 없습니다.
          </td>
        </tr>"""
        )

    log_tbody = "\n".join(log_rows)

    # 향후 권고 조치 목록 렌더링
    recommendation_items: list[str] = []
    if report.recommendations:
        for idx, rec in enumerate(report.recommendations):
            safe_rec = html.escape(rec)
            recommendation_items.append(
                f"      <li><strong>{idx + 1}단계:</strong> {safe_rec}</li>"
            )
    else:
        recommendation_items.append("      <li>추가 권고 조치 사항 없음.</li>")

    recommendations_html = "\n".join(recommendation_items)

    html_template = f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>침해사고 긴급 대응 결과 보고서 ({safe_incident_id})</title>
  <style>
    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}
    body {{
      font-family: "Malgun Gothic", "맑은 고딕", "Pretendard", "Noto Sans KR", sans-serif;
      background-color: #f5f5f5;
      color: #111111;
      padding: 30px 15px;
      line-height: 1.5;
    }}
    .document-page {{
      max-width: 820px;
      margin: 0 auto;
      background: #ffffff;
      border: 1px solid #999999;
      padding: 40px 45px;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.08);
    }}
    .top-meta-bar {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 25px;
      border-bottom: 2px solid #222222;
      padding-bottom: 12px;
    }}
    .doc-identifier {{
      font-size: 13px;
      color: #333333;
    }}
    .doc-identifier div {{
      margin-bottom: 4px;
    }}
    .approval-box {{
      border-collapse: collapse;
      font-size: 12px;
      text-align: center;
    }}
    .approval-box th {{
      background-color: #f2f2f2;
      border: 1px solid #444444;
      padding: 4px 12px;
      font-weight: 600;
      width: 65px;
    }}
    .approval-box td {{
      border: 1px solid #444444;
      height: 50px;
      vertical-align: middle;
      color: #777777;
    }}
    .title-box {{
      text-align: center;
      margin: 25px 0 30px;
    }}
    .title-box h1 {{
      font-size: 23px;
      font-weight: 800;
      letter-spacing: 2px;
      color: #000000;
      margin-bottom: 8px;
    }}
    .title-sub {{
      font-size: 14px;
      color: #444444;
    }}
    .risk-high {{
      color: #c00000;
      font-weight: 800;
    }}
    .risk-medium {{
      color: #d97706;
      font-weight: 800;
    }}
    .risk-low {{
      color: #2563eb;
      font-weight: 800;
    }}
    .section-block {{
      margin-bottom: 25px;
      page-break-inside: avoid;
    }}
    .section-header {{
      font-size: 15px;
      font-weight: 700;
      color: #000000;
      margin-bottom: 8px;
      padding-bottom: 4px;
      border-bottom: 1px solid #333333;
    }}
    .report-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      margin-top: 6px;
    }}
    .report-table th, .report-table td {{
      border: 1px solid #555555;
      padding: 7px 10px;
      text-align: left;
    }}
    .report-table th {{
      background-color: #f2f2f2;
      font-weight: 600;
      color: #111111;
      text-align: center;
    }}
    .report-table tfoot th {{
      background-color: #f9f9f9;
      font-weight: 600;
    }}
    .report-table tfoot th.total-label {{
      text-align: right;
      padding-right: 15px;
    }}
    .report-table td.center {{
      text-align: center;
    }}
    .report-table code {{
      font-family: Consolas, monospace;
      font-size: 12px;
    }}
    .summary-text-box {{
      border: 1px solid #555555;
      padding: 12px 14px;
      background-color: #fafafa;
      font-size: 13px;
      line-height: 1.7;
      color: #111111;
      margin-bottom: 10px;
    }}
    .bullet-list {{
      margin-left: 18px;
      font-size: 13px;
      color: #222222;
      line-height: 1.8;
    }}
    .bullet-list li {{
      margin-bottom: 4px;
    }}
    .footer-notice {{
      margin-top: 30px;
      padding-top: 10px;
      border-top: 1px dashed #777777;
      font-size: 11px;
      color: #555555;
      text-align: center;
      line-height: 1.5;
    }}
    @media print {{
      @page {{
        size: A4 portrait;
        margin: 15mm;
      }}
      body {{
        background-color: #ffffff;
        padding: 0;
      }}
      .document-page {{
        box-shadow: none;
        border: none;
        padding: 0;
        max-width: 100%;
      }}
      .approval-box th, .report-table th {{
        background-color: #f2f2f2 !important;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
      }}
    }}
  </style>
</head>
<body>

<div class="document-page">
  <div class="top-meta-bar">
    <div class="doc-identifier">
      <div><strong>문서번호:</strong> {safe_incident_id}</div>
      <div><strong>보안등급:</strong> 대외비 (인가망 한정)</div>
      <div><strong>대응체계:</strong> 10초 관통 원자적 차단 오케스트레이터</div>
    </div>
    <table class="approval-box">
      <thead>
        <tr>
          <th>담당</th>
          <th>검토</th>
          <th>결재</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>(서명)</td>
          <td></td>
          <td></td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class="title-box">
    <h1>침해사고 긴급 대응 결과 보고서</h1>
    <div class="title-sub">
      사고 식별번호: {safe_incident_id} &nbsp;|&nbsp;
      위험 등급: <span class="{risk_class}">{risk_label}</span>
    </div>
  </div>

  <div class="section-block">
    <div class="section-header">1. 사고 개요</div>
    <div class="summary-text-box">
      {safe_summary}
    </div>
    <table class="report-table">
      <tbody>
        <tr>
          <th style="width: 20%;">공격 유형</th>
          <td style="width: 30%;">{safe_attack_type} ({safe_mitre_id})</td>
          <th style="width: 20%;">위험도 평가</th>
          <td style="width: 30%;"><span class="{risk_class}">{risk_label}</span></td>
        </tr>
        <tr>
          <th>출발지 주소</th>
          <td><code>{safe_source_ip}</code></td>
          <th>피해 대상 자원</th>
          <td><code>{safe_target_id}</code></td>
        </tr>
        <tr>
          <th>접근 시도 대상</th>
          <td colspan="3">{safe_accounts}</td>
        </tr>
      </tbody>
    </table>
  </div>

  <div class="section-block">
    <div class="section-header">2. 긴급 차단 조치 내역</div>
    <table class="report-table">
      <thead>
        <tr>
          <th style="width: 15%;">구분</th>
          <th style="width: 25%;">대상 자원</th>
          <th style="width: 35%;">적용 조치</th>
          <th style="width: 12%;">결과</th>
          <th style="width: 13%;">처리 시간</th>
        </tr>
      </thead>
      <tbody>
{remediation_tbody}
      </tbody>
      <tfoot>
        <tr>
          <th colspan="4" class="total-label">전체 긴급 대응 소요 시간</th>
          <th class="center">{time_total}</th>
        </tr>
      </tfoot>
    </table>
  </div>

  <div class="section-block">
    <div class="section-header">3. 수집 로그 내역</div>
    <table class="report-table">
      <thead>
        <tr>
          <th style="width: 10%;">번호</th>
          <th style="width: 25%;">출발지 주소</th>
          <th>기록 내역</th>
        </tr>
      </thead>
      <tbody>
{log_tbody}
      </tbody>
    </table>
  </div>

  <div class="section-block">
    <div class="section-header">4. 향후 조치 계획</div>
    <ul class="bullet-list">
{recommendations_html}
    </ul>
  </div>

  <div class="footer-notice">
    본 문서는 보안 오케스트레이터에 의해 자동 생성된 내부 열람용 문서입니다.<br>
    사내 인가 공인 IP 접속자만 열람할 수 있으며, 보존 기간(7일) 만료 후 자동 폐기됩니다.
  </div>
</div>

</body>
</html>"""
    return html_template


def upload_report_and_generate_presigned_url(
    report_html: str,
    incident_id: str,
    bucket_name: str,
    s3_client: Any = None,
    expires_in: int = DEFAULT_URL_EXPIRATION_SECONDS,
) -> str:
    """HTML 보고서를 S3에 업로드하고 1시간 만료의 Presigned URL을 생성하여 반환.

    Why:
        S3 퍼블릭 공개 없이 서명된 임시 URL을 통해서만 브라우저 접속을 허용하며,
        버킷 정책의 IP 조건절과 결합하여 이중 인가(Dual Authorization)를 구현함.

    Constraints:
        - bucket_name: 대상 S3 버킷 이름 (비어 있을 경우 ValueError).
        - incident_id: 사건 고유 식별자. 객체 키는 `reports/{incident_id}.html`로 결정론적 매핑.
        - expires_in: Presigned URL 유효 시간 (초, 기본값 3600초).

    Side-effects / Edge-cases:
        - S3 PutObject 및 generate_presigned_url 호출 시 발생하는 클라이언트 오류는
          호출자가 적절히 제어할 수 있도록 예외를 전파함.
    """
    if not bucket_name:
        raise ValueError("bucket_name은 비어 있을 수 없습니다.")
    if not incident_id:
        raise ValueError("incident_id는 비어 있을 수 없습니다.")

    client = s3_client
    if client is None:
        import boto3
        from botocore.config import Config

        client = boto3.client(
            "s3",
            config=Config(
                connect_timeout=S3_CONNECT_TIMEOUT_SECONDS,
                read_timeout=S3_READ_TIMEOUT_SECONDS,
                retries={"mode": "standard", "total_max_attempts": 1},
            ),
        )

    object_key = f"reports/{incident_id}.html"
    body_bytes = report_html.encode("utf-8")

    logger.info("S3 보고서 업로드 시작: bucket=%s, key=%s", bucket_name, object_key)
    client.put_object(
        Bucket=bucket_name,
        Key=object_key,
        Body=body_bytes,
        ContentType="text/html; charset=utf-8",
    )

    url = client.generate_presigned_url(
        ClientMethod="get_object",
        Params={"Bucket": bucket_name, "Key": object_key},
        ExpiresIn=expires_in,
    )
    logger.info("S3 보고서 Presigned URL 발급 완료: bucket=%s, key=%s", bucket_name, object_key)
    return str(url)
