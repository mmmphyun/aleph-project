"""P5-2 관제용 Grafana 가져오기 자료를 생성한다. AWS 호출과 인프라 변경은 없다."""

from __future__ import annotations

from typing import Any

DATASOURCE = {"type": "cloudwatch", "uid": "cloudshield-cloudwatch"}
AUTH_GROUP = "/cloudshield/target/auth-log"
WEB_GROUP = "/cloudshield/target/nginx-access-log"
ORCHESTRATOR_GROUP = "/aws/lambda/CloudShield-Threat-Orchestrator"
ANALYZER_GROUP = "/aws/lambda/cloudshield-llm-analyzer"

# Lambda의 텍스트 로그와 JSON 로그의 message 문자열을 모두 처리한다.
JSON_RECORD = (
    "parse @message /(?<json_payload>\\{.*\\})/\n"
    "| fields jsonParse(json_payload) as envelope\n"
    "| fields coalesce(envelope.message, json_payload) as body\n"
    "| fields jsonParse(body) as record\n"
)


def build_dashboard(region: str = "ap-southeast-2") -> dict[str, Any]:
    """기존 데이터소스 UID에 연결되는 2×2 대시보드를 반환한다.

    Why: 클라우드 B가 관제 쿼리를 소유하고 플랫폼의 Docker/IAM 파일은 보존한다.
    Constraints: 후보 로그 건수는 확정 공격 수가 아니며 10초 전체 SLA를 추정하지 않는다.
    Side-effects: 순수 JSON 자료만 생성한다. 미수집 시간 필드는 No data로 남는다.
    """
    if not region or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in region):
        raise ValueError("AWS 리전 형식이 올바르지 않습니다")

    def target(ref: str, query: str, groups: list[str]) -> dict[str, Any]:
        return {
            "refId": ref,
            "id": ref,
            "datasource": dict(DATASOURCE),
            "queryMode": "Logs",
            "region": region,
            "expression": query,
            # Grafana 11.2에서 logGroups는 ARN이 필수다. 계정 ARN을 추정하지 않고
            # 해당 버전이 지원하는 이름 기반 필드로 기존 데이터소스 계정을 사용한다.
            "logGroupNames": list(groups),
        }

    definitions = [
        (
            "공격 후보 로그 인입 · SSH 실패 / HTTP 4xx",
            "timeseries",
            "SSH 인증 실패와 HTTP 4xx 원시 로그 건수. 재시도·정상 오타·404도 포함하므로 "
            "시그니처가 확정한 공격 사건 수와 구분한다.",
            [
                target(
                    "A",
                    "filter @message like /Failed password/\n"
                    "| stats count(*) as ssh_failures by bin(1m)",
                    [AUTH_GROUP],
                ),
                target(
                    "B",
                    'parse @message /"[^"]*" (?<http_status>[0-9]{3}) /\n'
                    "| filter http_status >= 400 and http_status < 500\n"
                    "| stats count(*) as http_4xx by bin(1m)",
                    [WEB_GROUP],
                ),
            ],
        ),
        (
            "탐지→대응 반환 지연 · 전체 10초 SLA 미평가",
            "timeseries",
            "기존 pipeline_timestamps의 remediated_epoch - detected_epoch(초). "
            "ThreatRemediatedMetric INFO JSON 로그의 시간 필드를 사용하며 누락 구간은 No data다. "
            "분 집계점이 보이도록 조회 범위에 분 경계를 포함한다. 대응 API 반환까지의 구간이며 "
            "조치 성공·공격 시작·"
            "물리적 차단 시각을 보장하지 않는다. Lambda Duration으로 대체하지 않는다.",
            [
                target(
                    "A",
                    JSON_RECORD + "| fields record.pipeline_timestamps.detected_epoch as detected, "
                    "record.pipeline_timestamps.remediated_epoch as remediated\n"
                    "| filter ispresent(detected) and ispresent(remediated) "
                    "and remediated >= detected\n"
                    "| fields (remediated - detected) as response_seconds\n"
                    "| stats max(response_seconds) as max_response_seconds, "
                    "pct(response_seconds, 95) as p95_response_seconds by bin(1m)",
                    [ORCHESTRATOR_GROUP, ANALYZER_GROUP],
                )
            ],
        ),
        (
            "LLM 정상 / Fallback · 사건별 최종 관측 상태",
            "piechart",
            "enhanced=검증된 분석, parse_failed/call_failed=Fallback. "
            "동일 사건의 재시도는 latest로 마지막 관측 상태 한 건만 집계한다. "
            "상태 로그가 없는 미호출·임포트/프롬프트 실패는 분모에서 제외된다. "
            "전체 호출 성공률로 해석하지 않는다.",
            [
                target(
                    "A",
                    JSON_RECORD + '| filter record.event = "cloudshield.llm_analysis"\n'
                    "| fields coalesce(record.incident_id, record.incident_ref) as incident, "
                    "record.status as analysis_status\n"
                    "| filter ispresent(incident) and analysis_status in "
                    '["enhanced", "parse_failed", "call_failed"]\n'
                    "| stats latest(analysis_status) as outcome by incident\n"
                    "| stats count(*) as incidents by outcome",
                    [ANALYZER_GROUP],
                )
            ],
        ),
        (
            "사건 처리 타임라인 · 최신 200건",
            "table",
            "기존 플랫폼·LLM·Slack 로그의 관측 타임라인. incident_id 없는 행은 "
            "시간대만으로 특정 사건과 결합하지 않는다. 모든 실행 단계가 로깅된다는 보장은 없다.",
            [
                target(
                    "A",
                    "fields @timestamp, @log, @logStream, @message\n"
                    "| filter @message like /INC-|위협 대응|Slack|복구|cloudshield.llm_analysis/\n"
                    "| parse @message /(?<incident_id>INC-[A-Za-z0-9-]+)/\n"
                    "| sort @timestamp desc\n| limit 200",
                    [ORCHESTRATOR_GROUP, ANALYZER_GROUP],
                )
            ],
        ),
    ]
    panels = []
    for index, (title, kind, description, targets) in enumerate(definitions):
        panel = {
            "id": index + 1,
            "title": title,
            "type": kind,
            "description": description,
            "datasource": dict(DATASOURCE),
            "gridPos": {"x": (index % 2) * 12, "y": (index // 2) * 10, "w": 12, "h": 10},
            "targets": targets,
            "fieldConfig": {"defaults": {"noValue": "미관측"}, "overrides": []},
            "options": {},
        }
        if index == 1:
            panel["fieldConfig"]["defaults"]["unit"] = "s"
        if kind == "piechart":
            panel["options"] = {
                "reduceOptions": {"values": True, "calcs": [], "fields": "/^incidents$/"},
                "legend": {"displayMode": "table", "placement": "bottom", "values": ["percent"]},
                "displayLabels": ["name", "percent"],
            }
        panels.append(panel)
    return {
        "id": None,
        "uid": "cloudshield-p5-2",
        "title": "CloudShield P5-2 SecOps",
        "schemaVersion": 39,
        "version": 1,
        "editable": True,
        "timezone": "Asia/Seoul",
        "refresh": "",
        "time": {"from": "now-1h", "to": "now"},
        "tags": ["cloudshield", "cloud-b", "p5-2"],
        "templating": {"list": []},
        "annotations": {"list": []},
        "panels": panels,
    }
