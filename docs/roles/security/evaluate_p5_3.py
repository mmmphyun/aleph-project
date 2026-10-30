"""합성 고정셋을 실제 보안 어댑터에 재생하고 분모가 명확한 오프라인 지표를 출력한다.

Why: 정상 보강과 의도한 실패 격리를 구분하며 실인프라 성공률로 오인하지 않게 한다.
Constraints: 저장된 응답만 주입한다. 근거 대조는 사전 검수한 문자열·건수 assertion에 한정한다.
Side-effects: main에서 지정한 JSON 결과 파일만 쓴다. AWS·Slack·S3 호출은 수행하지 않는다.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from contracts.incident import IncidentReport
from detection.llm_deep_analyzer import analyze_incident_with_bedrock


class _ReplayClient:
    def __init__(self, case: dict[str, Any]) -> None:
        self.case = case

    def converse(self, **kwargs: Any) -> Any:
        if self.case.get("exception") == "TimeoutError":
            raise TimeoutError("합성 고정셋의 의도된 타임아웃")
        return self.case["response"]


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    """원본 보존·수용된 분석·선언된 근거를 독립 기대값과 비교한다.

    Constraints: expected_status는 평가 라벨이며 실제 결과 판정에는 사용하지 않는다.
    Side-effects: 주입 응답을 실제 어댑터로 검증한다. 원본 필드 변경은 실패로 기록한다.
    """
    base = IncidentReport.model_validate(case["base_report"])
    result = analyze_incident_with_bedrock(
        base, case["raw_logs"], bedrock_client=_ReplayClient(case)
    )
    protected = set(IncidentReport.model_fields) - {"summary_ko", "recommendations"}
    enhanced = result is not base
    expected_enhanced = case["expected_status"] == "enhanced"
    assertions = case["evidence_assertions"]
    evidence_matches = 0
    for assertion in assertions:
        source_matches = (
            len(case["raw_logs"]) == assertion["line_count"]
            if "line_count" in assertion
            else any(assertion["source_fragment"] in line for line in case["raw_logs"])
        )
        evidence_matches += bool(
            enhanced and source_matches and assertion["summary_fragment"] in result.summary_ko
        )
    sections = result.summary_ko.split("\n\n") if enhanced else []
    quality_matches = sum(
        2 <= len(re.findall(r"[.!?](?:\s|$)", section.split("\n", 1)[1])) <= 3
        for section in sections
    )
    return {
        "case_id": case["case_id"],
        "expected_enhanced": expected_enhanced,
        "enhanced": enhanced,
        "contract_valid": IncidentReport.model_validate_json(result.model_dump_json()) == result,
        "protected_fields_preserved": result.model_dump(include=protected)
        == base.model_dump(include=protected),
        "expected_analysis_matches": (
            result.model_dump(mode="json", include={"summary_ko", "recommendations"})
            == case["expected_analysis"]
            if expected_enhanced
            else result is base
        ),
        "evidence_matches": evidence_matches,
        "evidence_assertions": len(assertions),
        "two_or_three_sentence_sections": quality_matches,
        "accepted_sections": len(sections),
    }


def _ratio(passed: int, total: int) -> dict[str, int | float | None]:
    return {"passed": passed, "total": total, "rate": passed / total if total else None}


def evaluate_dataset(dataset: dict[str, Any]) -> dict[str, Any]:
    rows = [evaluate_case(case) for case in dataset["cases"]]
    normal = [row for row in rows if row["expected_enhanced"]]
    failures = [row for row in rows if not row["expected_enhanced"]]
    return {
        "dataset_version": dataset["dataset_version"],
        "scope": "synthetic_replay_only_not_live_bedrock_or_real_attack_evidence",
        "final_contract_compliance": _ratio(sum(r["contract_valid"] for r in rows), len(rows)),
        "normal_enhancement": _ratio(sum(r["enhanced"] for r in normal), len(normal)),
        "accepted_analysis_contract_compliance": _ratio(
            sum(r["contract_valid"] for r in rows if r["enhanced"]),
            sum(r["enhanced"] for r in rows),
        ),
        "fallback_isolation": _ratio(sum(not r["enhanced"] for r in failures), len(failures)),
        "protected_field_integrity": _ratio(
            sum(r["protected_fields_preserved"] for r in rows), len(rows)
        ),
        "expected_analysis_match": _ratio(
            sum(r["expected_analysis_matches"] for r in rows), len(rows)
        ),
        "declared_evidence_match": _ratio(
            sum(r["evidence_matches"] for r in normal),
            sum(r["evidence_assertions"] for r in normal),
        ),
        "two_or_three_sentence_sections": _ratio(
            sum(r["two_or_three_sentence_sections"] for r in normal),
            sum(r["accepted_sections"] for r in normal),
        ),
        "cases": rows,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="P5-3 합성 고정셋 오프라인 재생")
    parser.add_argument("dataset", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = evaluate_dataset(json.loads(args.dataset.read_text(encoding="utf-8")))
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if any(
        row["enhanced"] != row["expected_enhanced"]
        or not row["contract_valid"]
        or not row["protected_fields_preserved"]
        or not row["expected_analysis_matches"]
        or row["evidence_matches"] != row["evidence_assertions"]
        or row["two_or_three_sentence_sections"] != row["accepted_sections"]
        for row in result["cases"]
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
