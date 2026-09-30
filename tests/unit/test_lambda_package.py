# CloudShield 단위 테스트: Lambda 배포 패키지 무결성 및 pydantic 의존성 검증
# 소유자: 클라우드 A (플랫폼 전담 영역)
"""이슈 #102: Lambda 배포 번들의 pydantic 의존성 포함 및 핸들러 임포트 검증 테스트.

Why:
    AWS Lambda Python 3.12 기본 런타임에는 pydantic 및 pydantic-core가 포함되어 있지 않으므로,
    배포 아티팩트 생성 시 해당 의존성이 번들에 포함되어 핸들러 로딩 시 Runtime.ImportModuleError가
    발생하지 않음을 로컬 검증 단계에서 기계적으로 보장함.
"""

from __future__ import annotations

import importlib
import sys
import zipfile
from pathlib import Path

import pytest

# scripts 디렉토리 임포트 지원
root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from scripts.package_lambda import RUNTIME_DEPENDENCIES, build_lambda_bundle  # noqa: E402


@pytest.fixture
def lambda_bundle_artifacts(tmp_path: Path) -> tuple[Path, Path]:
    """임시 디렉터리에 Lambda 배포 번들 및 ZIP 생성."""
    src_dir = root_dir / "src"
    output_dir = tmp_path / "bundle"
    zip_path = tmp_path / "orchestrator.zip"

    build_lambda_bundle(src_dir, output_dir, zip_path)
    return output_dir, zip_path


def test_lambda_bundle_contains_required_packages(
    lambda_bundle_artifacts: tuple[Path, Path],
) -> None:
    """배포 디렉터리 및 ZIP 파일 내에 src 모듈과 pydantic 필수 종속성이 포함되어 있는지 검증."""
    output_dir, zip_path = lambda_bundle_artifacts

    # 1. 디렉터리 기반 검증
    for dep in RUNTIME_DEPENDENCIES:
        dep_path = output_dir / dep
        dep_py = output_dir / f"{dep}.py"
        assert dep_path.exists() or dep_py.exists(), f"번들에 필수 의존성 누락: {dep}"

    assert (output_dir / "contracts" / "events.py").exists()
    assert (output_dir / "remediation" / "orchestrator.py").exists()

    # 2. ZIP 아카이브 내부 파일 목록 검증
    assert zip_path.exists()
    with zipfile.ZipFile(zip_path, "r") as zf:
        namelist = zf.namelist()
        # pydantic 패키지 내부 파일 포함 여부
        assert any(
            name.startswith("pydantic/") or name == "pydantic/__init__.py" for name in namelist
        )
        assert any("contracts/events.py" in name for name in namelist)
        assert any("remediation/orchestrator.py" in name for name in namelist)


def test_lambda_bundle_excludes_unwanted_files(
    lambda_bundle_artifacts: tuple[Path, Path],
) -> None:
    """__pycache__, *.pyc 등 불필요한 빌드 캐시 파일이 번들에서 제외되었는지 검증."""
    _, zip_path = lambda_bundle_artifacts

    with zipfile.ZipFile(zip_path, "r") as zf:
        namelist = zf.namelist()
        assert not any("__pycache__" in name for name in namelist)
        assert not any(name.endswith(".pyc") for name in namelist)
        assert not any(".pytest_cache" in name for name in namelist)


def test_lambda_bundle_handler_importable(
    lambda_bundle_artifacts: tuple[Path, Path],
) -> None:
    """배포 번들 경로를 sys.path에 추가했을 때 핸들러 및 계약 모델이 정상 import되는지 검증."""
    output_dir, _ = lambda_bundle_artifacts
    bundle_str = str(output_dir)

    # 임시로 sys.path 맨 앞에 번들 디렉터리 삽입
    sys.path.insert(0, bundle_str)
    try:
        # 번들 내부 모듈 임포트 검증
        orchestrator_mod = importlib.import_module("remediation.orchestrator")
        assert hasattr(orchestrator_mod, "threat_orchestrator_handler")

        events_mod = importlib.import_module("contracts.events")
        assert hasattr(events_mod, "CloudWatchLogsPayload")

        incident_mod = importlib.import_module("contracts.incident")
        assert hasattr(incident_mod, "IncidentReport")
    finally:
        if bundle_str in sys.path:
            sys.path.remove(bundle_str)
