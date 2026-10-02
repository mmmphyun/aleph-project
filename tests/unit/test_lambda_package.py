# CloudShield 단위 테스트: Lambda 배포 패키지 무결성 및 pydantic 의존성 검증
# 소유자: 클라우드 A (플랫폼 전담 영역)
"""이슈 #102 / PR #103: Lambda 배포 번들의 Linux 휠 바이너리 및 격리 환경 임포트 무결성 검증.

Why:
    AWS Lambda Python 3.12 기본 런타임은 Linux x86_64 기반이며 pydantic 및 pydantic-core,
    typing_inspection 등 런타임 의존성이 포함되어 있지 않음.
    호스트 OS(Windows/macOS) 개발 환경의 site-packages 오염 없이 독립된 프로세스(python -S)에서
    ZIP 아티팩트만으로 필수 의존성이 적재되는지, 그리고 Windows DLL(.pyd)이 아닌
    Lambda 런타임 호환 Linux ELF 바이너리(.so)가 번들링되는지를 기계적으로 검증함.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

# scripts 디렉토리 임포트 지원
root_dir = Path(__file__).resolve().parents[2]
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from scripts.package_lambda import (  # noqa: E402
    RUNTIME_DEPENDENCIES,
    build_lambda_bundle,
    fetch_linux_dependencies,
    validate_linux_native_binaries,
)


@pytest.fixture(scope="module")
def lambda_bundle_artifacts(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """모듈 단위 임시 디렉터리에 Lambda 배포 번들 및 Linux x86_64 호환 ZIP 생성."""
    tmp_path = tmp_path_factory.mktemp("lambda_bundle")
    src_dir = root_dir / "src"
    output_dir = tmp_path / "bundle"
    zip_path = tmp_path / "orchestrator.zip"

    build_lambda_bundle(src_dir, output_dir, zip_path)
    return output_dir, zip_path


def test_lambda_bundle_contains_required_packages(
    lambda_bundle_artifacts: tuple[Path, Path],
) -> None:
    """배포 디렉터리 및 ZIP 파일 내에 src 모듈과 typing_inspection 등 필수 의존성 검증."""
    output_dir, zip_path = lambda_bundle_artifacts

    # 1. 번들 디렉터리 검증
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
        assert any(name.startswith("pydantic/") for name in namelist)
        assert any(
            name.startswith("typing_inspection/") or name.startswith("typing_inspection.py")
            for name in namelist
        ), "typing_inspection 패키지가 ZIP 내에 존재해야 함"
        assert any("contracts/events.py" in name for name in namelist)
        assert any("remediation/orchestrator.py" in name for name in namelist)


def test_lambda_bundle_linux_native_binary_compatibility(
    lambda_bundle_artifacts: tuple[Path, Path],
) -> None:
    """배포 ZIP이 Windows(.pyd)가 아닌 AWS Lambda Linux(.so) 네이티브 바이너리를 탑재했는지 검증."""
    _, zip_path = lambda_bundle_artifacts

    with zipfile.ZipFile(zip_path, "r") as zf:
        namelist = zf.namelist()

        # 1. Linux ELF 공유 라이브러리(.so) 존재 검증
        so_files = [n for n in namelist if n.startswith("pydantic_core/") and n.endswith(".so")]
        assert len(so_files) > 0, "Lambda Python 3.12 Linux용 pydantic_core .so 파일이 누락됨"
        assert any("x86_64-linux" in f or "cpython-312" in f for f in so_files), (
            f"올바른 Linux x86_64 CPython 3.12 바이너리가 아님: {so_files}"
        )

        # 2. Windows 전용 .pyd 파일 절대 배제 검증
        pyd_files = [n for n in namelist if n.endswith(".pyd")]
        assert len(pyd_files) == 0, (
            f"Windows 전용 .pyd 바이너리가 Lambda ZIP에 포함되어 호환성 결함 유발: {pyd_files}"
        )


def test_lambda_bundle_excludes_unwanted_files(
    lambda_bundle_artifacts: tuple[Path, Path],
) -> None:
    """__pycache__, *.pyc, *.dist-info 등 배포에 불필요한 빌드 캐시 및 메타데이터 제외 검증."""
    _, zip_path = lambda_bundle_artifacts

    with zipfile.ZipFile(zip_path, "r") as zf:
        namelist = zf.namelist()
        assert not any("__pycache__" in name for name in namelist)
        assert not any(name.endswith(".pyc") for name in namelist)
        assert not any(".pytest_cache" in name for name in namelist)
        assert not any(".dist-info" in name for name in namelist)


def test_lambda_bundle_isolated_process_import(
    lambda_bundle_artifacts: tuple[Path, Path],
    tmp_path: Path,
) -> None:
    """격리된 서브프로세스(python -S)에서 ZIP 아티팩트 추출 환경의 의존성 로딩 무결성 검증."""
    _, zip_path = lambda_bundle_artifacts

    # AWS Lambda 실제 실행 환경(ZIP -> /var/task 추출)을 모사하여 아티팩트 압축 해제
    task_dir = tmp_path / "lambda_task"
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(task_dir)

    task_abs_path = str(task_dir.resolve())

    # python -S 로 실행하여 호스트 가상환경 site-packages 자동 주입 원천 차단
    test_script = f"""
import sys
# site-packages 배제 확인 후 Lambda 태스크 디렉터리를 sys.path 최우선 삽입
sys.path.insert(0, {repr(task_abs_path)})

# 1. 런타임 필수 순수 파이썬 의존성 독립 임포트 검증
import typing_inspection
import annotated_types
import typing_extensions

print("[격리검증-성공] typing_inspection 및 필수 종속성 단독 로딩 완료")

# 2. 플랫폼 환경별 네이티브 모듈 로딩 분기 검증
import platform
if platform.system() == "Linux":
    # AWS Lambda 런타임 내장 SDK(boto3/botocore) 환경 에뮬레이션
    import unittest.mock
    for mod in [
        "boto3",
        "boto3.dynamodb",
        "boto3.dynamodb.conditions",
        "botocore",
        "botocore.exceptions",
    ]:
        sys.modules[mod] = unittest.mock.MagicMock()

    import pydantic
    import contracts.events as ev
    import contracts.incident as inc
    import remediation.orchestrator as orch

    assert hasattr(orch, "threat_orchestrator_handler")
    assert hasattr(ev, "CloudWatchLogsPayload")
    assert hasattr(inc, "IncidentReport")
    print("[격리검증-성공] Linux 환경 전체 핸들러 및 pydantic 계약 모델 로딩 완료")
else:
    # Windows/macOS 개발 환경: Linux .so 가 탑재되어 있으므로 OS 불일치로 인한
    # c-extension 로드 실패가 정상 동작임 (네이티브 .so 교차 탑재 입증)
    try:
        import pydantic
        print("[격리검증] pydantic 로딩됨")
    except ModuleNotFoundError as e:
        assert "_pydantic_core" in str(e)
        print("[격리검증-성공] 비-Linux 환경에서 Linux .so 탑재로 인한 정상 분기 확인:", e)
"""

    res = subprocess.run(
        [sys.executable, "-S", "-c", test_script],
        capture_output=True,
        text=True,
        check=False,
    )

    assert res.returncode == 0, (
        f"격리된 프로세스에서 ZIP 종속성 임포트 실패:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}"
    )
    assert "[격리검증-성공]" in res.stdout


def test_validate_linux_native_binaries_blocks_pyd(tmp_path: Path) -> None:
    """Windows 전용 .pyd 바이너리가 번들 내 존재할 경우 즉시 예외로 차단되는지 검증."""
    fake_bundle = tmp_path / "fake_bundle"
    pydantic_core_dir = fake_bundle / "pydantic_core"
    pydantic_core_dir.mkdir(parents=True, exist_ok=True)
    (pydantic_core_dir / "_pydantic_core.cp312-win_amd64.pyd").touch()

    with pytest.raises(RuntimeError, match=r"호환되지 않는 Windows 전용 \.pyd"):
        validate_linux_native_binaries(fake_bundle)


def test_validate_linux_native_binaries_requires_so(tmp_path: Path) -> None:
    """pydantic_core 디렉터리에 .so 바이너리가 누락된 경우 즉시 예외로 차단되는지 검증."""
    fake_bundle = tmp_path / "fake_bundle_no_so"
    pydantic_core_dir = fake_bundle / "pydantic_core"
    pydantic_core_dir.mkdir(parents=True, exist_ok=True)
    (pydantic_core_dir / "__init__.py").touch()

    with pytest.raises(RuntimeError, match=r"\.so 공유 라이브러리가 번들에 누락"):
        validate_linux_native_binaries(fake_bundle)


def test_build_lambda_bundle_fails_closed_on_invalid_platform(tmp_path: Path) -> None:
    """지원되지 않는 플랫폼 타깃으로 빌드 시 즉시 실패(Fail-Closed)하는지 검증."""
    src_dir = root_dir / "src"
    out_dir = tmp_path / "fail_bundle"

    with pytest.raises(RuntimeError, match=r"호환 패키지 다운로드에 실패했습니다"):
        build_lambda_bundle(
            src_dir=src_dir,
            output_dir=out_dir,
            target_platform="invalid-non-existent-platform",
        )


def test_fetch_linux_dependencies_pip_fallback_forwards_custom_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """uv 실패 후 pip fallback 시 임의/무효 플랫폼이 하드코딩되지 않고 그대로 전달되는지 검증."""
    captured_commands: list[list[str]] = []

    def mock_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(cmd)
        # uv와 pip 모두 실패 시뮬레이션
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="mock error")

    monkeypatch.setattr(subprocess, "run", mock_run)

    success = fetch_linux_dependencies(
        target_dir=tmp_path,
        platform="invalid-non-existent-platform",
    )
    assert not success
    assert len(captured_commands) == 2

    # 1순위 uv: --python-platform 에 입력 플랫폼 전달
    uv_cmd = captured_commands[0]
    assert uv_cmd[uv_cmd.index("--python-platform") + 1] == "invalid-non-existent-platform"

    # 2순위 pip: --platform 에 입력 플랫폼 전달 (manylinux 하드코딩 방지)
    pip_cmd = captured_commands[1]
    assert pip_cmd[pip_cmd.index("--platform") + 1] == "invalid-non-existent-platform"


def test_fetch_linux_dependencies_pip_fallback_maps_default_linux_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """기본 Linux 타깃(x86_64-unknown-linux-gnu)일 때 manylinux2014_x86_64로 매핑되는지 검증."""
    captured_commands: list[list[str]] = []

    def mock_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured_commands.append(cmd)
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="mock error")

    monkeypatch.setattr(subprocess, "run", mock_run)

    success = fetch_linux_dependencies(
        target_dir=tmp_path,
        platform="x86_64-unknown-linux-gnu",
    )
    assert not success
    assert len(captured_commands) == 2

    pip_cmd = captured_commands[1]
    assert pip_cmd[pip_cmd.index("--platform") + 1] == "manylinux2014_x86_64"


def test_fetch_linux_dependencies_fails_if_pydantic_core_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """설치 명령이 0을 반환하더라도 pydantic_core 디렉터리가 없으면 False 반환 검증."""

    def mock_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_run)

    success = fetch_linux_dependencies(
        target_dir=tmp_path,
        platform="x86_64-unknown-linux-gnu",
    )
    assert not success
