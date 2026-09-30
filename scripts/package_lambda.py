"""
scripts/package_lambda.py
CloudShield Lambda 오케스트레이터 배포 아티팩트 빌더.

Why:
    AWS Lambda 기본 Python 런타임(3.12)에는 pydantic 및 pydantic-core 등
    계약 모델 필수 의존성이 내장되어 있지 않아 Runtime.ImportModuleError가 발생함.
    따라서 src/ 코드와 런타임 필수 외부 의존성을 단일 배포 번들 디렉터리/ZIP으로
    통합 패키징하여 런타임 무결성을 보장함.

Constraints:
    - 표준 라이브러리 및 현재 venv 환경의 패키지를 복사하여 OS 독립적 빌드 보장.
    - 불필요한 __pycache__, 테스트 파일, .egg-info 등은 패키징에서 엄격히 제외.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import zipfile
from pathlib import Path

# Lambda 런타임에 필요한 외부 패키지 목록
RUNTIME_DEPENDENCIES = [
    "pydantic",
    "pydantic_core",
    "annotated_types",
    "typing_extensions",
]


def resolve_package_dir(package_name: str) -> Path | None:
    """현재 Python 환경에서 모듈/패키지의 실제 설치 디렉터리 또는 파일 경로 반환."""
    try:
        spec = importlib.util.find_spec(package_name)
        if spec is None:
            return None
        if spec.submodule_search_locations:
            return Path(list(spec.submodule_search_locations)[0])
        if spec.origin:
            return Path(spec.origin)
    except Exception:
        return None
    return None


def build_lambda_bundle(
    src_dir: Path,
    output_dir: Path,
    zip_output_path: Path | None = None,
) -> Path:
    """src 디렉터리와 런타임 필수 패키지를 output_dir에 통합 복사 후 선택적으로 zip 압축."""
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. src/ 내부 모듈 복사 (contracts, remediation, collector, detection, reporter)
    for item in src_dir.iterdir():
        if item.name.startswith((".", "_")) or item.name.endswith(".egg-info"):
            continue
        dest = output_dir / item.name
        if item.is_dir():
            shutil.copytree(
                item,
                dest,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".pytest_cache"),
            )
        elif item.is_file() and item.suffix == ".py":
            shutil.copy2(item, dest)

    # 2. 런타임 외부 종속성 복사
    for pkg in RUNTIME_DEPENDENCIES:
        pkg_path = resolve_package_dir(pkg)
        if pkg_path is None or not pkg_path.exists():
            sys.stderr.write(f"[경고] 필수 런타임 패키지를 찾을 수 없음: {pkg}\n")
            continue

        if pkg_path.is_dir():
            dest = output_dir / pkg_path.name
            if not dest.exists():
                shutil.copytree(
                    pkg_path,
                    dest,
                    ignore=shutil.ignore_patterns(
                        "__pycache__",
                        "*.pyc",
                        "*.pyo",
                        "tests",
                        "*.dist-info",
                        "test_*.py",
                        "*test*",
                    ),
                )
        elif pkg_path.is_file():
            dest = output_dir / pkg_path.name
            if not dest.exists():
                shutil.copy2(pkg_path, dest)

    # 3. ZIP 파일 생성 (지정된 경우)
    if zip_output_path:
        zip_output_path.parent.mkdir(parents=True, exist_ok=True)
        if zip_output_path.exists():
            zip_output_path.unlink()

        with zipfile.ZipFile(zip_output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(output_dir):
                for file in files:
                    file_path = Path(root) / file
                    arcname = file_path.relative_to(output_dir)
                    zf.write(file_path, arcname)

        return zip_output_path

    return output_dir


def main() -> None:
    """CLI 엔트리포인트."""
    repo_root = Path(__file__).resolve().parents[1]
    src_dir = repo_root / "src"
    bundle_dir = repo_root / "build" / "lambda_bundle"
    zip_path = (
        repo_root / "infra" / "terraform" / "modules" / "lambda" / "build" / "orchestrator.zip"
    )

    print(f"[빌드 시작] Lambda 배포 번들 생성: {src_dir} -> {bundle_dir}")
    build_lambda_bundle(src_dir, bundle_dir, zip_path)
    print(
        f"[빌드 완료] 배포 아티팩트 생성 완료: {zip_path} (크기: {zip_path.stat().st_size} bytes)"
    )


if __name__ == "__main__":
    main()
