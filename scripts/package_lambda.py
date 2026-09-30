"""
scripts/package_lambda.py
CloudShield Lambda 오케스트레이터 배포 아티팩트 빌더.

Why:
    AWS Lambda 기본 Python 런타임(3.12, Linux x86_64)에는 pydantic 및 pydantic-core 등
    계약 모델 필수 의존성이 내장되어 있지 않아 Runtime.ImportModuleError가 발생함.
    특히 Windows 등 타 OS 개발 환경에서 빌드 시 네이티브 바이너리(.pyd vs .so) 불일치로
    런타임 결함이 유발되므로, Lambda 대상(manylinux x86_64) 호환 휠을 다운로드하여
    src/ 코드와 함께 단일 배포 ZIP 아티팩트로 통합 번들링함.

Constraints:
    - Lambda 런타임 호환 Linux x86_64 ELF 바이너리(.so) 패키징 강제 (.pyd 제외).
    - pydantic 의존성 트리 내 typing_inspection 포함 필수.
    - 불필요한 __pycache__, 테스트 파일, .egg-info, .dist-info 등은 배포 산출물에서 엄격히 제외.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# Lambda 런타임에 필요한 외부 패키지 목록 (typing_inspection 필수 포함)
RUNTIME_DEPENDENCIES = [
    "pydantic",
    "pydantic_core",
    "annotated_types",
    "typing_extensions",
    "typing_inspection",
]


def resolve_local_package_dir(package_name: str) -> Path | None:
    """현재 Python 환경에서 모듈/패키지의 실제 설치 디렉터리 또는 파일 경로 반환 (Fallback용)."""
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


def fetch_linux_dependencies(
    target_dir: Path,
    python_version: str = "3.12",
    platform: str = "x86_64-unknown-linux-gnu",
) -> bool:
    """AWS Lambda Linux x86_64 타깃에 호환되는 pydantic 종속성 휠을 target_dir에 설치."""
    # 1순위: uv pip install (크로스 플랫폼 지원 최우선)
    try:
        cmd_uv = [
            "uv",
            "pip",
            "install",
            "--target",
            str(target_dir),
            "--python-platform",
            platform,
            "--python-version",
            python_version,
            "pydantic",
        ]
        res = subprocess.run(cmd_uv, capture_output=True, text=True, check=False)
        if res.returncode == 0:
            return True
        sys.stderr.write(f"[패키징 경고] uv pip install 실패: {res.stderr}\n")
    except FileNotFoundError:
        pass

    # 2순위: pip install --platform manylinux2014_x86_64 (표준 pip fallback)
    try:
        cmd_pip = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--target",
            str(target_dir),
            "--platform",
            "manylinux2014_x86_64",
            "--python-version",
            python_version,
            "--only-binary=:all:",
            "pydantic",
        ]
        res = subprocess.run(cmd_pip, capture_output=True, text=True, check=False)
        if res.returncode == 0:
            return True
        sys.stderr.write(f"[패키징 경고] pip install fallback 실패: {res.stderr}\n")
    except Exception as exc:
        sys.stderr.write(f"[패키징 경고] pip install 예외 발생: {exc}\n")

    return False


def build_lambda_bundle(
    src_dir: Path,
    output_dir: Path,
    zip_output_path: Path | None = None,
    python_version: str = "3.12",
    target_platform: str = "x86_64-unknown-linux-gnu",
) -> Path:
    """src 디렉터리와 Linux 호환 런타임 종속성을 output_dir에 통합 복사 후 zip 압축."""
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

    # 2. 런타임 외부 종속성 수집 (AWS Lambda Linux x86_64 호환)
    with tempfile.TemporaryDirectory() as td:
        temp_deps_dir = Path(td)
        success = fetch_linux_dependencies(
            temp_deps_dir,
            python_version=python_version,
            platform=target_platform,
        )

        if success:
            # 다운로드된 Linux 의존성 패키지를 번들로 복사
            for dep in RUNTIME_DEPENDENCIES:
                dep_dir = temp_deps_dir / dep
                dep_file = temp_deps_dir / f"{dep}.py"
                if dep_dir.exists() and dep_dir.is_dir():
                    dest = output_dir / dep
                    if not dest.exists():
                        shutil.copytree(
                            dep_dir,
                            dest,
                            ignore=shutil.ignore_patterns(
                                "__pycache__",
                                "*.pyc",
                                "*.pyo",
                                "tests",
                                "*.dist-info",
                                "test_*.py",
                            ),
                        )
                elif dep_file.exists() and dep_file.is_file():
                    dest = output_dir / dep_file.name
                    if not dest.exists():
                        shutil.copy2(dep_file, dest)
        else:
            # 오프라인/환경 제약 시 로컬 venv fallback (경고 수반)
            sys.stderr.write(
                "[패키징 주의] Linux 휠 직접 다운로드 실패로 로컬 venv 종속성 복사 수행\n"
            )
            for pkg in RUNTIME_DEPENDENCIES:
                pkg_path = resolve_local_package_dir(pkg)
                if pkg_path is None or not pkg_path.exists():
                    sys.stderr.write(f"[경고] 필수 런타임 패키지를 찾을 수 없음: {pkg}\n")
                    continue
                dest = output_dir / pkg_path.name
                if pkg_path.is_dir() and not dest.exists():
                    shutil.copytree(
                        pkg_path,
                        dest,
                        ignore=shutil.ignore_patterns(
                            "__pycache__",
                            "*.pyc",
                            "*.pyo",
                            "tests",
                            "*.dist-info",
                        ),
                    )
                elif pkg_path.is_file() and not dest.exists():
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
    """CLI 엔트리포인트: 배포용 아티팩트 빌드 실행."""
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
