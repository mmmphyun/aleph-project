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
    - 대상 플랫폼(Linux x86_64) 휠 다운로드 실패 시 빌드를 즉시 중단(Fail-Closed).
    - Windows 전용 .pyd 바이너리 검출 시 즉시 예외 발생 및 배포 파일 생성 차단.
    - Lambda 런타임 호환 Linux x86_64 ELF 바이너리(.so) 패키징 강제.
    - pydantic 의존성 트리 내 typing_inspection 포함 필수.
    - 불필요한 __pycache__, 테스트 파일, .egg-info, .dist-info 등은 배포 산출물에서 엄격히 제외.
"""

from __future__ import annotations

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
            "pydantic>=2.0",
        ]
        res = subprocess.run(cmd_uv, capture_output=True, text=True, check=False)
        if res.returncode == 0 and (target_dir / "pydantic_core").exists():
            return True
        sys.stderr.write(f"[패키징 경고] uv pip install 실패: {res.stderr}\n")
    except FileNotFoundError:
        pass

    # 2순위: pip install (표준 pip fallback)
    try:
        pip_platform = (
            "manylinux2014_x86_64" if platform == "x86_64-unknown-linux-gnu" else platform
        )
        cmd_pip = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--target",
            str(target_dir),
            "--platform",
            pip_platform,
            "--python-version",
            python_version,
            "--only-binary=:all:",
            "pydantic>=2.0",
        ]
        res = subprocess.run(cmd_pip, capture_output=True, text=True, check=False)
        if res.returncode == 0 and (target_dir / "pydantic_core").exists():
            return True
        sys.stderr.write(f"[패키징 경고] pip install fallback 실패: {res.stderr}\n")
    except Exception as exc:
        sys.stderr.write(f"[패키징 경고] pip install 예외 발생: {exc}\n")

    return False


def validate_linux_native_binaries(target_dir: Path) -> None:
    """번들 디렉터리 내 Linux .so 탑재 및 Windows .pyd 부재를 강제 검증 (Fail-Closed)."""
    # 1. Windows C-Extension .pyd 파일 존재 차단
    pyd_files = list(target_dir.rglob("*.pyd"))
    if pyd_files:
        raise RuntimeError(
            f"[빌드 차단] 호환되지 않는 Windows 전용 .pyd 바이너리가 번들에 포함되었습니다: "
            f"{[f.name for f in pyd_files]}. Linux x86_64 전용 휠로 빌드하십시오."
        )

    # 2. Linux ELF 공유 라이브러리 .so 파일 존재 확인
    so_files = list(target_dir.glob("pydantic_core/_pydantic_core*.so"))
    if not so_files:
        raise RuntimeError(
            "[빌드 차단] AWS Lambda Linux x86_64 호환 pydantic_core .so 공유 라이브러리가 "
            "번들에 누락되었습니다."
        )


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

        # Linux 플랫폼 패키지 확보 실패 시 빌드 즉시 실패 (Fail-Closed)
        if not success:
            raise RuntimeError(
                f"[빌드 실패] AWS Lambda Linux x86_64({target_platform}, Python {python_version}) "
                "호환 패키지 다운로드에 실패했습니다. 유효하지 않은 아티팩트 생성을 방지하기 위해 "
                "빌드를 중단합니다 (Fail-Closed)."
            )

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

    # 3. ZIP 생성 전 번들 디렉터리의 Linux 네이티브 바이너리 무결성 검증
    validate_linux_native_binaries(output_dir)

    # 4. ZIP 파일 생성 (지정된 경우)
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

        # ZIP 내부 바이너리 무결성 교차 검증
        with zipfile.ZipFile(zip_output_path, "r") as zf:
            namelist = zf.namelist()
            if any(n.endswith(".pyd") for n in namelist):
                zip_output_path.unlink(missing_ok=True)
                raise RuntimeError("[빌드 실패] ZIP 아티팩트에 .pyd 바이너리가 감지되어 삭제됨.")
            if not any(
                n.startswith("pydantic_core/_pydantic_core") and n.endswith(".so") for n in namelist
            ):
                zip_output_path.unlink(missing_ok=True)
                raise RuntimeError(
                    "[빌드 실패] ZIP 아티팩트에 pydantic_core .so 바이너리가 누락되어 삭제됨."
                )

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
