# CloudShield 로컬 통합 검증 스크립트
# 목적: CI 푸시 전 린트, 포맷, 단위 테스트를 로컬에서 단일 명령어로 검증

$ErrorActionPreference = "Stop"

# Windows 환경에서 깨진 WSL bash stub(system32/bash.exe) 회피 및 Git Bash 우선순위 확보
if (Test-Path "C:\Program Files\Git\bin\bash.exe") {
    $env:PATH = "C:\Program Files\Git\bin;" + $env:PATH
}

Write-Host "[1/4] 테스트 파일 표준 경로 검사 중..." -ForegroundColor Cyan
$wrongTests = Get-ChildItem -Path . -Recurse -Filter "test_*.py" -File | Where-Object { 
    $_.FullName -notmatch "[\\/]tests[\\/]" -and $_.FullName -notmatch "[\\/]\.venv[\\/]" 
}
if ($wrongTests) {
    Write-Error "[오류] 표준 경로(tests/) 외부에 단위 테스트 파일이 발견되었습니다:`n$($wrongTests.FullName -join "`n")`n모든 단위 테스트는 tests/unit/ 하위에 위치해야 합니다."
    exit 1
}

Write-Host "[2/4] Ruff Lint 검사 실행 중..." -ForegroundColor Cyan
uv run ruff check .

Write-Host "[3/4] Ruff Format 검사 실행 중..." -ForegroundColor Cyan
uv run ruff format --check .

Write-Host "[4/4] Pytest 단위 및 계약 테스트 실행 중..." -ForegroundColor Cyan
uv run python -m pytest -v

Write-Host "`n[성공] 모든 로컬 품질 및 계약 검증을 통과했습니다." -ForegroundColor Green
