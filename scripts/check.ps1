# CloudShield 로컬 통합 검증 스크립트
# 목적: CI 푸시 전 린트, 포맷, 단위 테스트를 로컬에서 단일 명령어로 검증

$ErrorActionPreference = "Stop"

Write-Host "[1/3] Ruff Lint 검사 실행 중..." -ForegroundColor Cyan
uv run ruff check .

Write-Host "[2/3] Ruff Format 검사 실행 중..." -ForegroundColor Cyan
uv run ruff format --check .

Write-Host "[3/3] Pytest 단위 및 계약 테스트 실행 중..." -ForegroundColor Cyan
uv run pytest -v

Write-Host "`n[성공] 모든 로컬 품질 및 계약 검증을 통과했습니다." -ForegroundColor Green
