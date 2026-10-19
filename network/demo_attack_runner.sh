#!/usr/bin/env bash
# Why: 발표 진입점을 고정하고 Python 러너의 기본 dry-run 및 승인 검증을 그대로 적용한다.
# Constraints: 실제 실행은 Linux에서 유효한 승인 파일과 --execute가 모두 필요하다.
# Side-effects: exec로 종료 코드와 신호를 전달한다. 자동 권한 상승이나 재실행은 하지 않는다.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
command -v python3 >/dev/null || { printf '%s\n' 'python3 필요' >&2; exit 127; }
exec python3 -B "$root/demo_attack_runner.py" "$@"
